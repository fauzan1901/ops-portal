# ADR-004: Automation of ACI interfaces, port-channels, and vPCs (Fabric Access Policies)

**Status:** Accepted — phase 1 (Interfaces) and phase 2 for vPCs (Create vPC) built 2026-10-26
**Date:** 2026-10-19 (proposed), 2026-10-26 (phases 1 and 2)

> **Decision 2026-10-26** (the user asked for vPC creation): the portal **only adds** a vPC policy group + selector + port
> blocks after a Review (question 1: yes); explicit permission **ACI: create vPCs** (`aci-interfaces`) or an administrator
> (question 2); the conventions are read from APIC itself: the settings are copied from an existing vPC of the pair, the
> pair's profile when the ports are the same on both leaves, otherwise one profile per leaf, selector name = policy group
> name without `-PG` (questions 3–4, no dump yet); a port that is up or has a neighbour = a warning (question 5); no undo
> (question 6); write rights of the service account on `uni/infra` **not checked in production yet** (question 7). Access
> ports and single-leaf port-channels are not created yet.
**Deciders:** Acme Cloud team (owner of the ACI portal module)

## Context

### Problem

Static Port in the portal (`/aci/`) can only attach **paths that already exist** in the fabric (`fabricPathEp`, the list
shown in Search APIC and in the product templates). Port-channel and vPC paths appear only after the physical ports
are configured in **Fabric → Access Policies** of APIC. For a new server (Acme Flex compute, Acme Prime ESXi, RHOSO
node) the flow today is:

1. The server is plugged into two leaves (for example leaf 122 and 123, eth1/45).
2. The network team creates the port configuration in the APIC GUI by hand: policy group, selector, port block.
3. The new path (for example `topology/pod-1/protpaths-122-123/pathep-[RHOSO-TRAFFIC-F-PG]`) appears.
4. The operator attaches the static port to the EPG through the portal, then adds that path to the product template.

Step 2 is not recorded in the portal, has no Review, and is easy to get wrong: the port is put in a selector that is
already used, its AAEP does not contain the EPG domain (binding fails with fault *invalid path / encap not in pool*),
or the policy group name does not follow the convention.

The current portal rule (`docs/ACI-AUTOMATION.md`, WI User Guide): the portal **never changes the fabric access
policy** (interface policy group, AEP, VLAN pool). This automation changes that rule, so a decision is needed.

### How Access Policies work

A new port can be used by an EPG if the following chain of objects is complete. Objects marked * usually already exist
and can simply be reused; only the policy group, selector, and port block are created for each new server.

```
VLAN pool* ──▶ Domain* (physDomP / vmmDomP) ──▶ AAEP* (infraAttEntityP)
                                                   ▲
Interface policies* (link level, LACP, CDP, LLDP, MCP)
        │                                          │
        ▼                                          │
Interface Policy Group  ── infraRsAttEntP ─────────┘
  access port: infraAccPortGrp      uni/infra/funcprof/accportgrp-<PG>
  port-channel: infraAccBndlGrp     uni/infra/funcprof/accbundle-<PG>   lagT=link
  vPC:          infraAccBndlGrp     uni/infra/funcprof/accbundle-<PG>   lagT=node
        ▲
        │ infraRsAccBaseGrp
Interface selector + port block     uni/infra/accportprof-<IntProf>/hports-<sel>-typ-range/portblk-<blk>
        ▲                            (fromCard/toCard, fromPort/toPort: eth1/45)
        │ infraRsAccPortP
Leaf profile + switch selector*     uni/infra/nprof-<SwProf>/leaves-<sel>-typ-range/nodeblk-<blk> (from_ 122, to_ 123)

vPC protection group* (fabricExplicitGEp, uni/fabric/protpol/expgep-<name>): leaf 122 + 123 as a vPC pair
```

Result in the fabric:

| Policy group | Leaf | Path that appears (can be bound to an EPG) |
|---|---|---|
| Access port | one leaf | `topology/pod-1/paths-118/pathep-[eth1/45]` (the physical port path always exists; the PG decides speed, AAEP, LLDP) |
| Port-channel | one leaf | `topology/pod-1/paths-111/pathep-[<PG>]` |
| vPC | leaf pair | `topology/pod-1/protpaths-122-123/pathep-[<PG>]` |

Things that decide the shape of the change:

- **Interface profile per vPC pair** (for example `Leaf122-123_IntProf`, attached to the leaf profile with nodes
  122–123): one selector is enough, the same port on both leaves goes into the vPC.
- **Interface profile per leaf** (`Leaf122_IntProf` and `Leaf123_IntProf`): one selector in each profile,
  pointing to the same vPC policy group.
- **AAEP** must contain the domain used by the EPG of that product, and the domain's VLAN pool must contain its VLAN.
  Otherwise static binding fails.
- Newer APIC versions also have an **Interface Configuration** model (port-centric, `infraPortConfig`). If the fabric
  already uses it, the automation must follow that model. The dump (below) shows which model is used.

### Example change: new vPC for one server

One POST to `/api/mo/uni/infra.json`, one APIC transaction (all succeed or all fail), same as Provisioning today:

```json
{"infraInfra": {"attributes": {"dn": "uni/infra"}, "children": [
  {"infraFuncP": {"attributes": {"dn": "uni/infra/funcprof"}, "children": [
    {"infraAccBndlGrp": {"attributes": {"name": "RHOSO-TRAFFIC-F-PG", "lagT": "node", "descr": "rhoso-compute-06"}, "children": [
      {"infraRsAttEntP": {"attributes": {"tDn": "uni/infra/attentp-DCB-OPENSTACK-AAEP"}}},
      {"infraRsHIfPol": {"attributes": {"tnFabricHIfPolName": "25G"}}},
      {"infraRsLacpPol": {"attributes": {"tnLacpLagPolName": "LACP-ACTIVE"}}},
      {"infraRsLldpIfPol": {"attributes": {"tnLldpIfPolName": "LLDP-ON"}}},
      {"infraRsCdpIfPol": {"attributes": {"tnCdpIfPolName": "CDP-OFF"}}}]}}]}},
  {"infraAccPortP": {"attributes": {"dn": "uni/infra/accportprof-Leaf122-123_IntProf"}, "children": [
    {"infraHPortS": {"attributes": {"name": "RHOSO-TRAFFIC-F", "type": "range"}, "children": [
      {"infraPortBlk": {"attributes": {"name": "block2", "fromCard": "1", "toCard": "1", "fromPort": "45", "toPort": "45"}}},
      {"infraRsAccBaseGrp": {"attributes": {"tDn": "uni/infra/funcprof/accbundle-RHOSO-TRAFFIC-F-PG"}}}]}}]}}]}}
```

Variants:

- **Access port**: `infraAccPortGrp` (no LACP) and one selector per port in the interface profile of that leaf.
- **Port-channel**: `infraAccBndlGrp` with `lagT=link`, selector in the interface profile of one leaf.
- **Adding a port to an existing policy group** (the server gets an additional link): only a new port block, or a new
  selector that points to the old PG. The policy group is not changed.

Names, AAEP, and policies in the example follow the portal mock. Real values are taken from the dump of each site.

## Decision (proposed)

### Phase 0: read-only dump (now)

`tools/aci-access-dump/` reads all the objects above from the APIC of each site, using GET only, with the portal's
service account `apic:<site>` (or your own read-only account). The result is `summary.md` (naming conventions, profiles
per leaf or per pair, AAEP per type of policy group, free ports per leaf, findings) plus raw CSV and JSON. This dump is
used to fill in the conventions per site before any code that changes APIC exists.

### Phase 1: read-only Interfaces page

New menu **Fabric → Interfaces** in `/aci/`, following the existing page pattern (PatternFly v5 / AWX: step cards,
data tables, filters like Report). It contains, per site:

- list of leaves and vPC pairs;
- ports per leaf: status (*Free*, *Configured*, *Bound*, *Uplink*), selector, policy group, AAEP, port-channel,
  LLDP neighbour, number of EPG bindings; filter *Show only free ports*;
- policy groups with their relations and the ports that use them;
- findings (overlapping selectors, policy group without AAEP, vPC on only one leaf).

No changes to APIC. This phase already helps the network team find free ports and check requests.

### Phase 2: create ports, port-channels, and vPCs

On the same page, the **Configure ports** button opens a flow like Provisioning:

1. **Leaf**: one leaf or a vPC pair (from `fabricExplicitGEp`).
2. **Ports**: checklist of ports with status. A port that is already in a selector cannot be chosen. The LLDP neighbour
   is shown so it matches the server name in the request.
3. **Policy group**: *Create new* or *Use existing* (add ports to an old PG). For a new PG: type (Access /
   Port-channel / vPC, from the leaf choice), name (suggested from the product convention, checked for uniqueness), AAEP, link level,
   LACP, CDP, LLDP, MCP. Initial values are taken from the **product profile** (Acme Flex, Acme Prime, RHOSO) that is
   filled in from the dump.
4. **Interface profile & selector**: chosen automatically from the leaf profile attached to that leaf. The portal only
   adds a new selector, and never changes or deletes an existing selector.
5. **Review & apply**: table of steps (object, name, *New*), check results, and the JSON payload. After apply, the portal
   waits for the new path to appear in `fabricPathEp`, then offers **Add to product template** (Fabric → Templates) and
   **Bind on Static Port**.

Checks on the server before apply (re-read from APIC, not from the browser):

| Check | From APIC | Result |
|---|---|---|
| Port exists and is not a fabric uplink | `l1PhysIf` (`usage`, `portT`) | block |
| Port is not yet in any selector on the interface profiles attached to that leaf | `infraHPortS`, `infraPortBlk`, `infraRsAccPortP`, `infraNodeBlk` | block |
| Policy group name is not yet used | `infraAccPortGrp`, `infraAccBndlGrp` | block |
| The vPC leaves really are one pair | `fabricExplicitGEp`, `fabricNodePEp` | block |
| The chosen AAEP and policies exist | `infraAttEntityP`, `fabricHIfPol`, `lacpLagPol`, ... | block |
| AAEP contains the product EPG domain and its VLAN pool | `infraRsDomP`, `infraRsVlanNs`, `fvnsEncapBlk` | warning |
| Port is up or has a neighbour | `ethpmPhysIf`, `lldpAdjEp` | warning (the server is already plugged in) |

Same rules as the current ACI module:

- **Permission**: a new explicit permission **ACI: configure interfaces** (`aci-interfaces`, via
  `register(permissions=...)`), ticked in Users; administrators are always allowed. It is not part of "all modules".
- **Audit**: new History action `access-policy`, recorded **before** it is sent to APIC, then marked
  success / failed / unknown (the `audited_apply` pattern); activity log `access_policy.applied` / `.failed` / `.unknown`.
- **No deletes**: the portal only creates new objects. Undo (phase 3) is only for objects created by the portal in that
  change, and only if its path is not yet used by any EPG.
- **Mock APIC**: `tests/mock_apic.py` already has access policies per site (derived from the template paths) and needs
  to create `fabricPathEp` when it receives a new PG + selector. Tests are in `tests/test_aci.py`.

### Phase 3 (optional): undo and cleanup

Undo `access-policy` changes from History (delete the selector / PG created by the portal if its path has no EPG
binding), and a report of unused objects (policy groups without a selector, *configured* ports without a binding) as
input for manual cleanup.

## Options Considered

| Option | Pros | Cons |
|---|---|---|
| **Direct REST from the ACI module (chosen)** | Same as Static Port and Provisioning: one transaction, Review from APIC data, audit before sending, the existing service account | Per-site conventions must be filled in first |
| Ansible `cisco.aci` (`aci_access_port_to_interface_policy_leaf_profile`, etc.) | Ready-made modules | The portal's ACI module does not use Ansible; each module is one request (not one transaction); Review and conflict checks still have to be written by us |
| Stay manual in the APIC GUI | No risk from new code | Not recorded in the portal, no Review, conventions depend on people |
| Configuration templates only (copy-paste JSON) | Simple | No port and name checks, no audit |

## Consequences

- The rule "the portal never changes access policy" is replaced by "the portal only **adds** port configuration
  (policy group, selector, port block) after Review; it never changes or deletes existing ones". The WI and
  `docs/ACI-AUTOMATION.md` are updated.
- The APIC service account of each site needs write rights on `uni/infra` (domain *all*, role *access-admin* or
  equivalent). This needs to be checked; the current account may only have tenant rights.
- Mistakes in access policy affect physical ports: the checks above must be complete, and phase 2 is built only
  after phase 1 is in use and the conventions from the dump are approved.

## Risks

| Risk | Mitigation |
|---|---|
| A port in use is moved to another policy group, traffic drops | The portal never adds a port that is already in a selector; a port that is up is only a warning because a new server is usually already plugged in |
| Overlapping selectors (the same port in two selectors) | Checked in all interface profiles attached to the leaf; existing findings are shown in Phase 1 |
| Wrong AAEP, EPG binding fails | Warning if the AAEP does not contain the domain/VLAN pool of the product EPG; product profile from the dump |
| The fabric already uses the Interface Configuration model | The dump records `infraPortConfig`; if present, the phase 2 design is adjusted |
| The service account lacks rights | Test writes in the lab / mock first; APIC error messages are saved in History as they are now |

## Questions to answer

1. May the rule "the portal does not change access policy" be replaced by "only add, after Review"?
2. Who is allowed: the explicit permission *ACI: configure interfaces* (proposed), or administrators only?
3. Naming convention per site: interface profile per leaf or per vPC pair; policy group name
   (`Openstack-Traffic-<X>-PG`, `RHOSO-TRAFFIC-<X>-PG`, `VMWare-Traffic-C<nn>`, ...); selector and port block names.
   Answered from the dump, then confirmed by the network team.
4. AAEP and policies per product (Acme Flex, Acme Prime, RHOSO): AAEP, link level (10G/25G/100G), LACP active,
   CDP/LLDP. Also from the dump.
5. A port that is already up or has a neighbour: is a warning enough (proposed), or should it be blocked?
6. Is undo / deletion of portal-created objects needed (phase 3), or do we stay without deletion?
7. Does the service account `apic:<site>` have write rights on `uni/infra` now? If not, use a separate account (new
   credential target) or add rights to the existing account?
8. Build phase 1 (read-only page) before phase 2?

## Action Items

1. [ ] The user runs the dump on the bastion (`tools/aci-access-dump/README.md`) and fetches the result.
2. [ ] Analyze the conventions per site from `summary.md`; fill in the product profiles; answer questions 3–4.
3. [ ] Decide questions 1, 2, 5–8.
4. [ ] Phase 1: Fabric → Interfaces page (read-only), tests, local demo, deploy after approval.
5. [ ] Phase 2: port / PC / vPC configuration with Review, audit, permission; mock + tests; demo; deploy.

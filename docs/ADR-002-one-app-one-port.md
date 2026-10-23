# ADR-002: Merge Static Port, Provisioning, and Report into one app on one port

**Status:** Accepted
**Date:** 2026-09-23
**Deciders:** Acme Cloud team (owner of the ACI Web UI)

## Context

After ADR-001 (log in once with an ACI user, choose the site per request), there were still three separate Flask apps:
V8 Static Port (:8080), V9 Provisioning (:8081), and V11 Report (:8082). As a result:

- Users had to log in three times and switch between ports.
- The APIC code (login, session, discovery) was duplicated in three places with different styles.
- Some of the same weaknesses were present in all three:
  - Apply was sent per object (it could fail halfway).
  - There was no preview of changes against the existing state.
  - The VMM provider was always assumed to be VMware.
  - Report used one query per EPG (slow).
  - Export files left temp files behind.

Request: one port only, the functions merged, and everything rebuilt.

## Decision

Rebuild as **one app `aci_webui/` on port 8080** with three tabs and one login:

1. **Separate layers:** `app.py` (routes), `aci.py` (pure ACI logic that receives an `api` function), `apic_sites.py` (multi-site session from ADR-001), and `report.py` (export).
2. **Apply = one POST (one APIC transaction).** Static port sends all `fvRsPathAtt` inside one `fvAEPg`. Provisioning sends one `fvTenant` tree containing VRF, BD, subnet, L3Out, AP, EPG, and domain.
3. **Preview is required before Apply**, with a diff against the existing state:
   - Static port: new / changed (the old VLAN is shown) / same. A binding that is the same is not sent again.
   - Provisioning: create new / use existing / already exists and will be updated, plus warnings (for example the EPG will move to another BD).
4. **Existing objects are not touched:** the "use existing" mode only references the name, and the description is sent only if it is filled in.
5. **Validation on the server:** object names (prevents path injection), VLAN 1–4094, TDN path format, subnet (must not be the network address), scope, domain DN, and duplicate paths. All per-row errors are collected at once.
6. **Report:** one paged `fvRsPathAtt` query (class or subtree depending on the filter). Binding types: Physical / PC / vPC / FEX. Export without temp files, and the file name contains the site and time.
7. **Tests included:** a mock APIC over HTTPS with a simple object model, plus 21 unit and end-to-end tests.

## Options Considered

### Option A: One new app, rewritten (chosen)
| Dimension | Assessment |
|-----------|------------|
| Complexity | Medium: about 2,300 lines including UI and tests |
| Cost | No extra infrastructure |
| Scalability | New sites and products only need configuration or an added tab |
| Team familiarity | Still Flask + vanilla JS |

**Pros:** one login, one port, one code base; atomic Apply; diff preview; has tests.
**Cons:** needs to be tested again in the lab before production use; some small features of the old versions are not carried over (see Consequences).

### Option B: One port through a reverse proxy (nginx) in front of the three old apps
**Pros:** minimal code change.
**Cons:** still three logins/sessions and three code bases, and the old weaknesses are not fixed. Does not meet the request "rebuild everything".

### Option C: Paste the three old apps into one Flask app as they are
**Pros:** fast.
**Cons:** brings the duplication and all the old weaknesses into one place.

## Consequences

- Easier: one URL for all work and all sites, changes are reviewed through preview before Apply, behavior is protected by tests.
- Harder: the session is still in-memory. Restarting means logging in again, and the app must run as a single process.
- Old features that are not carried over:
  - The "Load Sample" button (tenant-specific sample data) — replaced by bulk text.
  - "Duplicate xN" — replaced by an interface range generator.
- The old folders (`aci_webui_dual_exact`, `aci_webui_v11_report_8082`) can be deleted after the new app passes lab tests.

## Action Items

1. [x] Build `aci_webui/` with tests; 21/21 tests pass against the mock APIC, UI verified in the browser.
2. [ ] Test in the lab against the real APIC (DCB, DCA, DCC): login, discovery, preview, then Apply to a test EPG.
3. [ ] Stop the old apps (`aci_webui_dual_exact/stop_all.sh`, the V11 process), then run `aci_webui/start.sh`.
4. [ ] Archive or delete the old app folders after the transition period.
5. [ ] When RHOSO is ready, decide whether a per-product filter is needed in the UI.

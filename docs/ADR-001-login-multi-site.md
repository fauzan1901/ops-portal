# ADR-001: Log in once with an ACI user, choose the site per request

**Status:** Accepted (implementation moved to the combined app `aci_webui/`, see ADR-002)
**Date:** 2026-09-23
**Deciders:** Acme Cloud team (owner of the ACI Web UI)

## Context

There are three Flask Web UIs for ACI: V8 Static Port (:8080), V9 Provisioning (:8081), and V11 Report (:8082).
Before, each app had two layers of login:

1. A web Basic Auth pop-up (one shared account, `BASIC_AUTH_USER` / `BASIC_AUTH_PASSWORD`).
2. An APIC login form with a manually typed IP. One session works with only one APIC.

New requirements:

- There are three sites. Each has one APIC that all products share (OpenStack, VMware, and later RHOSO): DCB 172.26.2.250, DCA 172.24.27.251, DCC 172.25.172.53.
- No web login pop-up. Operators log in with their own ACI user.
- After login, the operator can choose any site for Apply without logging in again.

## Decision

1. **Basic Auth is removed.** The APIC login with a personal ACI user becomes the only gate. APIC RBAC and the audit log record the real user.
2. **Log in once, in parallel to all sites.** `apic_sites.SiteSessions` logs in to all sites in `ACI_SITES` in parallel, then keeps one token per site in memory. The password is not stored. A site that fails to log in is marked with the reason, and this does not cancel the other sites.
3. **Every request carries the site** (`?site=DCB`, form field `site`, or JSON `site`), instead of keeping an "active site" in the server session. This way two tabs can work on different sites without overwriting each other.
4. **Only registered sites can be targeted.** The server maps the site name to the host. The client can no longer send an arbitrary host, so there is no SSRF even though Basic Auth is removed.
5. **Tokens are kept alive.** `aaaRefresh` runs after half of the token lifetime (`refreshTimeoutSeconds`, APIC default 600 seconds). The page calls `/api/keepalive` every 2 minutes so that a site that is not in use does not expire. A token rejected by APIC is turned into a "please log in again" message.
6. **Wrong-site safeguards:** the Site Target card is always visible (sticky), the tab title gets the prefix `[SITE]`, the Apply confirmation names the site and host, and the Apply result shows the site. The V11 export has the site name in the file name and in the Summary sheet.

## Options Considered

### Option A: Log in once to all sites, site per request (chosen)
| Dimension | Assessment |
|-----------|------------|
| Complexity | Medium: one shared module (`apic_sites.py`) |
| Cost | No extra infrastructure |
| Scalability | A new site only needs to be added to `ACI_SITES` |
| Team familiarity | Still Flask + urllib as before |

**Pros:** instant site switching, safe for multiple tabs, no stored passwords, per-user audit.
**Cons:** login takes a bit longer if a site is unreachable (limited by `APIC_LOGIN_TIMEOUT_SECONDS`, default 15 seconds); the user must have an account on every site.

### Option B: Site dropdown, log in again on every site change
| Dimension | Assessment |
|-----------|------------|
| Complexity | Low |
| Cost | No extra infrastructure |
| Scalability | Good |
| Team familiarity | High |

**Pros:** smallest change.
**Cons:** does not meet the requirement "free to apply to any site after login".

### Option C: One service account per site stored on the server
**Pros:** operators do not need to log in at all.
**Cons:** passwords are stored on disk, all changes are recorded under one account so the audit is lost, and the Web UI is open to anyone on the network. Rejected.

## Trade-off Analysis

Keeping the "active site" in the server session is simpler on the client side. However, two tabs that share the same cookie can switch each other's site, and Apply can land on the wrong site. Carrying the site in every request adds one parameter to all fetch calls, but removes that risk completely.

## Consequences

- Easier: switching sites, per-user audit, and adding sites or products (just edit the env).
- Harder: the session is still in-memory. Restarting the app means logging in again, and running more than one worker (gunicorn `-w >1`) needs a shared session store.
- To review again:
  - When RHOSO is ready, decide whether the product must be chosen in the UI (tenant/domain filter) or whether a naming convention is enough.
  - Apply to many sites at once is not supported yet (on purpose, for safety).

## Action Items

1. [x] Module `apic_sites.py` (identical in v8, v9, v11), remove Basic Auth, and add Site Target in all three UIs.
2. [x] Test against a mock APIC: 37/37 scenarios pass, including refresh, expired, a site that fails to log in, and per-site Apply isolation.
3. [ ] Test in the lab against the real APIC (DCB, DCA, DCC) with a read-only user, then with an operator user.
4. [ ] Make sure the Web UI server can reach all three APICs (routing/firewall to 172.26.2.250, 172.24.27.251, 172.25.172.53 port 443).
5. [ ] Decide the UI needs per product (OpenStack, VMware, RHOSO).

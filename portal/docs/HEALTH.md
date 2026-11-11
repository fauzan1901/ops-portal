# Status (module `/status/`)

The health of every product of every site on one page. Its checks run by themselves every 4 hours, **read only**, and
never run a fix. See also `portal/modules/health/`.

## What it shows

- **One card per product** for the chosen site: **OpenStack**, **NetApp ONTAP**, **VMware Cloud** (read only) and
  **Hardware (BMC)**. The checks of each are listed in `modules/health/products.py`. OpenStack also runs the OVN and
  Nova checks: ovn-metadata, ovn-chassis-stale, compute-hypervisor-sync and placement-consistency.
- **Hardware (BMC)**:
  - The check `bmc-health` runs for **every BMC** listed in Runbook Automation → BMC for that site.
  - Every server is one row, for example "Server hardware (BMC): compute-07".
  - A site without BMCs shows Not configured.
  - A new BMC joins the next round by itself.
- **The status of a product** is the worst check of its last round:

  | Status | Meaning |
  |---|---|
  | **Safe** | Every check OK |
  | **Needs attention** | A Warning |
  | **Not safe** | A Problem found |
  | **Could not check** | A check that Could not run or is Unknown |
  | **Not configured** | The site has no such product (for example no ONTAP or vCenter) |

- **Every check** shows its status, a link to its run in Runbook Automation and when it ended. A check that is not OK
  opens by itself and shows:
  - **What it found**: the Warning or Problem steps of the check, with their detail.
  - **Recommendations**: the recommendations of the result. The label *fix* means its fix is asked for on the run page
    with Run this fix (pre-check, then an engineer's review).
  - **Check next**: the follow-up checks, with a link to Runbook Automation → Checks. They are listed as `next` in
    `products.py`.

## Rounds

- A round runs by itself every `STATUS_INTERVAL_HOURS` hours (default **4**) for every site with at least one configured
  product.
- The scheduler starts looking `STATUS_START_DELAY_MINUTES` minutes after the portal starts (default 5), so that an
  install is not followed by many checks at once.
- `STATUS_INTERVAL_HOURS=0` turns the schedule off; only Run now is left.
- **Run now** is open to every user of the Status module, for the site on screen. One round per site at a time.
- The checks of a round run **one after the other**, so that the director, ONTAP or vCenter never get several checks at
  once. Sites run at the same time.
- Every check runs through Runbook Automation as the user **`health`** (an operator without fix rights). Its result is
  in Runs like any run.
- The same check already started by an operator is waited for up to 3 minutes, then recorded as "already running".
- The wait for the result of one check is `STATUS_CHECK_WAIT_MINUTES` (default 30).
- A round running while the portal restarts is recorded as **Stopped**.
- Rounds and their items are kept 30 days (tables `health_rounds`, `health_items`). Their runs stay in Runs.
- A running round shows as a job on the portal's home page, and the updater waits for it.

## Metrics for Grafana

The metrics come on the same endpoint as the alerts, `GET /runbook/api/alerts/metrics` (source token), so no new scrape is
needed:

| Metric | Content |
|---|---|
| `ops_platform_status{site,product}` | 0 safe, 1 needs attention, 2 not safe, 3 could not check (from the last round that ended) |
| `ops_platform_round_age_seconds{site}` | Age of the last round that ended |
| `ops_platform_round_running{site}` | 1 while a round runs |

Example Grafana alerts:
- `ops_platform_status == 2`: a product is not safe, sent on by AlertHub to an operator.
- `ops_platform_round_age_seconds > 9 * 3600`: the rounds are late.

## Access and demo

- The `health` module is given on the Users page. "All modules" includes it.
- Demo: `./test_mode.sh`, then open `/status/` and click Run now. The checks run against the mocks. The demo accounts
  `operator` and `l1` have Status.
- Tests: `tests/test_health.py`.

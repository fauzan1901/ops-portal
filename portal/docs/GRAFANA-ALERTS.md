# Grafana alerts to the portal (Runbook Automation → Alerts)

Grafana (or Prometheus Alertmanager) sends its alerts to the portal. For every alert the portal runs the matching
checks at once and, when the rule gives a check an automatic action, its fix, one item at a time until the problem is
gone. Alerting stays in Grafana: the portal only receives the webhook, it does not create alerts and does not send
notifications. The results are on the pages **Alerts** and **Runs**. The code
is in `modules/wi/alerts.py`, its tests in `tests/test_wi_alerts.py`.

## The flow

1. Grafana sends a notification to `POST https://<portal>/runbook/api/alerts/grafana` with the token of a **source**.
2. The portal records every alert with its labels on the page **Alerts**.
3. Every matching **rule** (alert name and labels) runs **all its checks** (1 to 10):
   - the site comes from the rule or from a label;
   - the parameters of each check are filled from the labels;
   - each check is a run of its own, runs as the account `grafana` and is listed in Runs;
   - on the page Alerts, an alert has one row per check.
4. The same check of the same rule, with the same site and parameters, runs again only after the *cooldown*
   (default 30 minutes). Grafana sends an alert that is still firing again at every group interval and repeat interval.
5. When the check has an **automatic action** on the rule, the portal measures with the measuring check and runs the
   fix one item at a time until the problem is gone (see [Automatic actions](#automatic-actions)).
6. At most 10 checks from alerts run at the same time (`RUNBOOK_ALERT_MAX_CHECKS`). Further alerts are recorded as
   "Not checked" and are checked on the next Grafana notification.

A `resolved` alert closes the firing alert with the same fingerprint.

## For the monitoring team: connecting Grafana

A portal administrator creates one **source** per Grafana or per team in Alerts → Sources → **Add source**.
- The token is shown once. The portal keeps only its hash.
- If the token is lost, create a new one with **New token**. The old token stops working at once.
- **Allowed from** (optional) limits the sender addresses, as the portal sees them.

In Grafana: **Alerting → Contact points → Add contact point**, integration **Webhook**.

| Field | Value |
|---|---|
| URL | `https://<portal address>/runbook/api/alerts/grafana` (the button **How to connect** in the portal shows it) |
| HTTP Method | `POST` |
| Optional Webhook settings → Authorization Header | Scheme `Bearer`, Credentials = the token of the source |
| TLS | If the portal certificate comes from an internal CA, add the CA in the TLS settings |

Then, in **Notification policies**, route the alerts the portal should check to that contact point. Keep resolved
messages on. Basic auth is accepted too: any user name, password = the token.

Prometheus Alertmanager:

```yaml
receivers:
  - name: ops-portal
    webhook_configs:
      - url: https://<portal address>/runbook/api/alerts/grafana
        send_resolved: true
        http_config:
          authorization:
            type: Bearer
            credentials: <token>
```

Useful labels:
- `site`: DCA, DCB, DCC, or a value that contains a site name such as `dca-openstack`.
- `instance`: the host address, for example `10.253.128.5:9100`; the port is ignored.
- `severity`.

An alert without a label a rule needs is still recorded, with "Not checked: The alert has no label …".

Portal answers:

| HTTP | Meaning |
|---|---|
| 200 | Accepted: `{"alerts": n, "checks": k, "ignored": i}` (`ignored`: alerts that match **Ignore alerts named** of the source) |
| 400 | The body is not a Grafana / Alertmanager notification (not JSON, no `alerts`, or an alert without `labels`); from a known sender, a sample is kept for the administrator |
| 401 | Wrong token, source disabled, or no Authorization header (except from an address in **Accept without a token from**) |
| 403 | The sender address is not in the **Allowed from** list of the source |
| 413 | The body is larger than 1 MiB |
| 429 | More than 600 alerts per minute from one source |

## Senders that cannot send a token (no Authorization header)

Some senders cannot set an Authorization header, for example a webhook relay of the monitoring team. For such a
sender an administrator fills in **Accept without a token from** on its source (Alerts → Sources → **Edit**).

- **Exact IPv4 addresses only**, no networks or ranges, at most 10.
- When the source has **Allowed from**, every address must be inside it. Example: a source with Allowed from
  10.248.80.0/23 gets `10.248.81.15, 10.248.81.16, 10.248.81.18`.
- An address may belong to one active source only.
- Every change of this field must be confirmed by typing the source name, and is recorded in Activity
  (`wi.alert_source`) with the addresses before and after.

How it works:

- A request **without an Authorization header** from one of these addresses is taken as coming from that source.
- A request without a header from any other address, even inside Allowed from, is still refused with **401**.
- A request with a **wrong token**, also from a listed address, is still refused with **401**. The right token and
  Basic auth keep working as usual.
- An alert received without a token is handled like any other alert. Its rules run, including their automatic
  actions; this is the owner's decision.

To keep it visible:

- The source row shows "**no token** … without a token from 10.248.81.15, …".
- An alert received without a token has the label **no token** in the Received list.
- The portal log writes "no token" for every such notification.

The address the portal sees is the client address after nginx (`OPS_TRUSTED_PROXIES`). An IPv4 address written as
IPv6 (`::ffff:a.b.c.d`) is read as its IPv4 address.

## Notifications the portal cannot read

A known sender sometimes sends a body that is not in the Grafana or Alertmanager format. A known sender is one with the
right token, or one from an address accepted without a token. Examples: a body that is not JSON, JSON without an
`alerts` list, or `alerts` without `labels`. Then:

- The portal answers **400** with "… The notification was recorded for the portal administrator".
- The portal keeps a **sample**: time, source, client address, User-Agent, Content-Type, size, reason and body (cut at
  8 KB).
- Only the **last 20** are kept. No other header is kept, Authorization and tokens included.
- The limit of 600 per minute per source applies to samples too.

Administrators see them on the card **Notifications the portal could not read** on the page Alerts:

- Every row opens to show its body. A JSON body is shown formatted.
- **Delete samples** deletes all samples after a confirmation, recorded in Activity (`wi.alert_samples`).
- Operators cannot see the bodies: the API `/runbook/api/alerts/samples` is for administrators only.

The samples are used to write the mapping of a new format into the portal rules (for example the relay format below).
An unknown sender (no token, from an address that is not listed) is refused with 401 and nothing is kept.

**Read again (administrators).** Once a new mapping is installed, old samples can be read again without waiting for
the sender: Grafana repeats an alert that is still firing only after its repeat interval, which can be hours. Use
**Read again** on a row, or **Read all again** in the card header.

- The body of the sample is read again with the mapping in force now (`normalize`).
- When it can be read, the sample is accepted as a notification of its source, from the client address of the
  sample, exactly as the receiver does: rules, checks, cooldown / duplicates and **Ignore alerts named** all apply.
  Then the sample is deleted, and Activity records `wi.alert_samples` ("Sample #n … read again: 1 alert, …").
- When it still cannot be read, the answer is 400 with the reason, and the sample is kept.
- A sample whose body was cut at 8 KB (its real size is kept) cannot be read again: the sender has to send it again.
- The source of the sample must still exist and be enabled.
- **Read all again** reads the samples oldest first, in the order they came. Only the samples that could be read are
  deleted.

## Alerts nobody needs (Ignore alerts named)

Per source, an administrator can fill in **Ignore alerts named** (Alerts → Sources → **Edit**), for example
`Speedtest*` for a "Speedtest Bandwidth Low" alert that nobody needs.

- Alert name patterns, as in the alert name of a rule: `*` matches any text, case-insensitive. One per line or
  separated by commas. At most 20 patterns of at most 200 characters each.
- The notification is still accepted (200). An alert whose name matches, firing or resolved, **is not recorded and
  starts nothing**.
- The answer and the portal log count them (`"ignored": n`).
- The source row shows "ignores Speedtest* · 12 ignored in 7 days" (counts per day in the table `wi_alert_ignored`).
- Alerts of that source **received before** the pattern was saved that match it are **hidden, not deleted**: history
  is never deleted silently. The mark is the column `ignored` of `wi_alert_events`.
  - The Received list and its counts leave them out by default.
  - **Ignored** in the state filter shows only these alerts, labelled "ignored".
  - When the pattern is removed or changed so that it no longer matches, they show again.
  - Matching uses the current source name. Alerts recorded under an older name of the source (before a rename) are not
    hidden.
  - At start the portal applies the saved patterns once more, so after an upgrade old matching alerts are hidden
    without saving the source again.
  - Rules, cooldown and **Create rule** still read this history as usual.
- Every change of the patterns is recorded in Activity (`wi.alert_source`), for example "ignore alerts named: old → new
  (12 earlier alerts hidden)" or "(… shown again)". No typed confirmation is needed: the change never starts anything
  that did not run before.

### The Ignore button on an alert

Administrators do not need to open Edit source: every alert in the Received list has an **Ignore** button.

- Ignore adds the **exact name** of the alert to **Ignore alerts named** of its source. `*`, `?` and `[` in the alert
  name are taken literally.
- After the confirmation, alerts with that name from that source are no longer recorded, so no rule, check or
  automatic action runs for them.
- Alerts with the same name already received move to the history (**History: ignored**).
- **Stop ignoring** on an ignored alert takes the name out again, and its older alerts show again.
  - When the alert is ignored by a `*` pattern (for example `Speedtest*`), the portal refuses and asks for the change
    through Edit source: that pattern ignores other alerts too.
- Both are recorded in Activity (`wi.alert_source`): "ignore alerts named X (Ignore on alert #n; …)".

## AlertHub (webhook relay of the monitoring team)

A monitoring team may send its alerts through AlertHub (`User-Agent: AlertHub-Webhook/1.0`, without a token, see above). Its
messages have their own format (`"event": "alertify.analysis"`), and the portal reads them like a Grafana notification
(`alerts.normalize`):

- When the message carries the original Grafana notification in `grafana` (or `raw`), that notification is used:
  labels, annotations, `fingerprint`, `startsAt` and `status` from Grafana.
- When there is only a markdown message (`*ALERT: <alert name>*`, `**Node:**`, `**Cluster:**`, `**Site:**`, `**Role:**`,
  `**Instance:**`, `**Status:**`), it is read into the labels `alertname`, `nodename`, `cluster`, `site`, `role`,
  `instance`. Other fields (for example `Usage`) become annotations. `Status: Resolved` closes the alert. The
  `fingerprint` is made from the alert name, node, instance and cluster, so the same alert stays one.

A rule for a AlertHub alert uses the same labels as a Grafana alert, for example Alert name `OpenStack Cloud Node High Memory
Usage`, Site `{{labels.site}}` and the host parameter `{{labels.nodename}}`. A AlertHub message with another event or
without an `ALERT:` line is kept as a sample (previous section).

## Metrics for the monitoring team's Grafana: automation failures reach an operator

The portal sends no notification of its own. The way back uses the same chain as the incoming alerts:
1. The monitoring team's Prometheus scrapes the portal metrics.
2. Their Grafana makes an alert from them.
3. The relay passes it to the operators like any other alert.

- Endpoint: `GET /runbook/api/alerts/metrics`, Prometheus text format 0.0.4.
- Authentication as for the receiver: the token of a source (Bearer, or Basic password), or no header from an address
  the source accepts without a token. The addresses a source allows apply too.
- Counts only. No target names, VM names or result text.

| Metric | Meaning |
|---|---|
| `ops_alert_actions_need_operator{window,site}` | *Run* automatic actions that ended in the window (`1h`, `24h`) in a way an operator must take over: `failed`, `error`, `refused`, `measure`, `no-fix`, `no-items`, `max`, `restart`. Every site is always listed, 0 when there are none. Pilot mode (Observe) is not counted. |
| `ops_alert_actions_running{site}` | Automatic actions running now. |
| `ops_alert_actions_ended{window,site,rule,mode,stop}` | Actions that ended in the window, by the way they stopped. `gone` means the problem is solved, `observed` is a pilot-mode record. |
| `ops_alerts_received{window,site,state}` | Alerts received. Ignored alerts are not counted. `state="no-rule"`: there is no rule for the alert yet. |
| `ops_alert_automatic_actions_paused` | 1 while all automatic actions are paused. |
| `ops_alert_site_frozen{site}` | 1 for a site where automatic changes never run. |
| `ops_fix_reviews_waiting{site}` | Manual fix requests whose pre-check passed and that wait for an engineer's review (page Fix reviews). Every site is always listed, 0 when there are none. See [WI-CHECK-ACCESS.md](WI-CHECK-ACCESS.md). |

Example Prometheus scrape (set up by the monitoring team; the source token is kept in a file, not in the
configuration):

```yaml
- job_name: ops-portal-alerts
  metrics_path: /runbook/api/alerts/metrics
  scrape_interval: 1m
  authorization:
    type: Bearer
    credentials_file: /etc/prometheus/ops-portal.token
  static_configs:
    - targets: ["ops-portal.example.internal:8480"]
```

Example alert rules in their Grafana:
- **Portal automation needs an operator**: `max by (site) (ops_alert_actions_need_operator{window="1h"}) > 0`.
  It resolves by itself one hour after the last action that stopped. The label `site` is passed on by the relay.
- **Portal automatic actions paused** (optional): `ops_alert_automatic_actions_paused == 1` for more than 2 hours.
- **Portal fix review waiting**: `max by (site) (ops_fix_reviews_waiting) > 0` for 2 minutes. The relay passes it to
  the engineer on duty. It resolves by itself once the request is reviewed, withdrawn or expired.

These alerts also come back to the portal through the relay. So that they start nothing, add the patterns
`Portal automatic*` and `Portal fix review*` to **Ignore alerts named** of that source, or leave them without a rule
(recorded as `no-rule`).

Automatic actions of a rule do not go through the engineer's review of manual fixes: the owner's approval is recorded
on the rule. A fix an operator runs from a check result always goes through the pre-check and review
(WI-CHECK-ACCESS.md).

## Rules (administrators)

Alerts → Rules → **Add rule**, or **Create rule** on an alert that has no rule yet.

| Field | Meaning |
|---|---|
| Alert name | `alertname` of the Grafana alert rule, case-insensitive. `*` matches any text |
| Labels | One label per line: `severity=critical`, `team!=dns`, `instance=~10\.0\..*`, `env!~dev\|test`. A regex must match the whole value, as in Prometheus |
| Site | A site name, or `{{labels.site}}` |
| Checks | One or more checks that are ready to run (**Add a check**). Example: the alert "Nova compute down" runs OpenStack services, Pacemaker health and Compute memory together. Log collection (collect logs, sos report) cannot be started from an alert |
| Parameters (per check) | Text with `{{labels.<name>}}`, `{{annotations.<name>}}`, `{{alertname}}` and the filters `\|host` (address without port or scheme), `\|short`, `\|lower`, `\|upper`. Empty means the default of the check |
| Check again after | Cooldown in minutes (0 to 1440) |

**Try** tests a rule on an alert already received: whether it matches, its site and, for each check, the parameters
it produces or why the check cannot run. Nothing runs while trying.

### Presets: rules for the alerts that may come

`modules/wi/alert_presets.yml` holds ready rules for the alerts the monitoring team's Grafana (through AlertHub) may send,
for every domain, not only OpenStack:

- **Hardware**: DIMM, PSU, fan, temperature, BMC.
- **OpenStack computes**: high memory or CPU, with live migration of the smallest instances first.
- **Other OpenStack nodes**: controllers, disk / iSCSI paths, node disks, node down.
- **Control plane**: Galera, RabbitMQ, Pacemaker, OVN, API.
- **Storage**: floating IPs, Cinder pools, ONTAP.
- **CDN**: /run, root disk, memory, datasource.
- **Other**: certificates, DNS, SIEM, GB200, VMware Cloud (read only), and any other Linux host.

How to use them:

- **Create rule** on a received alert fills the form from the **first** matching preset. A match is decided by alert
  name patterns and labels, for example a `nodename` label that contains `compute`. The alert name is taken exactly
  from the alert.
- **Add rule → Start from a preset** fills the form from the chosen preset, with its first name pattern.
- The order of the presets matters:
  - hardware comes first, so that "Memory ECC error" is not taken for a full memory;
  - OpenStack computes are recognised by `nodename`;
  - a plain Linux host is the last preset.
- A preset **saves nothing**. The administrator reads the form, changes it when needed, and saves; on save the rule is
  checked like any other.
- The automatic action of a preset (for example live migration on compute memory / CPU, or deleting AIDE files on a
  CDN's /run) always starts in **Observe only**.
  - The action is filled in only when its fix has already appeared in a portal run.
  - When it has not, the form says to run that check once from Checks. Running the fix is not needed.
- `tests/test_wi_alerts.py` checks every preset: its checks exist, parameters and templates are valid, its fix text is
  really a fix of that check, and its label regexes have no comma.

Example **compute memory** (preset `openstack-compute-memory`):

| Check | Content |
|---|---|
| 1. Overcloud node health | `role=compute`, `node={{labels.nodename}}`, `mem_warn=80` (measuring) |
| 2. Live migrate instances of a compute | `compute={{labels.nodename}}`. Automatic action: *Live-migrate the instances you tick off …*, **Smallest first**, at most 5 per alert, stops when check 1 no longer reports memory above `mem_warn` |

The **compute CPU** preset is the same but stops on `cpu_warn`. The percentages can be changed in the threshold field of
the action. The field "Destinations: CPU and RAM under (%)" of check 2 is the limit for the **destination** computes,
not the stop condition.

Example **Cinder pool** (preset `cinder-pool`, for an alert such as "Cinder volume over 80%"):

| Check | Content |
|---|---|
| Cinder volume over 80% | `pool` = the pool of the alert (fixed, or a label such as `{{labels.pool}}`, so that only that pool is measured), `snapshot_days=14`, `pool_warn=70` (**Bring the pool under (%)**) |
| Action | *Delete the snapshots older than 14 days of one volume…*: volume by volume, at most 10 per alert. **Then**: *Migrate volumes from …*, **Smallest first**, at most 5. The action stops as soon as the pool is under `pool_warn` |

- A volume that still has newer snapshots is never migrated by itself.
- Deleting snapshots cannot be undone. So Run mode needs the owner's approval and a ticket, and the preset always
  starts in Observe only.

Other presets with an automatic action from a fix their check already offers (all start in **Observe only**, measured
again by the same check):

| Preset | Automatic action | At most per alert | Stays for a person |
|---|---|---|---|
| `certificates` | *Renew the certificates that expire soon*: `getcert resubmit` per request (CA_UNREACHABLE / stuck ones are not taken) | 5 | fixing the reach to IdM |
| `compute-storage-paths` | *Give the disks without any path their paths back*: re-scan the lost SCSI addresses, WWID checked | 4 | moving leftover instance directories |
| `cdn-datasource` | *Start the stopped lb container* (only when the container is stopped) | 1 | restarting a running lb (it carries traffic) |
| `dns` | *Free the disk*: empty `/var/log/syslog` and remove its archives | 1 | turning query logging off (a configuration change and a restart) |
| `siem` | *rsyslog must run and listen …*: restart rsyslog when it does not run / listen on 514 | 1 | opening ports in firewalld |

A GB200 NIC link is never an automatic action either. The test `test_presets_with_a_safe_fix_get_an_automatic_action`
keeps this list.

## Automatic actions

Every check of a rule can have one **automatic action**: one fix that a result of that check has offered. After the
check, the portal measures first. As long as the measuring check still reports the problem on the target of the fix
(compute, host), the portal runs **one item** (for example one live migration), or the whole fix once when it has no
items, and measures again. Automatic actions work for every kind of fix: SSH host, OpenStack, ONTAP, VyOS, and fixes
with ticked items.

This replaces the ticks "Fixes that run by themselves" of the earlier version. At start, a fix that was allowed on a
rule becomes the automatic action of its check (the whole fix once, measured by the check itself). A check has one
action at most; a second fix of the same check is not carried over, and this is recorded in Activity
(`wi.alert_rule`).

### Fields per check (Edit rule → Check n → Automatic action)

| Field | Meaning |
|---|---|
| Fix that runs by itself | A fix that has appeared in a result of this check from this rule, **or from any run of the same check in the portal**, for example a drain by an operator or a health round. A fix from another run is marked "seen in Run #n". So a new rule can get its action without waiting for its first alert. The portal reads new runs whenever the Alerts page opens (`scan_runs`, at most the 200 newest runs at a time). The same fix for another compute or host counts as the same action (`fix_shape`): "off ha-2" equals "off compute-7" |
| Mode | *Observe only (pilot)*: measures and records what would run, changes nothing. *Run*: really runs the fix. A newly chosen fix always starts in *Observe only*. Actions saved before modes existed count as *Run* |
| Order of the items | Fixes with items only: *As listed* (default), *Smallest first* or *Largest first*. The last two exist only when the items have a size. For live migration the size is the RAM of the instance flavor (MiB): *Smallest first* moves the smallest VM first |
| At most per alert | The maximum number of items per alert, 1 to 50 (default 5). For a fix **without items**: how many times the same fix may run for different volumes or hosts of the same result (default 1), for example the old snapshots of volume A, then volume B, and so on, one at a time with a measurement each time. The same fix on the same target is not repeated within one action |
| Then, when it has nothing left | Optional. A second fix of the same check, run once the first has nothing left to do or reached its maximum while the measuring check still reports the problem. For example delete old snapshots first, then migrate volumes. The second fix has its own *Order* and *At most per alert*. The owner's approval covers both fixes |
| Items an operator ticks | Items the check marks *manual* are **never** taken by an automatic action. For example a volume that still has (newer) snapshots: migrating it deletes all its snapshots, so an operator must tick it |
| Stop when this check no longer reports it | The measuring check: this check or another check of the same rule, for example *Overcloud node health* measuring and *Live migrate instances of a compute* acting |
| Threshold (parameter of the measuring check) | A numeric parameter of the measuring check for the stop condition, for example `mem_warn = 80` for node memory or `cpu_warn = 70` for CPU, or both. Only the topics filled in are measured. The default `mem_warn = 75` applies only when the rule sets **no threshold at all** and neither does the measuring check, so a CPU rule no longer stops on memory. Empty means the check's own value |

Every new or changed action must be confirmed by typing the rule name. Changing the mode is a change too.

### Pilot first: Observe only

*Observe only* shows the decisions of an action on real alerts before the action may change anything. It goes the same
way as *Run*: the measuring check runs and the decision follows the same rules, but no fix runs. When the problem is
still there, the action records:

- the items it would run, in their order (for example *smallest first*) and at most *At most per alert*. For live
  migration, the VM names and their RAM. For a fix without items, the fix itself once;
- a summary of the destinations from the result of the acting check, when that check has a *Destinations* step
  (compute drain: how many computes are under the CPU / RAM limit now, and their names). **The destination of each VM
  cannot be known in advance**: in *Run*, `wi_ops` picks it right before that VM's migration, with the same guards as
  Run fix;
- why *Run* would stop at that moment, if it would: switch off, site frozen, or no owner's approval yet.

Then the action stops with the state **Observed**. The column Result reads, for example:

> Automatic action #7 (observe only, would run 2 instances, nothing changed): Overcloud node health (run #905): Memory:
> 82% used (…). Observe only, it would run 2 instances of 3 that can run, smallest first: 1. vm-small (2 GiB), 2. vm-mid
> (4 GiB). In Run mode they run one at a time, … Destinations: CPU and RAM under 70%: 4 of 12 compute(s) are under 70%
> CPU and RAM now (…). Under the limit now: … In Run mode now: Locked: customer-impacting (…). Nothing was changed.

Because it changes nothing, *Observe only*:

- needs no owner's approval;
- still runs on a frozen site and while the global switch is off, as the checks do;
- is not counted in, and not limited by, the hourly limit and the 6-hour pause of *Run*. The rule cooldown still
  applies.

Still in force: one action per target at a time, an action stops when its rule changes, and fixes that may never run by
themselves (VMware Cloud, ESXi, database) cannot be chosen.

Suggested use: run a new rule in *Observe only* for about a week. Read the column Result of every alert: are the VMs
it would move the expected ones, and is there a destination under the limit? Then switch to *Run*, with the owner's
approval.

### When an action stops

The order is: measure, one item, measure again, and so on. The action stops at the first of:

- **Problem gone**: the measuring check is OK, or its finding for that target is gone. With a threshold on the rule,
  only the steps of the same topic are read (`mem_warn` means the Memory step): a disk warning on the same node does not
  keep migrations going.
- **Maximum reached**: the items reached *At most per alert*. A fix without items runs once. Then an operator takes
  over.
- **Item failed**: the action stops at the first item that fails or that an operator cancels, and never goes on after
  a failure.
- **The measuring check cannot tell**: its result is Not checked or Could not run, or it cannot run.
- **Something changed on the way**: the switch is turned off, the site is frozen, the rule is changed or disabled, the
  approval no longer holds, or the latest check result no longer offers the fix. The running item finishes and is not
  cancelled; the next item does not run.
- **Portal restart**: a running action ends, and the operator sees the last fix in Runs.

Everything is recorded. Each item is a fix of its own in Runs, as `grafana`, with the rule, the alert number, the action
number, "item k of at most n" and the approval. Activity (`wi.alert_action`) records the start and the end of the
action. The column **Fix** of the alert shows the state of the action (Running, Problem gone, Maximum used, Failed,
Stopped, Observed), and the column **Result** what it did and why it stopped. Example:

> Automatic action #4 (3 instances moved, smallest first: vm-a (2 GiB), vm-b (4 GiB), vm-c (8 GiB)): Overcloud node
> health (run #812): Memory: 72% used (…). Threshold 75% / 95%. The problem of overcloud-novacomputeha-2.localdomain is
> gone: stopped.

### The owner's approval for fixes with an impact on customers

A fix with an **impact on customers** runs by itself (*Run*) only when the owner's approval is recorded on the rule.
*Observe only* needs no approval. Switching *Observe only* to *Run* is a change of the rule, so the action is locked
until a new approval is recorded. When every customer-impacting action goes back to *Observe only*, the old approval
ends too. This covers every fix other than a normal-risk fix on an SSH host:

- OpenStack, ONTAP or VyOS changes;
- fixes with ticked items (live migration, image deletion and the like);
- change steps of a template;
- high risk: delete, truncate, kill, restart, stop or reboot (`fixes.HIGH_RE`);
- firewall, network, package, account or mount changes (`alerts.AUTO_DENY`).

To record the approval (Edit rule → Automatic actions):

1. Fill in **Owner's approval: ticket or reference** with the ticket number or reference of the owner's approval.
2. Type the rule name to confirm.
3. Save. The administrator who saves is recorded as the approver (from the session), with the time and the ticket.

The approval shows on the rule row ("Approved by X, ticket Y, date") and in Activity (`wi.alert_rule`).

- A rule without approval is saved, but its action is **locked** (label *locked*) and does not run. The column Result
  of the alert reads "Locked: customer-impacting (...)".
- The approval covers the rule as it is: alert name, labels, site, checks with their actions, and the hourly limit.
  When any of these changes, the action is locked again until a new approval is recorded.
- Normal-risk fixes on an SSH host need no approval, only the typed rule name.

### What never runs by itself

With or without approval, these never run by themselves:

- **VMware Cloud** (checks of the Prime category) and **ESXi hosts** (group `esxi`): both are read-only from the
  portal;
- fixes that **write to a database directly**: SQL that writes, `*-manage`, and `reset-state` (`alerts.DB_WRITE`).
  Database changes stay with an operator, following the team rules.

Such fixes are still listed on the rule (*never by itself*, with the reason), but cannot be chosen.

The **LUN copy guard** works per run instead: instance migrations, volume migrate / retype, detach and retype rollback can
still be chosen as automatic actions, but an item or fix the guard marks *manual* is skipped in that run (the LUN of its
volume is also in another FlexVol of the same SVM, is not in its pool, is not found, or NetApp / the Cinder database cannot
be read). When every item is manual, the action runs nothing, the same as when nothing can run by itself. See
[WI-COVERAGE.md](WI-COVERAGE.md#lun-copy-guard-flexclone).

### Guards that always apply

- **Global switch** on the card *Automatic fixes*: untick **Automatic actions of the rules run** to stop every action.
  Checks keep running, and a running action stops before its next item.
- **Sites where automatic changes never run** (card *Automatic fixes*): **optional and empty by default**. An
  administrator can tick a site that must not be changed automatically for now, for example during an incident there.
  Checks keep running on that site, but nothing is changed automatically; the column Result gives the reason. Every
  change of the list is recorded in Activity (`wi.alert_settings`).
- **One action per target at a time**. A second alert for the same compute or host is recorded "already being handled
  by run #n (automatic action #a ...)" and starts nothing.
- **Hourly limit**: at most N *Run* automatic actions per hour per rule (default 3). *Observe only* is not counted.
- **Cooldown**: a *Run* action with the same fix on the same target at most once every 6 hours. An alert that comes
  back after that waits for an operator. *Observe only* is not counted.
- **Migration guards**: every live migration goes through the same checks as with Run fix: spread of large VMs, server
  group affinity, and destination capacity (under the CPU / RAM limit). One migration per site at a time.

## Storage

- Tables: `wi_alert_sources` (with the columns `tokenless` and `ignore_names`), `wi_alert_ignored` (ignored alerts per
  source per day), `wi_alert_rules`, `wi_alert_events` (column `auth`: `token` or `none`; column `ignored`: 1 = hidden by
  a pattern of its source), `wi_alert_fixes_seen` (with `impact`, `items`, `sized`), `wi_alert_actions` (one row per
  automatic action: loop, items, stop reason; column `mode`: `run` or `observe`, an *Observe only* item has the state
  `observed` and no fix number), `wi_alert_settings` (the automatic-action switch and `frozen_sites`, empty by default)
  and `wi_alert_samples` (the last 20 notifications that could not be read). New columns are added to older tables at
  start.
- By default the Alerts list shows only the alerts **still firing**, so that resolved and ignored alerts do not pile
  up. They are not deleted but move to the history: choose the state **History: resolved**, **History: ignored** or
  **All alerts** to see them.
- `wi_alert_fixes_seen` rows with `rule_id = 0` hold the fixes seen in any portal run (the choices of actions for a new
  rule). `wi_alert_settings.known_run` keeps the number of the last run read.
- Alerts are kept for `RUNBOOK_ALERT_KEEP_DAYS` days (default **30**), then deleted. The runs and fixes they started stay.

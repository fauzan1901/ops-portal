# Grafana alerts to the portal (Operation Automation → Alerts)

Grafana (or Prometheus Alertmanager) sends its alerts to the portal. For every alert the portal runs the matching
checks at once and, when allowed, the safe fixes. Alerting stays in Grafana: the portal only receives the webhook, it
does not create alerts and does not send notifications. The results are on the pages **Alerts** and **Runs**. The code
is in `modules/wi/alerts.py`, its tests in `tests/test_wi_alerts.py`.

## The flow

1. Grafana sends a notification to `POST https://<portal>/wi/api/alerts/grafana` with the token of a **source**.
2. The portal records every alert with its labels on the page **Alerts**.
3. Every matching **rule** (alert name and labels) runs **all its checks** (1 to 10):
   - the site comes from the rule or from a label;
   - the parameters of each check are filled from the labels;
   - each check is a run of its own, runs as the account `grafana` and is listed in Runs;
   - on the page Alerts, an alert has one row per check.
4. The same check of the same rule, with the same site and parameters, runs again only after the *cooldown*
   (default 30 minutes). Grafana sends an alert that is still firing again at every group interval and repeat interval.
5. When a check finds a problem and the rule allows its fix, the fix runs by itself. The check then runs again as
   usual.
6. At most 10 checks from alerts run at the same time (`WI_ALERT_MAX_CHECKS`). Further alerts are recorded as
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
| URL | `https://<portal address>/wi/api/alerts/grafana` (the button **How to connect** in the portal shows it) |
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
      - url: https://<portal address>/wi/api/alerts/grafana
        send_resolved: true
        http_config:
          authorization:
            type: Bearer
            credentials: <token>
```

Useful labels:
- `site`: DCA, DCB, DCC, or a value that contains a site name such as `dca-openstack`.
- `instance`: the host address, for example `10.253.0.5:9100`; the port is ignored.
- `severity`.

An alert without a label a rule needs is still recorded, with "Not checked: The alert has no label …".

Portal answers:

| HTTP | Meaning |
|---|---|
| 200 | Accepted: `{"alerts": n, "checks": k}` |
| 400 | The body is not a Grafana / Alertmanager notification (no `alerts`) |
| 401 | Wrong token, source disabled, or no Authorization header |
| 403 | The sender address is not in the **Allowed from** list of the source |
| 413 | The body is larger than 1 MiB |
| 429 | More than 600 alerts per minute from one source |

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

## Fixes that run by themselves

Fixes with an impact on customers and database changes stay manual: an operator runs them. So a fix runs by itself
only when **all** of these hold:

- An administrator ticked it on the rule. Only fixes that appeared in the results of the checks of that rule can be
  ticked, and the rule name must be typed to confirm. It is recorded in Activity (`wi.alert_rule`). A check removed
  from the rule takes its fixes with it.
- The fix runs on an **SSH host** (Hosts & SSH) whose credential may run fixes. sites.yml hosts are read-only.
- **Normal risk**. Not delete, truncate, kill, restart, stop, reboot and the like (`fixes.HIGH_RE`).
- It does not change firewalls, network addresses or links, packages, accounts or mounts (`alerts.AUTO_DENY`).
- Not an OpenStack, ONTAP or VyOS fix, not a fix with ticked items (migrations, image deletion and the like), and not
  a change step of a template.
- At most N times per hour per rule (default 3).
- The same fix on the same target at most once every 6 hours. If the alert comes back after an automatic fix, it
  waits for an operator.
- The check result is Problem or Warning.
- **Allowed fixes run by themselves** on the card Automatic fixes is ticked. Untick it to stop every automatic fix at
  once, for example during a freeze or maintenance. The checks keep running.

Automatic fixes are recorded in Runs and Activity as `grafana`, with the rule and the alert number. If an allowed fix
cannot run (for example a read-only sites.yml host), the reason is in the column Result.

Example (CDN root disk): of the four fixes the check offers, only "Create the HAProxy logrotate rule" can be ticked.
Truncating logs, vacuuming the journal and restarting a service are locked because their risk is high.

## Storage

- Tables: `wi_alert_sources`, `wi_alert_rules`, `wi_alert_events`, `wi_alert_fixes_seen`, `wi_alert_settings` (the
  automatic-fix switch).
- Alerts are kept for `WI_ALERT_KEEP_DAYS` days (default 180). The runs they started stay.

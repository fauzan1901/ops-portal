# Changelog

## v0.1.0 (2026-11-09)

First tagged release of the public copy.

- **Operation Automation**: checks and fixes of the operations work instructions for OpenStack, NetApp ONTAP,
  VMware vCenter / NSX-T / vCloud Director, server BMCs and Linux hosts; log collection; a step-by-step router
  upgrade; compute drains that skip an instance that cannot move; a controller reboot readiness check.
- **Alerts**: Grafana or Prometheus Alertmanager webhooks start the matching checks, and allowed low-risk fixes.
- **ONTAP Restore**: OpenStack volumes back from NetApp snapshots, with approvals.
- **ACI**: static port bindings, product templates, vPCs, provisioning, reports and IP usage.
- **Shell**: SSH terminals in the browser with access per host, recorded sessions and live watch / join.
- MIT license, screenshots in the README, tests on GitHub Actions.

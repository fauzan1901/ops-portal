# Changelog

## v0.2.0 (2026-11-11)

- Modules have their own names and paths: Runbook Automation (`/runbook/`), Snapshot Restore (`/restore/`), Fabric
  Manager (`/fabric/`), Web Terminal (`/terminal/`) and Vulnerability Scans (`/vulns/`); environment variables,
  metric names and ports follow (demo on port 8483).
- **Vulnerability Scans**: Tenable Vulnerability Management findings and scans per site, limited to management networks.
- **Alerts**: automatic actions with a stop condition (measure, one item, measure again), an observe-only pilot mode,
  the owner's approval for customer-impacting fixes, ignore patterns, senders without a token, unreadable samples
  kept for the administrator, and a Prometheus metrics endpoint.
- **Fix review**: every manual fix is pre-checked and reviewed by an engineer before it runs.
- **Status** (`/status/`): read-only checks of every product of every site (OpenStack, NetApp ONTAP, VMware Cloud,
  server BMCs) every 4 hours, one card per product (safe, needs attention, not safe), recommendations and metrics.
- **LUN copy guard**: instance migrations, volume moves / retypes and detaches become manual while the LUN of a volume
  also exists in a FlexClone of its pool (or cannot be read); automatic actions never take them.
- New OpenStack checks: OVN metadata, stale OVN chassis (with a reviewed fix), Nova against libvirt, Placement
  allocations; the OVN database check also reads memory and neutron-server RSS.
- Alert presets: observe-only automatic actions for certificates, disk paths, CDN datasource, DNS disk and syslog
  collector; a sos report runs only while fencing is off.

## v0.1.0 (2026-11-09)

First tagged release of the public copy.

- **Runbook Automation**: checks and fixes of the operations work instructions for OpenStack, NetApp ONTAP,
  VMware vCenter / NSX-T / vCloud Director, server BMCs and Linux hosts; log collection; a step-by-step router
  upgrade; compute drains that skip an instance that cannot move; a controller reboot readiness check.
- **Alerts**: Grafana or Prometheus Alertmanager webhooks start the matching checks.
- **Snapshot Restore**: OpenStack volumes back from NetApp snapshots, with approvals.
- **Fabric Manager**: Cisco ACI static port bindings, product templates, vPCs, provisioning, reports and IP usage.
- **Web Terminal**: SSH terminals in the browser with access per host, recorded sessions and live watch / join.
- MIT license, screenshots in the README, tests on GitHub Actions.

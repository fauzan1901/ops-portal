# Dump ACI Access Policies (read-only)

Reads the **Fabric → Access Policies** configuration of each site (DCB, DCA, DCC) for the design of interface,
port-channel, and vPC automation ([docs/ADR-004-aci-access-policies.md](../../docs/ADR-004-aci-access-policies.md)). It contains
leaf profiles, interface profiles, selectors and port blocks, policy groups (access / PC / vPC), AAEP, domains and
VLAN pools, interface policies (link level, LACP, CDP, LLDP, MCP), vPC pairs, the status of every port, port-channels,
LLDP/CDP neighbours, and EPG static bindings.

**Changes nothing.** Only `GET` is sent to APIC, plus `aaaLogin` / `aaaLogout` for sign-in and
sign-out. The script rejects other methods. The password is not written to disk and does not appear on the command line.

## Steps

1. On the Mac (the bastion SSH password is typed once):

   ```bash
   bash tools/aci-access-dump/transfer.sh push
   ```

2. On the bastion, with the portal APIC service account (`apic:<site>` in Administration → Credentials):

   ```bash
   sudo bash ~/aci-access-dump/aci-access-dump.sh
   ```

   One site only: `sudo bash ~/aci-access-dump/aci-access-dump.sh DCB`. The credentials are read as user
   `opsportal`, so the portal database is not opened by root. With your own APIC account (read-only is enough):
   `python3 ~/aci-access-dump/aci_access_dump.py --site DCB --user <account>` (the password is asked).

3. On the Mac, fetch the result:

   ```bash
   bash tools/aci-access-dump/transfer.sh fetch
   ```

   The result is in `aci-access-dump-results/<time>/<site>-<time>/`.

## Result contents

| File | Contents |
|---|---|
| `summary.md` | Summary: APIC version, leaves and vPC pairs, leaf profile → interface profile, policy group naming patterns with the AAEP / link level / LACP that are usually used, AAEP → domain → VLAN pool, interface policies, free ports per leaf, findings (overlapping selectors, selectors without a policy group, and similar) |
| `ports.csv` | Every port of every leaf: status, selector, policy group, AAEP, port-channel, path, number of EPG bindings, neighbour |
| `policy_groups.csv` | Every policy group with all its relations and the ports that use it |
| `selectors.csv` | Every selector: interface profile, leaf, port, policy group |
| `raw/<class>.json` | All objects of every class as they are in APIC |

The result contains internal infrastructure data. Do not upload it to a public place.

## Local test (mock APIC)

```bash
portal/.venv/bin/python -m unittest discover -s tools/aci-access-dump -v
```

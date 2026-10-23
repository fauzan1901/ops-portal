#!/usr/bin/env bash
# Read-only dump of the ACI access policies of each site (leaf / interface profiles, selectors, policy groups, AAEPs,
# VLAN pools, interface policies, ports with state, port-channels, LLDP/CDP neighbours, static port bindings), with
# the APIC service account of the portal (Administration -> Credentials, apic:<site>). Only GET requests to APIC
# (plus sign-in / sign-out): nothing changes on APIC or in the portal.
# Run on the bastion:  sudo bash ~/aci-access-dump/aci-access-dump.sh          # DCB, DCA and DCC
#                      sudo bash ~/aci-access-dump/aci-access-dump.sh DCB
# Result: ~/aci-access-dump/out/<site>-<time>/summary.md (+ ports.csv, policy_groups.csv, selectors.csv, raw/*.json)
# and ~/aci-access-dump/out.tar.gz with all of it, to fetch with tools/aci-access-dump/transfer.sh fetch.
set -uo pipefail
cd "$(dirname "$0")"
HERE="$PWD"
SVC=opsportal
APP=/opt/ops-portal
PY="$APP/.venv/bin/python"
ENV_FILE=/etc/ops-portal/ops-portal.env
OWNER="${SUDO_USER:-$(id -un)}"
[ "$(id -u)" = 0 ] || { echo "Run with sudo: the portal's service account is read as the user $SVC." >&2; exit 1; }
[ -x "$PY" ] && [ -f "$ENV_FILE" ] || { echo "Ops Portal not found ($PY, $ENV_FILE)." >&2; exit 1; }
SITES=("$@")
[ ${#SITES[@]} -gt 0 ] || SITES=(DCB DCA DCC)
mapfile -t PORTAL_ENV < <(grep -E '^PORTAL_[A-Z_]+=' "$ENV_FILE")
mkdir -p "$HERE/out"

for SITE in "${SITES[@]}"; do
  # Host and service account from the portal, read as the portal's own user (stdin: its home may not be readable).
  if ! cred="$(cd / && sudo -u "$SVC" env "${PORTAL_ENV[@]}" "$PY" -I - "$APP" "$SITE" < "$HERE/portal_credential.py")"; then
    echo "== $SITE: skipped (no APIC service account in the portal)" >&2
    continue
  fi
  { read -r APIC_HOST; read -r APIC_USER; read -r APIC_PASSWORD; } < <(printf '%s' "$cred" \
    | "$PY" -I -c 'import json, sys; d = json.load(sys.stdin); print(d["host"]); print(d["username"]); print(d["password"])')
  unset cred
  export APIC_HOST APIC_USER APIC_PASSWORD   # in the environment, never on a command line
  "$PY" -I "$HERE/aci_access_dump.py" --site "$SITE" --out "$HERE/out" >/dev/null || echo "== $SITE: dump failed" >&2
  unset APIC_PASSWORD
done

tar -czf "$HERE/out.tar.gz" -C "$HERE/out" .
chown -R "$OWNER" "$HERE/out" "$HERE/out.tar.gz"
echo "Done: $HERE/out/<site>-<time>/summary.md, everything in $HERE/out.tar.gz ($(du -h "$HERE/out.tar.gz" | cut -f1))."

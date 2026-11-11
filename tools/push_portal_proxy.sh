#!/usr/bin/env bash
# Runs on this Mac: copies bastion/portal-proxy (PortalProxy.cs, install-portal-proxy.ps1, README.md) to the bastion,
# to ~/portal-proxy in WSL and to C:\Users\Administrator\Desktop\PortalProxy. Nothing is installed or restarted: an
# administrator runs install-portal-proxy.ps1 on the bastion afterwards. You type the SSH password; nothing is stored.
set -euo pipefail
ACI="$(cd "$(dirname "$0")/.." && pwd)"
. "$ACI/tools/bastion_ssh.sh"
bastion_connect 600
"${SSH[@]}" 'mkdir -p ~/portal-proxy'
for f in PortalProxy.cs install-portal-proxy.ps1 README.md; do
  "${SSH[@]}" "cat > ~/portal-proxy/$f" < "$ACI/bastion/portal-proxy/$f"
done
"${SSH[@]}" 'desk=/mnt/c/Users/Administrator/Desktop/PortalProxy
mkdir -p "$desk" && cp ~/portal-proxy/* "$desk/"
echo "Copied to C:\Users\Administrator\Desktop\PortalProxy ($(grep -m1 -o "Version = \"[0-9.]*\"" "$desk/PortalProxy.cs"))"'
echo 'Next, on the bastion (PowerShell as Administrator):'
echo '  cd C:\Users\Administrator\Desktop\PortalProxy'
echo '  powershell -ExecutionPolicy Bypass -File .\install-portal-proxy.ps1'

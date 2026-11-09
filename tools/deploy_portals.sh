#!/usr/bin/env bash
# Runs on this Mac: builds the deploy packages of both portals, copies them with update_portals.sh and the PortalProxy
# files (bastion/portal-proxy) to the bastion, and runs the update there. You type the SSH password once and the sudo
# password when asked; nothing is stored.
#   bash tools/deploy_portals.sh                 # both portals
#   bash tools/deploy_portals.sh aci_webui       # one of them
set -euo pipefail
ACI="$(cd "$(dirname "$0")/.." && pwd)"
SSH=(ssh -o ControlMaster=auto -o ControlPath=/tmp/aci-cm-%C -o ControlPersist=1800 -p 2222 deploy@172.26.0.100)
apps=("$@")
if [ ${#apps[@]} -eq 0 ]; then apps=(aci_webui ontap_restore); fi

python3 "$ACI/tools/build_zips.py" "${apps[@]}"
"${SSH[@]}" true
for app in "${apps[@]}"; do
  zip="$ACI/${app}_deploy.zip"
  sum="$(shasum -a 256 "$zip" | cut -d' ' -f1)"
  echo "== Upload ${app}_deploy.zip ($(du -h "$zip" | cut -f1 | tr -d ' '))"
  "${SSH[@]}" "cat > ~/${app}_deploy.zip" < "$zip"
  "${SSH[@]}" "cd ~ && echo '$sum  ${app}_deploy.zip' | sha256sum -c --quiet -" && echo "   checksum OK"
done
"${SSH[@]}" 'cat > ~/update_portals.sh' < "$ACI/tools/update_portals.sh"
"${SSH[@]}" 'mkdir -p ~/portal-proxy && rm -f ~/portal-proxy/*'
for f in PortalProxy.cs install-portal-proxy.ps1 README.md; do
  "${SSH[@]}" "cat > ~/portal-proxy/$f" < "$ACI/bastion/portal-proxy/$f"
done
echo
"${SSH[@]}" -t "bash ~/update_portals.sh ${apps[*]}"

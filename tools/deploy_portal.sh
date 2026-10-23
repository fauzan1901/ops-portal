#!/usr/bin/env bash
# Runs on this Mac: builds portal_deploy.zip, copies it to the bastion and unpacks it in ~/portal-deploy/<time>/portal.
# You type the SSH password once (or an open connection is reused); nothing is stored. Then on the bastion:
#   first time (ACI Web UI + ONTAP Restore -> one portal):  sudo bash ~/portal-deploy/<time>/portal/deploy/cutover.sh
#   updates afterwards:                                      sudo bash ~/portal-deploy/<time>/portal/deploy/install.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SSH=(ssh -o ControlMaster=auto -o ControlPath=/tmp/aci-cm-%C -o ControlPersist=1800 -p 2222 deploy@172.26.0.100)
stamp="$(date +%Y%m%d-%H%M%S)"

python3 "$ROOT/tools/build_zips.py" portal
zip="$ROOT/portal_deploy.zip"
sum="$(shasum -a 256 "$zip" | cut -d' ' -f1)"
"${SSH[@]}" true
echo "== Upload portal_deploy.zip ($(du -h "$zip" | cut -f1 | tr -d ' '))"
"${SSH[@]}" "mkdir -p ~/portal-deploy/$stamp && cat > ~/portal-deploy/$stamp/portal_deploy.zip" < "$zip"
"${SSH[@]}" "cd ~/portal-deploy/$stamp && echo '$sum  portal_deploy.zip' | sha256sum -c --quiet - && python3 -m zipfile -e portal_deploy.zip . \
  && find portal -name '*.sh' -exec sed -i 's/\r\$//' {} + && echo '   checksum OK, unpacked in ~/portal-deploy/$stamp/portal'"
echo "$stamp"

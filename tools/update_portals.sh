#!/usr/bin/env bash
# Runs on the bastion (WSL, as deploy): updates the portals from the packages that tools/deploy_portals.sh uploaded.
#   1/5 no ACI change, restore or deletion is running   2/5 database backups   3/5 install.sh of each portal
#       (ONTAP Restore: site settings of this environment added to sites.yml when missing, see deploy/site-settings.py)
#   4/5 checks   5/5 PortalProxy files to the Windows desktop (an administrator installs it there, see its README)
# Usage: bash ~/update_portals.sh [aci_webui] [ontap_restore]
set -euo pipefail
apps=("$@")
if [ ${#apps[@]} -eq 0 ]; then apps=(aci_webui ontap_restore); fi
stamp="$(date +%Y%m%d-%H%M%S)"
work="$HOME/portal-deploy/$stamp"
declare -A HOST=([aci_webui]=aci.example.internal [ontap_restore]=restore.example.internal)
declare -A PORT=([aci_webui]=8080 [ontap_restore]=8081)
declare -A SERVICE=([aci_webui]=aci-webui [ontap_restore]=ontap-restore)
declare -A DB=([aci_webui]=/var/lib/aci_webui/audit.db [ontap_restore]=/var/lib/ontap_restore/restore.db)
for app in "${apps[@]}"; do
  [ -n "${HOST[$app]+x}" ] || { echo "Unknown portal: $app (aci_webui or ontap_restore)" >&2; exit 1; }
  [ -f "$HOME/${app}_deploy.zip" ] || { echo "$HOME/${app}_deploy.zip is missing" >&2; exit 1; }
done

echo "== 1/5 Work in progress"
sudo -v
for app in "${apps[@]}"; do
  if [ "$app" = aci_webui ]; then
    # A change being sent to APIC right now (pending for less than 10 minutes; older ones are left-overs).
    n="$(sudo python3 -c '
import datetime, sqlite3
db = sqlite3.connect("file:/var/lib/aci_webui/audit.db?mode=ro", uri=True)
now = datetime.datetime.now().astimezone()
recent = 0
for (ts,) in db.execute("SELECT ts FROM audit WHERE status = ?", ("pending",)):
    t = datetime.datetime.fromisoformat(ts)
    t = t if t.tzinfo else t.astimezone()
    recent += (now - t).total_seconds() < 600
print(recent)')"
    if [ "$n" != 0 ]; then echo "   An ACI change is being sent to APIC right now. Try again in a minute." >&2; exit 1; fi
    echo "   ACI Web UI: no change being sent to APIC"
  else
    n="$(sudo sqlite3 -readonly "${DB[$app]}" "SELECT (SELECT COUNT(*) FROM restores WHERE status='running')
                                                     + (SELECT COUNT(*) FROM deletions WHERE status='deleting')")"
    if [ "$n" != 0 ]; then
      echo "   ONTAP Restore: $n restore or deletion job(s) running. Wait until they finish (Jobs, Approvals), then run again." >&2
      exit 1
    fi
    echo "   ONTAP Restore: no restore or deletion running"
  fi
done

echo
echo "== 2/5 Database backups"
for app in "${apps[@]}"; do
  sudo sqlite3 "${DB[$app]}" ".backup '${DB[$app]}.bak-$stamp'"
  echo "   ${DB[$app]}.bak-$stamp"
done

echo
echo "== 3/5 Install"
mkdir -p "$work"
for app in "${apps[@]}"; do
  python3 -m zipfile -e "$HOME/${app}_deploy.zip" "$work"
  echo "---------- $app ----------"
  sudo WEB_TLS=1 WEB_HOSTNAME="${HOST[$app]}" bash "$work/$app/deploy/install.sh"
  if [ "$app" = ontap_restore ]; then
    # DCA: Cinder overcommits 2:1 (DCB and DCC 1:1, the default); premium and standard are old types there.
    echo "==> Site settings in /etc/ontap_restore/sites.yml (added only when missing)"
    sudo /opt/ontap_restore/.venv/bin/python "$work/ontap_restore/deploy/site-settings.py" /etc/ontap_restore/sites.yml \
      DCA overcommit_ratio=2 "hidden_volume_types=[premium, standard]"
  fi
done
# Keep the last three unpacked versions.
ls -1d "$HOME"/portal-deploy/*/ 2>/dev/null | sort | head -n -3 | xargs -r rm -rf

echo
echo "== 4/5 Checks"
session_client() {   # "client" of /api/session: the address the portal sees for this request
  python3 -c 'import json, sys
try: print(json.load(sys.stdin).get("client", "missing (old version)"))
except Exception: print("no answer")'
}
for app in "${apps[@]}"; do
  host="${HOST[$app]}"; port="${PORT[$app]}"; proxy=$((port + 20000))
  code="$(curl -sk --noproxy '*' -o /dev/null -w '%{http_code}' "https://$host:$port/healthz" || true)"
  printf '   %-66s %s\n' "https://$host:$port/healthz" "$code"
  printf '   %-66s %s\n' "service ${SERVICE[$app]}" "$(systemctl is-active "${SERVICE[$app]}" || true)"
  printf '   %-66s %s\n' "client address, direct to nginx (127.0.0.1 expected)" \
    "$(curl -sk --noproxy '*' "https://127.0.0.1:$port/api/session" | session_client)"
  printf '   %-66s %s\n' "PROXY protocol port 127.0.0.1:$proxy for PortalProxy (127.0.0.1 expected)" \
    "$(curl -sk --noproxy '*' --haproxy-protocol "https://127.0.0.1:$proxy/api/session" | session_client)"
done
if [[ " ${apps[*]} " == *" aci_webui "* ]] && ! sudo cmp -s "$work/aci_webui/product_templates.json" /etc/aci_webui/product_templates.json; then
  echo "   Note: /etc/aci_webui/product_templates.json differs from the package (it is not changed by this update)."
fi

echo
echo "== 5/5 PortalProxy for Windows (real client address in the logs)"
desk=/mnt/c/Users/Administrator/Desktop
if [ -d "$desk" ] && mkdir -p "$desk/PortalProxy" 2>/dev/null && cp "$HOME"/portal-proxy/* "$desk/PortalProxy/" 2>/dev/null; then
  echo '   Copied to C:\Users\Administrator\Desktop\PortalProxy'
  echo '   Install it on the bastion (Remote Desktop, PowerShell as Administrator):'
  echo '     cd C:\Users\Administrator\Desktop\PortalProxy'
  echo '     powershell -ExecutionPolicy Bypass -File .\install-portal-proxy.ps1'
else
  echo "   $desk is not reachable from WSL: copy ~/portal-proxy to the bastion, then run install-portal-proxy.ps1 there."
fi
echo
echo "Done. Open the portals and press Ctrl+F5 (an open tab offers to reload when it has the old version)."

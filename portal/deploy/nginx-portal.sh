#!/usr/bin/env bash
# nginx of the Ops Portal (run with sudo): HTTPS on WEB_PORT (+ PROXY protocol on WEB_PORT+20000 for the bastion's
# PortalProxy) and the old ONTAP Restore port OLD_ONTAP_PORT redirected to the portal. Sites of other applications that
# use these ports (aci-webui, ontap-restore) are disabled; their files stay in sites-available. When nginx refuses the
# new configuration, the previous one is put back.
set -euo pipefail
APP_DIR=/opt/ops-portal
ENV_FILE=/etc/ops-portal/ops-portal.env
APP_PORT=18090
env_value() { grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- | tr -d '" ' || true; }
WEB_PORT="$(env_value WEB_PORT)"; WEB_PORT="${WEB_PORT:-8080}"
OLD_PORT="$(env_value OLD_ONTAP_PORT)"
NAME="$(env_value WEB_HOSTNAME)"
PROXY_PORT=$((WEB_PORT + 20000))
avail=/etc/nginx/sites-available; enabled=/etc/nginx/sites-enabled
echo "==> nginx: portal on $WEB_PORT (PROXY $PROXY_PORT)${OLD_PORT:+, old ONTAP port $OLD_PORT -> portal}"
backup="$(mktemp -d)"
cp -a "$enabled/." "$backup/" 2>/dev/null || true
cp -a "$avail/ops-portal" "$avail/ops-portal-oldport" "$backup/" 2>/dev/null || true
canonical=""
if [ -n "$NAME" ]; then
  canonical="        if (\$host != \"$NAME\") { return 301 https://$NAME:$WEB_PORT\$request_uri; }"
fi
sed "s/__WEB_PORT__/$WEB_PORT/g; s/__PROXY_PORT__/$PROXY_PORT/g; s/__APP_PORT__/$APP_PORT/g" "$APP_DIR/deploy/nginx-ops-portal.conf" \
  | awk -v c="$canonical" '{ if ($0 == "__CANONICAL__") print c; else print }' > "$avail/ops-portal"
ln -sf "$avail/ops-portal" "$enabled/ops-portal"
if [ -n "$OLD_PORT" ]; then
  target="${NAME:-\$host}:$WEB_PORT"
  sed "s/__OLD_PORT__/$OLD_PORT/g; s/__OLD_PROXY_PORT__/$((OLD_PORT + 20000))/g; s|__TARGET__|$target|g" \
    "$APP_DIR/deploy/nginx-ops-portal-oldport.conf" > "$avail/ops-portal-oldport"
  ln -sf "$avail/ops-portal-oldport" "$enabled/ops-portal-oldport"
else
  rm -f "$enabled/ops-portal-oldport"
fi
# Other sites on the same ports are switched off (the portal takes over 8080 and 8081).
for site in "$enabled"/*; do
  name="$(basename "$site")"
  case "$name" in ops-portal|ops-portal-oldport) continue ;; esac
  for port in "$WEB_PORT" "$PROXY_PORT" ${OLD_PORT:+"$OLD_PORT" "$((OLD_PORT + 20000))"}; do
    if grep -Eq "listen[^;]*[: ]$port[ ;]" "$site" 2>/dev/null; then
      rm -f "$site"; echo "   disabled site $name (it used port $port; the file stays in $avail)"; break
    fi
  done
done
rm -f "$enabled/default"
if ! nginx -t 2>/tmp/nginx-portal-test.log; then
  cat /tmp/nginx-portal-test.log >&2
  rm -f "$enabled"/*; cp -a "$backup/." "$enabled/" 2>/dev/null || true
  echo "nginx refused the configuration: the previous sites are back, nothing changed." >&2
  rm -rf "$backup"; exit 1
fi
rm -rf "$backup"
systemctl reload nginx 2>/dev/null || systemctl restart nginx
echo "   nginx reloaded. Sites: $(ls "$enabled" | tr '\n' ' ')"

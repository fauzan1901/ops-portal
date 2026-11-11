#!/usr/bin/env bash
# nginx of the Ops Portal (run with sudo): HTTPS on WEB_PORT (+ PROXY protocol on WEB_PORT+20000 for the bastion's
# PortalProxy) and the old Snapshot Restore port OLD_ONTAP_PORT redirected to the portal. Only the sites of the applications
# the portal replaced (fabric-ui, snapshot-restore) are disabled when they use these ports; their files stay in
# sites-available. A site of another team (e.g. otherapp = another team's app on 8482, which also takes 127.0.0.1:28081) is never
# disabled: when it uses the old ONTAP port or its PROXY port, the portal leaves that port to it and installs no
# redirect there; when it uses the portal's own ports, it stays and nginx -t decides. Only the stock "default" link is
# removed. When nginx refuses the new configuration, the previous one is put back.
set -euo pipefail
APP_DIR=/opt/ops-portal
ENV_FILE=/etc/ops-portal/ops-portal.env
APP_PORT=18400
env_value() { grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- | tr -d '" ' || true; }
WEB_PORT="$(env_value WEB_PORT)"; WEB_PORT="${WEB_PORT:-8480}"
OLD_PORT="$(env_value OLD_ONTAP_PORT)"
NAME="$(env_value WEB_HOSTNAME)"
PROXY_PORT=$((WEB_PORT + 20000))
avail=/etc/nginx/sites-available; enabled=/etc/nginx/sites-enabled
backup="$(mktemp -d)"
cp -a "$enabled/." "$backup/" 2>/dev/null || true
cp -a "$avail/ops-portal" "$avail/ops-portal-oldport" "$backup/" 2>/dev/null || true
LEGACY="fabric-ui snapshot-restore"   # the applications the portal replaced (ADR-003)
ours() { case "$1" in ops-portal|ops-portal-oldport) return 0 ;; esac; return 1; }
legacy() { local l; for l in $LEGACY; do [ "$1" = "$l" ] && return 0; done; return 1; }
uses() {   # does the site file $1 listen on port $2 (comment lines left out)
  grep -v '^[[:space:]]*#' "$1" 2>/dev/null | grep -Eq "(^|[;{[:space:]])listen[^;]*[: ]$2[ ;]"
}
other_sites() {   # enabled sites that are neither the portal's nor of the replaced applications
  local site name
  for site in "$enabled"/*; do
    [ -e "$site" ] || continue
    name="$(basename "$site")"
    ours "$name" || legacy "$name" || echo "$site"
  done
}
if [ -n "$OLD_PORT" ]; then   # the old ONTAP port belongs to another team's site: leave it to that site
  while IFS= read -r site; do
    [ -n "$site" ] || continue
    if uses "$site" "$OLD_PORT" || uses "$site" "$((OLD_PORT + 20000))"; then
      echo "   site $(basename "$site") (another application) uses port $OLD_PORT or $((OLD_PORT + 20000)): left as it is, the old ONTAP port is not redirected"
      OLD_PORT=""
      break
    fi
  done < <(other_sites)
fi
echo "==> nginx: portal on $WEB_PORT (PROXY $PROXY_PORT)${OLD_PORT:+, old ONTAP port $OLD_PORT -> portal}"
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
# The replaced applications on the same ports are switched off; a site of another team is never touched.
for site in "$enabled"/*; do
  [ -e "$site" ] || [ -L "$site" ] || continue
  name="$(basename "$site")"
  ours "$name" && continue
  for port in "$WEB_PORT" "$PROXY_PORT" ${OLD_PORT:+"$OLD_PORT" "$((OLD_PORT + 20000))"}; do
    if uses "$site" "$port"; then
      if legacy "$name"; then
        rm -f "$site"; echo "   disabled site $name (it used port $port; the file stays in $avail)"
      else
        echo "   WARNING: site $name (another application) also listens on port $port: left as it is" >&2
      fi
      break
    fi
  done
done
# only the stock default site (a link to sites-available/default), never a file someone wrote there
if [ -L "$enabled/default" ] && [ "$(readlink -f "$enabled/default")" = "$(readlink -f "$avail/default" 2>/dev/null)" ]; then
  rm -f "$enabled/default"
fi
if ! nginx -t 2>/tmp/nginx-portal-test.log; then
  cat /tmp/nginx-portal-test.log >&2
  rm -f "$enabled"/*; cp -a "$backup/." "$enabled/" 2>/dev/null || true
  echo "nginx refused the configuration: the previous sites are back, nothing changed." >&2
  rm -rf "$backup"; exit 1
fi
rm -rf "$backup"
systemctl reload nginx 2>/dev/null || systemctl restart nginx
echo "   nginx reloaded. Sites: $(ls "$enabled" | tr '\n' ' ')"

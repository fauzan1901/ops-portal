#!/usr/bin/env bash
# The one DNS name of the portal (run with sudo), e.g. after ops-portal.example.internal resolves to
# this server and its Duo redirect URLs are registered in Duo (Applications -> the portal's application):
#   https://<name>:8080/auth/sso/callback   and   https://<name>:8080/auth/duo/callback
#   sudo bash /opt/ops-portal/deploy/set-hostname.sh <name>
# Updates WEB_HOSTNAME, the Duo redirect URLs in auth.yml, nginx (other names and 8081 redirect to it) and, when the
# certificate does not cover the name, creates a new self-signed certificate.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo." >&2; exit 1; }
NAME="${1:-}"
[[ "$NAME" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || { echo "Usage: $0 <dns name>" >&2; exit 1; }
ETC=/etc/ops-portal
ENV_FILE=$ETC/ops-portal.env
PORT="$(grep -E '^WEB_PORT=' "$ENV_FILE" | tail -1 | cut -d= -f2)"; PORT="${PORT:-8080}"
getent hosts "$NAME" >/dev/null || echo "   Warning: $NAME does not resolve on this server yet."
cp -a "$ETC/auth.yml" "$ETC/auth.yml.bak-$(date +%Y%m%d-%H%M%S)"
if grep -qE '^WEB_HOSTNAME=' "$ENV_FILE"; then sed -i -E "s|^WEB_HOSTNAME=.*|WEB_HOSTNAME=$NAME|" "$ENV_FILE"; else echo "WEB_HOSTNAME=$NAME" >> "$ENV_FILE"; fi
/opt/ops-portal/.venv/bin/python - "$ETC/auth.yml" "https://$NAME:$PORT" <<'PY'
import re, sys
path, base = sys.argv[1], sys.argv[2]
section, out = "", []
for line in open(path, encoding="utf-8").read().splitlines():
    top = re.match(r"^([A-Za-z_]+):", line)
    if top:
        section = top.group(1)
    m = re.match(r"^(\s+redirect_uri:\s*)", line)
    if m and section in ("sso", "duo"):
        line = f'{m.group(1)}"{base}/auth/{section}/callback"'
        print(f"   {section}.redirect_uri = {base}/auth/{section}/callback")
    out.append(line)
open(path, "w", encoding="utf-8").write("\n".join(out) + "\n")
PY
if ! openssl x509 -in "$ETC/tls/server.crt" -noout -ext subjectAltName 2>/dev/null | grep -q "DNS:$NAME"; then
  sans="$(openssl x509 -in "$ETC/tls/server.crt" -noout -ext subjectAltName | tail -1 | tr -d ' ' | sed 's/IPAddress/IP/g')"
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=$NAME" -addext "subjectAltName=$sans,DNS:$NAME" \
    -keyout "$ETC/tls/server.key" -out "$ETC/tls/server.crt" 2>/dev/null
  chmod 600 "$ETC/tls/server.key"
  echo "   New self-signed certificate including $NAME"
fi
bash /opt/ops-portal/deploy/nginx-portal.sh
echo "Done: https://$NAME:$PORT (auth.yml changes apply without a restart)."

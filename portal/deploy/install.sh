#!/usr/bin/env bash
# Install or update the Ops Portal on Ubuntu (26.04 LTS, including WSL). Run from the portal folder:
#   sudo WEB_HOSTNAME=<dns name> bash deploy/install.sh
# Python libraries ship with the package (wheels/), so the install needs no internet (apt only when Ubuntu packages are
# missing). Safe to re-run for updates: the code is replaced, configuration (/etc/ops-portal: sites.yml, auth.yml,
# credentials.key, SSH keys, certificate) and data (/var/lib/ops-portal) are kept.
# Variables: WEB_HOSTNAME (the one name of the portal), WEB_ALT_NAMES (more names in the certificate, comma separated),
#            WI_SSH_PROXY (web proxy host:port for SSH to public addresses, see ops-portal.env),
#            SKIP_NGINX=1 (code and service only; deploy/nginx-portal.sh switches nginx later).
set -euo pipefail

APP_DIR=/opt/ops-portal
DATA_DIR=/var/lib/ops-portal
CONF_DIR=/etc/ops-portal
ENV_FILE=$CONF_DIR/ops-portal.env
APP_USER=opsportal
APP_PORT=18090
SRC="$(cd "$(dirname "$0")/.." && pwd)"

step() { printf '\n==> %s\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { echo "Run with sudo: sudo bash deploy/install.sh" >&2; exit 1; }
[ -f "$SRC/app.py" ] && [ -d "$SRC/modules" ] || { echo "app.py not found in $SRC; run from the portal folder." >&2; exit 1; }
if [ "$(ps -p 1 -o comm= 2>/dev/null)" != "systemd" ]; then
  echo "systemd is not running, but the ops-portal service needs it (WSL: [boot] systemd=true in /etc/wsl.conf)." >&2
  exit 1
fi

step "System packages"
missing=()
for pkg in python3 python3-venv nginx sqlite3 curl openssh-client openssl rsync; do
  [[ "$(dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null)" == *" ok installed" ]] || missing+=("$pkg")
done
if [ ${#missing[@]} -gt 0 ]; then
  apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing[@]}" >/dev/null
else
  echo "   All packages are already installed."
fi
# sshpass: SSH hosts (and jump hosts) with password sign-in on Hosts & SSH. Optional: keys work without it.
if [[ "$(dpkg-query -W -f='${Status}' sshpass 2>/dev/null)" != *" ok installed" ]]; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sshpass >/dev/null 2>&1 \
    || echo "   Warning: sshpass could not be installed: hosts with password sign-in will not connect (keys work)."
fi
python3 -c 'import sys; assert sys.version_info >= (3, 12), sys.version' || { echo "ansible-core needs Python 3.12 or newer." >&2; exit 1; }

step "Service user and folders"
id "$APP_USER" >/dev/null 2>&1 || useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$APP_USER"
install -d -o "$APP_USER" -g "$APP_USER" -m 750 "$DATA_DIR" "$DATA_DIR/backup"
install -d -o "$APP_USER" -g "$APP_USER" -m 700 "$DATA_DIR/.ssh"
install -d -m 755 "$CONF_DIR"
install -d -o root -g "$APP_USER" -m 750 "$CONF_DIR/keys"
install -d -m 700 "$CONF_DIR/tls"

step "Application code to $APP_DIR"
install -d -m 755 "$APP_DIR"
rsync -a --delete --exclude '.venv/' --exclude '__pycache__/' --exclude 'data/' --exclude '*.db*' \
  --exclude 'sites.yml' --exclude 'auth.yml' --exclude 'credentials.key' "$SRC/" "$APP_DIR/"
find "$APP_DIR" -path "$APP_DIR/.venv" -prune -o -type d -exec chmod 755 {} + -o -type f -exec chmod 644 {} +
find "$APP_DIR/deploy" -type f -exec sed -i 's/\r$//' {} +
chmod 755 "$APP_DIR"/deploy/*.sh "$APP_DIR"/deploy/*.py "$APP_DIR"/*.sh
chown -R root:root "$APP_DIR"

step "Python venv (Flask, ansible-core, pyVmomi) from wheels/"
python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install -q --disable-pip-version-check --no-index --find-links "$APP_DIR/wheels" -r "$APP_DIR/requirements.txt" \
  || { echo "Install from wheels/ failed (no wheels for this Python $(python3 -V)?)." >&2; exit 1; }
echo "   $("$APP_DIR/.venv/bin/ansible-playbook" --version | head -1)"

step "Configuration (existing files are not overwritten)"
save_env() { if grep -qE "^$1=" "$ENV_FILE"; then sed -i -E "s|^$1=.*|$1=$2|" "$ENV_FILE"; else printf '%s=%s\n' "$1" "$2" >> "$ENV_FILE"; fi; }
[ -f "$ENV_FILE" ] || { install -m 640 -o root -g "$APP_USER" "$APP_DIR/deploy/ops-portal.env" "$ENV_FILE"; echo "   Created: $ENV_FILE"; }
if [ -n "${WEB_HOSTNAME:-}" ]; then
  [[ "$WEB_HOSTNAME" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || { echo "Invalid WEB_HOSTNAME: $WEB_HOSTNAME" >&2; exit 1; }
  save_env WEB_HOSTNAME "$WEB_HOSTNAME"
fi
if [ -n "${WI_SSH_PROXY+x}" ]; then   # set (also to empty) on the command line: sudo WI_SSH_PROXY=172.26.0.242:3128 bash ...
  [[ -z "$WI_SSH_PROXY" || "$WI_SSH_PROXY" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*:[0-9]{1,5}$ ]] || { echo "Invalid WI_SSH_PROXY: $WI_SSH_PROXY (host:port)" >&2; exit 1; }
  save_env WI_SSH_PROXY "$WI_SSH_PROXY"
fi
for f in sites auth; do
  if [ ! -f "$CONF_DIR/$f.yml" ]; then
    install -m 640 -o root -g "$APP_USER" "$APP_DIR/$f.example.yml" "$CONF_DIR/$f.yml"
    echo "   Created: $CONF_DIR/$f.yml  <- fill it in"
  fi
done
[ -f "$CONF_DIR/product_templates.json" ] || install -m 644 "$APP_DIR/modules/aci/product_templates.json" "$CONF_DIR/product_templates.json"
if [ ! -s "$CONF_DIR/credentials.key" ]; then
  (umask 077 && "$APP_DIR/.venv/bin/python" -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())' > "$CONF_DIR/credentials.key.new")
  mv -f "$CONF_DIR/credentials.key.new" "$CONF_DIR/credentials.key"
  echo "   Created: $CONF_DIR/credentials.key  (keep a copy in a safe place: database backups need it)"
fi
sed -i 's/\r$//' "$ENV_FILE" "$CONF_DIR/sites.yml" "$CONF_DIR/auth.yml"
chown root:"$APP_USER" "$ENV_FILE" "$CONF_DIR/sites.yml" "$CONF_DIR/auth.yml" "$CONF_DIR/credentials.key"
chmod 640 "$ENV_FILE" "$CONF_DIR/sites.yml" "$CONF_DIR/auth.yml" "$CONF_DIR/credentials.key"
find "$CONF_DIR/keys" -type f -exec chown root:"$APP_USER" {} + -exec chmod 640 {} +

env_value() { grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- | tr -d '" ' || true; }
WEB_HOSTNAME="$(env_value WEB_HOSTNAME)"
if [ ! -f "$CONF_DIR/tls/server.crt" ]; then
  step "TLS certificate (self-signed)"
  host="$(hostname)"; ip="$(hostname -I | awk '{print $1}')"
  san="DNS:$host,DNS:localhost,IP:127.0.0.1${ip:+,IP:$ip}"
  for n in $WEB_HOSTNAME ${WEB_ALT_NAMES//,/ }; do san="$san,DNS:$n"; done
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=${WEB_HOSTNAME:-$host}" -addext "subjectAltName=$san" \
    -keyout "$CONF_DIR/tls/server.key" -out "$CONF_DIR/tls/server.crt" 2>/dev/null
  chmod 600 "$CONF_DIR/tls/server.key"
  echo "   $san (valid 825 days)"
fi

step "systemd service"
install -m 644 "$APP_DIR/deploy/ops-portal.service" "$APP_DIR/deploy/ops-portal-backup.service" \
  "$APP_DIR/deploy/ops-portal-backup.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --quiet ops-portal.service ops-portal-backup.timer
systemctl restart ops-portal.service
systemctl start ops-portal-backup.timer

step "Application check (127.0.0.1:$APP_PORT)"
for _ in $(seq 1 30); do
  if curl -fs --noproxy '*' "http://127.0.0.1:$APP_PORT/healthz" >/dev/null 2>&1; then ok=1; break; fi
  sleep 1
done
if [ -z "${ok:-}" ]; then
  echo "The portal does not answer. Latest log:" >&2
  journalctl -u ops-portal -n 40 --no-pager >&2
  exit 1
fi
echo "   The portal is running."

if [ "${SKIP_NGINX:-0}" != 1 ]; then
  bash "$APP_DIR/deploy/nginx-portal.sh"
fi
echo
echo "Done. Log: journalctl -u ops-portal -f   |   Database: $DATA_DIR/portal.db   |   Settings: $CONF_DIR"

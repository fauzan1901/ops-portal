#!/usr/bin/env bash
# Local portal accounts (administrators that do not depend on Active Directory).
#   sudo /opt/ops-portal/deploy/local-admin.sh add <name> [--display-name "Full Name"] [--duo-user <Duo username>]
#   sudo /opt/ops-portal/deploy/local-admin.sh passwd <name>
#   sudo /opt/ops-portal/deploy/local-admin.sh list | enable <name> | disable <name> | remove <name>
#   sudo /opt/ops-portal/deploy/local-admin.sh duo <name> <Duo username, or - for password only>
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo." >&2; exit 1; }
APP_DIR=/opt/ops-portal
DB=/var/lib/ops-portal/portal.db
[ -f "$DB" ] || { echo "$DB does not exist yet: install the portal first." >&2; exit 1; }
action="${1:-list}"
shift || true
run() { sudo -u opsportal env PORTAL_ACTOR="${SUDO_USER:-root}" "$APP_DIR/.venv/bin/python" "$APP_DIR/portal_auth.py" local-user "$@" --db "$DB"; }
if [ "$action" = duo ]; then run duo "${1:-}" --duo-user "${2:--}"; else run "$action" "$@"; fi

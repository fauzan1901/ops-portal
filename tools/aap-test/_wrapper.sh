# Shared part of the aap-test scripts (sourced): the path of the Operation Automation portal to the DCB director
# (portal service account -> management host -> director). run_remote <script> sends a bash script to the director.
SITE=DCB
SVC=opsportal
PY=/opt/ops-portal/.venv/bin/python
read -r MGMT_HOST MGMT_PORT MGMT_USER MGMT_KEY DIR_HOST DIR_USER DIR_PORT RC < <("$PY" - "$SITE" <<'EOF'
import sys, yaml
c = yaml.safe_load(open("/etc/ops-portal/sites.yml"))["sites"][sys.argv[1]]
m, d = c.get("mgmt") or {}, c.get("director") or {}
print(m.get("host", "-"), m.get("port", 22), m.get("user") or "-", m.get("private_key") or "-",
      d.get("host", "-"), d.get("user") or "stack", d.get("port", 22), d.get("overcloudrc") or "~/overcloudrc")
EOF
)
OPTS=(-o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=30 -p "$MGMT_PORT")
[ "$MGMT_KEY" != "-" ] && OPTS+=(-i "$MGMT_KEY")
TARGET="$MGMT_HOST"
[ "$MGMT_USER" != "-" ] && TARGET="$MGMT_USER@$MGMT_HOST"

run_remote() {   # $1 = header (variables), $2 = script; output on stdout
  { printf '%s\n' "$1"; printf 'source %s >/dev/null 2>&1 || { echo "source overcloudrc failed"; exit 1; }\n' "$RC"; printf '%s\n' "$2"; } \
    | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
      "ssh -o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=30 -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 \
    | grep -v -E 'post-quantum|store now, decrypt later|may need to be upgraded'
}

# Common settings of the test (project 249-DEMO-ITSO-DCB, Public-Shared-04-2 11.6.215.0/24, vyos-1.3-base).
COMMON='PID=2cc6a304b62e4fbca365add264d73cf7
NET=eee48953-f6a7-427b-a177-b536c620d4e4
SUBNET=86fbd1f2-de50-490e-8447-c9c51cefa4ed
IMAGE=95001f3a-57b1-43a2-9dfe-baaa30672f8b
CLIENT_IMAGE=2591bc53-df34-4ab3-af41-409c7a716053
FLAVOR=c1.medium.rc
MGMT_SRC=11.7.90.251/32
fail() { echo "FAILED: $*"; exit 1; }
step() { echo; echo "== $*"; }
# Work as the admin account scoped to the test project (needs a role on it; checked first by aap-test-create).
scope() {
  export OS_PROJECT_ID="$PID"; unset OS_PROJECT_NAME OS_TENANT_NAME OS_PROJECT_DOMAIN_NAME OS_PROJECT_DOMAIN_ID
  openstack token issue -f value -c project_id 2>/dev/null | grep -q "$PID" || fail "no token for project $PID (does the admin account have a role on it?)"
}
ip_of() { openstack port show "$1" -f value -c fixed_ips | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | head -1; }'

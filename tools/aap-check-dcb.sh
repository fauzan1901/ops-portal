#!/usr/bin/env bash
# Read-only check for FortiGate HA with a VIP (allowed address pairs) on site DCB, project DEMO-ITSO-DCB.
# Same path as the Operation Automation portal: portal service account -> management host -> director -> overcloudrc.
# Only list / show commands. Run on the bastion:  sudo bash ~/aap-check.sh [project name or ID]
set -u
SITE=DCB
PROJECT="${1:-DEMO-ITSO-DCB}"
case "$PROJECT" in *[!A-Za-z0-9_.-]*) echo "Project: letters, digits, _ . - only"; exit 1;; esac
OUT="/home/deploy/aap-check-$(date +%Y%m%d-%H%M%S).txt"
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
OPTS=(-o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new -p "$MGMT_PORT")
[ "$MGMT_KEY" != "-" ] && OPTS+=(-i "$MGMT_KEY")
TARGET="$MGMT_HOST"
[ "$MGMT_USER" != "-" ] && TARGET="$MGMT_USER@$MGMT_HOST"
echo "Site $SITE: management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys are not printed)"

REMOTE=$(cat <<EOF
source $RC >/dev/null 2>&1 || { echo "source $RC failed"; exit 1; }
echo "== RHOSP release"; cat /etc/rhosp-release
echo "== Client"; openstack --version 2>&1
echo "== Neutron extensions (allowed address pairs, port security)"
openstack extension list --network -f value -c Alias | grep -E '^(allowed-address-pairs|port-security|extraroute|l3-ha|dvr)\$' | sort
echo "== Network backend (agent types)"; openstack network agent list -f value -c "Agent Type" | sort | uniq -c
echo "== Project"
PID=\$(openstack project list --long -f value -c ID -c Name | awk -v p='$PROJECT' 'tolower(\$2) == tolower(p) || \$1 == p {print \$1; exit}')
if [ -z "\$PID" ]; then
  echo "project $PROJECT not found; projects whose name contains ITSO or DEMO (all domains):"
  openstack project list --long -f value -c ID -c Name -c "Domain ID" -c Enabled | grep -i -E 'itso|demo'
  exit 0
fi
openstack project show "\$PID" -f value -c id -c name -c domain_id -c enabled
echo "== Servers"; openstack server list --project "\$PID" -f json
echo "== Networks"; openstack network list --project "\$PID" -f json
echo "== Subnets"; openstack subnet list --project "\$PID" -f json
echo "== Routers"; openstack router list --project "\$PID" -f json
echo "== Ports (fixed IPs, MAC, allowed address pairs, port security, security groups)"
for p in \$(openstack port list --project "\$PID" -f value -c ID); do
  openstack port show "\$p" -f json -c id -c name -c status -c device_owner -c device_id -c network_id -c fixed_ips -c mac_address -c allowed_address_pairs -c port_security_enabled -c security_group_ids -c binding_host_id
done
echo "== Security groups"; openstack security group list --project "\$PID" -f json
for g in \$(openstack security group list --project "\$PID" -f value -c ID); do
  echo "-- rules of \$g"; openstack security group rule list "\$g" --long -f json
done
echo "== Floating IPs"; openstack floating ip list --project "\$PID" -f json
echo "== Quota"; openstack quota show "\$PID" -f json
EOF
)

{
  echo "Read-only check, $(date -Is), site $SITE, project $PROJECT"
  printf '%s\n' "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1
  echo "== exit $?"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

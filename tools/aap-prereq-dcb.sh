#!/usr/bin/env bash
# Read-only prerequisites of the allowed-address-pairs test (FortiGate HA VIP) on site DCB: external networks,
# images, flavors, quota of the project, how floating IPs are routed (distributed or centralized).
# Same path as the Operation Automation portal: portal service account -> management host -> director -> overcloudrc.
# Only list / show commands. Run on the bastion:  sudo bash ~/aap-check.sh [project name or ID]
set -u
SITE=DCB
PROJECT="${1:-249-DEMO-ITSO-DCB}"
case "$PROJECT" in *[!A-Za-z0-9_.-]*) echo "Project: letters, digits, _ . - only"; exit 1;; esac
OUT="/home/deploy/aap-prereq-$(date +%Y%m%d-%H%M%S).txt"
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
PID=\$(openstack project list -f value -c ID -c Name | awk -v p='$PROJECT' 'tolower(\$2) == tolower(p) || \$1 == p {print \$1; exit}')
echo "== Project \$PID"
echo "== External networks"; openstack network list --external -f value -c ID -c Name -c Subnets
for n in \$(openstack network list --external -f value -c ID); do
  openstack network show "\$n" -f value -c name -c shared -c provider:network_type -c provider:physical_network -c mtu
  openstack subnet list --network "\$n" -f value -c Name -c Subnet
done
echo "== Routers of the project with their external gateway"
for r in \$(openstack router list --project "\$PID" -f value -c ID); do
  openstack router show "\$r" -f value -c name -c external_gateway_info
done
echo "== Floating IPs of the project"; openstack floating ip list --project "\$PID" -f value -c "Floating IP Address" -c "Fixed IP Address" -c "Floating Network"
echo "== Images (active, public or of the project)"; openstack image list --status active -f value -c ID -c Name | grep -i -E 'vyos|pfsense|opnsense|forti|fgt|ubuntu|centos|rocky|alma|rhel|cirros|debian' | head -40
echo "== Flavors (small)"; openstack flavor list -f value -c Name -c VCPUs -c RAM -c Disk | awk '\$2 <= 2 && \$3 <= 4096' | head -20
echo "== Quota usage"; openstack limits show --absolute --project "\$PID" -f value | grep -E 'Instances|Cores|RAM|Volume|Gigabytes'
openstack quota show "\$PID" -f value -c floating-ips -c ports -c networks -c routers -c secgroups -c security-group-rules 2>/dev/null
echo "== Keypairs of the director user"; openstack keypair list -f value -c Name | head
echo "== Distributed floating IPs (deployment settings on the director)"
grep -rhoE '(NeutronEnableDVR|enable_distributed_floating_ip)[^,}]*' ~/templates ~/overcloud-deploy/*/tripleo-overcloud-*.yaml ~/*.yaml 2>/dev/null | sort -u | head -10
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

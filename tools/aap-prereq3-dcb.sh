#!/usr/bin/env bash
# Read-only prerequisites of the allowed-address-pairs test (FortiGate HA VIP) on site DCB: external networks,
# images, flavors, quota of the project, how floating IPs are routed (distributed or centralized).
# Same path as the Operation Automation portal: portal service account -> management host -> director -> overcloudrc.
# Only list / show commands. Run on the bastion:  sudo bash ~/aap-check.sh [project name or ID]
set -u
SITE=DCB
PROJECT="${1:-249-DEMO-ITSO-DCB}"
case "$PROJECT" in *[!A-Za-z0-9_.-]*) echo "Project: letters, digits, _ . - only"; exit 1;; esac
OUT="/home/deploy/aap-prereq3-$(date +%Y%m%d-%H%M%S).txt"
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
echo "== VyOS / pfSense images"
openstack image list --status active -f value -c ID -c Name | grep -i -E 'vyos|pfsense|opnsense|fortigate|fgt'
echo "== How the existing VyOS instance was built (image, flavor, key, volume)"
openstack server show d820ea18-496e-4d28-83bb-899ab2edb3ee -f json -c name -c image -c flavor -c key_name -c volumes_attached -c security_groups
for v in \$(openstack server show d820ea18-496e-4d28-83bb-899ab2edb3ee -f json -c volumes_attached | grep -oE '[0-9a-f]{8}-[0-9a-f-]{27}' | head -1); do
  openstack volume show "\$v" -f json -c size -c volume_type -c volume_image_metadata | grep -E '"size"|volume_type|image_name|image_id|"hw_|os_'
done
echo "== Flavors (name ram disk vcpus) of the c1 / m1 / e1 families up to 4 GB"
openstack flavor list -f value -c Name -c RAM -c Disk -c VCPUs | awk '\$2 <= 4096' | grep -E '^(c1|m1|e1)\.' | head -20
echo "== Public-Shared-04 subnets (gateway, pools, DHCP) and free addresses per subnet"
openstack subnet show 75745912-c74a-4cc6-ad2f-e244488c06bc -f value -c name -c cidr -c gateway_ip -c allocation_pools -c enable_dhcp
openstack subnet show 86fbd1f2-de50-490e-8447-c9c51cefa4ed -f value -c name -c cidr -c gateway_ip -c allocation_pools -c enable_dhcp
openstack ip availability show eee48953-f6a7-427b-a177-b536c620d4e4 -f json | grep -E '"(subnet_name|cidr|total_ips|used_ips)"'
echo "== done"
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

#!/usr/bin/env bash
# Read-only prerequisites of the allowed-address-pairs test (FortiGate HA VIP) on site DCB: external networks,
# images, flavors, quota of the project, how floating IPs are routed (distributed or centralized).
# Same path as the Operation Automation portal: portal service account -> management host -> director -> overcloudrc.
# Only list / show commands. Run on the bastion:  sudo bash ~/aap-check.sh [project name or ID]
set -u
SITE=DCB
PROJECT="${1:-249-DEMO-ITSO-DCB}"
case "$PROJECT" in *[!A-Za-z0-9_.-]*) echo "Project: letters, digits, _ . - only"; exit 1;; esac
OUT="/home/deploy/aap-prereq2-$(date +%Y%m%d-%H%M%S).txt"
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
PID=2cc6a304b62e4fbca365add264d73cf7
echo "== Images (VyOS, pfSense, FortiGate, Linux)"
openstack image list --status active -f value -c ID -c Name | grep -i -E 'vyos|pfsense|opnsense|forti|fgt|ubuntu|rocky|alma|centos|debian|cirros' | head -40
echo "== Flavors (up to 2 vCPU, 4 GB)"
openstack flavor list -f value -c Name -c VCPUs -c RAM -c Disk | awk '\$2 <= 2 && \$3 <= 4096' | head -20
echo "== Quota usage of the project"
openstack limits show --absolute --project "\$PID" -f value | grep -E 'Instances|Cores|RAM'
openstack quota show "\$PID" -f json | grep -E '"(floating-ips|floatingip|ports|port|networks|network|routers|router|instances|cores|ram)"'
echo "== Free addresses of the Public networks (total / used / free)"
openstack ip availability list --ip-version 4 -f value -c "Network ID" -c "Network Name" -c "Total IPs" -c "Used IPs" \
  | grep -i public | awk '{n=\$2; for (i=3; i<NF-1; i++) n=n" "\$i; print \$(NF-1), \$NF, \$(NF-1)-\$NF, n, \$1}' | sort -k3 -rn
echo "== Subnets of the Public networks (CIDR, gateway)"
openstack subnet list -f value -c Name -c Subnet -c Network | grep -E '31d8cf55-3bc0-4f83-870f-a41a7a6de761|38a3a8a8-e4a6-4ebd-a79b-b6b7d41cfeeb|eee48953-f6a7-427b-a177-b536c620d4e4|70598e56-6b08-41b0-ad4c-b098d099f0d0|6806d2df-7719-4711-aa3b-94fa4598ed4b|80eddead-6aa8-42b4-b006-d29870a15f94'
echo "== Distributed floating IPs (deployment settings on the director)"
grep -rhoE '(NeutronEnableDVR|enable_distributed_floating_ip)[^,}]*' ~/templates ~/overcloud-deploy/*/tripleo-overcloud-*.yaml ~/*.yaml 2>/dev/null | sort -u | head -10
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

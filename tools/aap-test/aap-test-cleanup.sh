#!/usr/bin/env bash
# Removes every object of the allowed address pairs test (aap-test-*) from project 249-DEMO-ITSO-DCB, removes the
# temporary role admin of the admin account on that project, and lists what is left. Run on the bastion: sudo bash ~/aap-test/aap-test-cleanup.sh
set -u
cd "$(dirname "$0")" && source ./_wrapper.sh
SCRIPT=$(cat <<'EOF'
ADMIN_PROJECT="${OS_PROJECT_NAME:-admin}"; ADMIN_PROJECT_DOMAIN="${OS_PROJECT_DOMAIN_NAME:-Default}"
scope
step "Instances"; for s in aap-test-client aap-test-a aap-test-b; do openstack server delete --wait "$s" 2>&1 | grep -v "No server with a name" ; done
step "Volumes"     # a boot volume becomes deletable once the deleted instance has released it
for v in aap-test-a-vol aap-test-b-vol; do
  for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
    out=$(openstack volume delete "$v" 2>&1) && { echo "deleted $v"; break; }
    if printf '%s' "$out" | grep -q "No volume with a name"; then break; fi
    sleep 10
  done
done
step "Floating IP of the VIP"
for f in $(openstack floating ip list --long -f value -c ID -c Description | awk '$2 == "aap-test" {print $1}'); do openstack floating ip delete "$f" && echo "deleted $f"; done
step "Ports";     for p in aap-test-a-eth0 aap-test-b-eth0 aap-test-vip aap-test-a-eth1 aap-test-b-eth1 aap-test-vip-inside; do openstack port delete "$p" 2>&1 | grep -v "No Port found"; done
step "Router";    for n in aap-test-vpc-subnet aap-test-outside-subnet; do openstack router remove subnet aap-test-router "$n" 2>&1 | grep -v -i "no router\|not found\|no subnet\|could not find\|not attached"; done
                 openstack router delete aap-test-router 2>&1 | grep -v "No Router found"
step "Outside network"; openstack subnet delete aap-test-outside-subnet 2>&1 | grep -v "No Subnet found"; openstack network delete aap-test-outside 2>&1 | grep -v "No Network found"
step "VPC";       openstack subnet delete aap-test-vpc-subnet 2>&1 | grep -v "No Subnet found"; openstack network delete aap-test-vpc 2>&1 | grep -v "No Network found"
step "Security groups"; for g in aap-test-sg aap-test-sg-inside; do openstack security group delete "$g" 2>&1 | grep -v "No SecurityGroup found"; done
step "Keypair";   openstack keypair delete aap-test-key 2>&1 | grep -v "No keypair with a name"
step "Left over (should be empty)"
{ openstack server list -f value -c Name; openstack port list -f value -c Name; openstack volume list -f value -c Name; openstack security group list -f value -c Name; openstack network list -f value -c Name; openstack router list -f value -c Name; } | grep '^aap-test-' || echo "nothing left"
step "Temporary role admin of the admin account on the project (added by aap-test-create.sh)"
unset OS_PROJECT_ID; export OS_PROJECT_NAME="$ADMIN_PROJECT" OS_PROJECT_DOMAIN_NAME="$ADMIN_PROJECT_DOMAIN"
openstack role remove --project "$PID" --user "$OS_USERNAME" --user-domain "${OS_USER_DOMAIN_NAME:-Default}" admin 2>&1 | grep -v -i "not found\|could not find"
echo "roles now: $(openstack role assignment list --project "$PID" --user "$OS_USERNAME" --user-domain "${OS_USER_DOMAIN_NAME:-Default}" --names -f value -c Role | tr '\n' ' ')"
EOF
)
run_remote "$COMMON" "$SCRIPT"

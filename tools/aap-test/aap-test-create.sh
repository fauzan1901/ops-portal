#!/usr/bin/env bash
# Allowed address pairs test (FortiGate HA simulated with two VyOS, VRRP unicast) on DCB, project 249-DEMO-ITSO-DCB:
# HA on ONE internal VPC port with ONE floating IP.
#   VPC aap-test-vpc 10.242.99.0/24, gateway 10.242.99.1 = router aap-test-router to Public-Shared-04
#   VIP 10.242.99.5: a reserved port bound to no instance, with the only floating IP (the public address of the service)
#   VyOS A 10.242.99.6 (priority 200) and B 10.242.99.7 (priority 100): one port each, the VIP as allowed address pair
#   (/32), VRRP unicast between them (like a FortiGate unicast heartbeat, no virtual MAC); ICMP / SSH from the
#   bastion's public address only
# Creates only objects named aap-test-* (and, when the admin account has no role on the project, the role admin for it,
# temporarily); remove them with aap-test-cleanup.sh.  Run on the bastion: sudo bash ~/aap-test/aap-test-create.sh
set -u
cd "$(dirname "$0")" && source ./_wrapper.sh
OUT="/home/deploy/aap-test-create-$(date +%Y%m%d-%H%M%S).txt"
# The test SSH key of the bastion account (only for these test instances).
sudo -u deploy test -f /home/deploy/.ssh/aap-test || sudo -u deploy ssh-keygen -q -t ed25519 -N '' -C aap-test -f /home/deploy/.ssh/aap-test
PUBKEY=$(cat /home/deploy/.ssh/aap-test.pub)
HEADER="PUBKEY='$PUBKEY'
$COMMON"
SCRIPT=$(cat <<'EOF'
step "Roles of the admin account on the project"
ROLES=$(openstack role assignment list --project "$PID" --user "$OS_USERNAME" --user-domain "${OS_USER_DOMAIN_NAME:-Default}" --names -f value -c Role)
if [ -z "$ROLES" ]; then   # approved by the user (2026-10-14): temporary, removed again by aap-test-cleanup.sh
  echo "No role yet: adding the role admin for $OS_USERNAME on the project temporarily (aap-test-cleanup.sh removes it)"
  openstack role add --project "$PID" --user "$OS_USERNAME" --user-domain "${OS_USER_DOMAIN_NAME:-Default}" admin || fail "role add"
  ROLES=$(openstack role assignment list --project "$PID" --user "$OS_USERNAME" --user-domain "${OS_USER_DOMAIN_NAME:-Default}" --names -f value -c Role)
fi
echo "$ROLES"
scope
step "No earlier test left over"
LEFT=$( { openstack server list -f value -c Name; openstack port list -f value -c Name; openstack volume list -f value -c Name; openstack network list -f value -c Name; openstack router list -f value -c Name; } | grep '^aap-test-')
[ -z "$LEFT" ] || fail "aap-test objects exist already (run aap-test-cleanup.sh first): $LEFT"
step "Keypair aap-test-key (public key of the bastion test key)"
printf '%s\n' "$PUBKEY" > /tmp/aap-test.pub
openstack keypair show aap-test-key -f value -c name 2>/dev/null || openstack keypair create --public-key /tmp/aap-test.pub aap-test-key -f value -c name || fail keypair
step "Security group aap-test-sg: ICMP and SSH from the bastion, VRRP (protocol 112) between the members"
SG=$(openstack security group create aap-test-sg --description "allowed address pairs test, delete after the test" -f value -c id) || fail "security group"
openstack security group rule create --ingress --ethertype IPv4 --protocol icmp --remote-ip "$MGMT_SRC" "$SG" -f value -c id >/dev/null || fail "rule icmp"
openstack security group rule create --ingress --ethertype IPv4 --protocol tcp --dst-port 22 --remote-ip "$MGMT_SRC" "$SG" -f value -c id >/dev/null || fail "rule ssh"
openstack security group rule create --ingress --ethertype IPv4 --protocol 112 --remote-group "$SG" "$SG" -f value -c id >/dev/null || fail "rule vrrp"
openstack security group rule create --ingress --ethertype IPv4 --protocol tcp --dst-port 22 --remote-group "$SG" "$SG" -f value -c id >/dev/null || fail "rule ssh between members"
echo "$SG"
step "VPC aap-test-vpc 10.242.99.0/24 and router aap-test-router to Public-Shared-04"
VPC=$(openstack network create aap-test-vpc -f value -c id) || fail "network"
VSUB=$(openstack subnet create --network "$VPC" --subnet-range 10.242.99.0/24 --gateway 10.242.99.1 --allocation-pool start=10.242.99.10,end=10.242.99.200 --dns-nameserver 8.8.8.8 aap-test-vpc-subnet -f value -c id) || fail "subnet"
RTR=$(openstack router create aap-test-router -f value -c id) || fail "router"
openstack router set --external-gateway "$NET" "$RTR" || fail "router gateway"
openstack router add subnet "$RTR" "$VSUB" || fail "router interface"
echo "router $RTR"
step "VIP port aap-test-vip 10.242.99.5 (reserved, bound to no instance) and its floating IP (the only public address)"
VIP=10.242.99.5
VIP_PORT=$(openstack port create --network "$VPC" --fixed-ip subnet="$VSUB",ip-address="$VIP" --security-group "$SG" aap-test-vip -f value -c id) || fail "VIP port"
FIP=$(openstack floating ip create --port "$VIP_PORT" --description aap-test "$NET" -f value -c floating_ip_address) || fail "floating IP"
echo "VIP $VIP (port $VIP_PORT), floating IP $FIP"
step "Ports of VyOS A and B in the VPC with the VIP as allowed address pair (/32)"
IPA=10.242.99.6; IPB=10.242.99.7
PA=$(openstack port create --network "$VPC" --fixed-ip subnet="$VSUB",ip-address="$IPA" --security-group "$SG" --allowed-address ip-address="$VIP" aap-test-a-eth0 -f value -c id) || fail "port A"
PB=$(openstack port create --network "$VPC" --fixed-ip subnet="$VSUB",ip-address="$IPB" --security-group "$SG" --allowed-address ip-address="$VIP" aap-test-b-eth0 -f value -c id) || fail "port B"
echo "A $IPA (port $PA)"; echo "B $IPB (port $PB)"
step "Boot volumes from vyos-1.3-base (4 GB)"
VA=$(openstack volume create --image "$IMAGE" --size 4 --bootable aap-test-a-vol -f value -c id) || fail "volume A"
VB=$(openstack volume create --image "$IMAGE" --size 4 --bootable aap-test-b-vol -f value -c id) || fail "volume B"
for v in "$VA" "$VB"; do
  for i in $(seq 1 60); do
    s=$(openstack volume show "$v" -f value -c status); [ "$s" = available ] && break
    [ "$s" = error ] && fail "volume $v in error"; sleep 10
  done
  echo "volume $v: $s"; [ "$s" = available ] || fail "volume $v not available in time"
done
step "cloud-init of VyOS: host name and VRRP unicast on eth0"
mk() {   # name priority own-address peer-address
cat > "/tmp/aap-test-$1.yaml" <<UD
#cloud-config
vyos_config_commands:
  - set system host-name 'aap-test-$1'
  - set high-availability vrrp group VIP interface 'eth0'
  - set high-availability vrrp group VIP vrid '51'
  - set high-availability vrrp group VIP virtual-address '$VIP/24'
  - set high-availability vrrp group VIP priority '$2'
  - set high-availability vrrp group VIP hello-source-address '$3'
  - set high-availability vrrp group VIP peer-address '$4'
UD
}
mk a 200 "$IPA" "$IPB"; mk b 100 "$IPB" "$IPA"; cat /tmp/aap-test-a.yaml
step "Instances aap-test-a and aap-test-b"
openstack server create --flavor "$FLAVOR" --volume "$VA" --port "$PA" --key-name aap-test-key --user-data /tmp/aap-test-a.yaml --wait aap-test-a -f value -c id -c status || fail "server A"
openstack server create --flavor "$FLAVOR" --volume "$VB" --port "$PB" --key-name aap-test-key --user-data /tmp/aap-test-b.yaml --wait aap-test-b -f value -c id -c status || fail "server B"
step "Result"
echo "FIP=$FIP -> VIP=$VIP, A=$IPA, B=$IPB"
echo "Next, on the bastion (no sudo): bash ~/aap-test/aap-test-test.sh $FIP   (VyOS needs about 2 minutes to finish cloud-init)"
EOF
)
{ echo "aap-test create, $(date -Is)"; run_remote "$HEADER" "$SCRIPT"; } | tee "$OUT"
chown deploy: "$OUT"; echo "Saved: $OUT"

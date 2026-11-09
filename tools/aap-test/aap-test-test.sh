#!/usr/bin/env bash
# From the bastion (as deploy, no sudo), through the ONE floating IP of the VIP:
#   bash ~/aap-test/aap-test-test.sh <FIP>          who holds the VIP, VRRP state of both VyOS (B through A), client path
#   bash ~/aap-test/aap-test-test.sh <FIP> watch    ping the floating IP every 0.2 s with timestamps (Ctrl-C to stop)
set -u
FIP="$1"; MODE="${2:-}"
[[ "$FIP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "not an IPv4 address: $FIP"; exit 1; }
SSH=(ssh -i "$HOME/.ssh/aap-test" -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
JUMP="ProxyCommand=ssh -i $HOME/.ssh/aap-test -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -W %h:%p vyos@$FIP"
OP=/opt/vyatta/bin/vyatta-op-cmd-wrapper
if [ "$MODE" = watch ]; then
  echo "Ping $FIP every 0.2 s (lost replies show as gaps in icmp_seq); Ctrl-C to stop"
  exec ping -D -i 0.2 -W 1 "$FIP"
fi
echo "== Ping the floating IP"; ping -c 3 -W 2 "$FIP" | tail -2
echo "== Who holds the VIP (SSH to the floating IP)"; "${SSH[@]}" "vyos@$FIP" hostname 2>&1 | tail -1
for ip in 10.242.99.6 10.242.99.7; do
  echo "== VRRP on $ip (through the active VyOS)"
  "${SSH[@]}" -o "$JUMP" "vyos@$ip" "hostname; $OP show vrrp" 2>&1 | tail -6
done

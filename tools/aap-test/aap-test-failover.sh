#!/usr/bin/env bash
# Stops or starts one VyOS of the test (the VRRP master A or the backup B), as a FortiGate failure would.
# Run on the bastion: sudo bash ~/aap-test/aap-test-failover.sh stop|start a|b
#                     sudo bash ~/aap-test/aap-test-failover.sh log client     (the client's ping log, last 60 lines)
set -u
ACTION="${1:-}"; NODE="${2:-}"
case "$ACTION:$NODE" in stop:a|stop:b|start:a|start:b|log:client|log:a|log:b) ;; *) echo "usage: aap-test-failover.sh stop|start a|b, or log client|a|b"; exit 1;; esac
cd "$(dirname "$0")" && source ./_wrapper.sh
echo "$(date '+%H:%M:%S') $ACTION aap-test-$NODE"
run_remote "$COMMON
ACTION=$ACTION
NODE=$NODE" 'scope
if [ "$ACTION" = log ]; then openstack console log show --lines 60 aap-test-$NODE | grep -E "aap-test|login:|vyos|cloud-init" | tail -60; exit 0; fi
openstack server $ACTION aap-test-$NODE || fail "$ACTION"
for i in $(seq 1 30); do s=$(openstack server show aap-test-$NODE -f value -c status); echo "$(date +%H:%M:%S) aap-test-$NODE $s"; case "$ACTION:$s" in stop:SHUTOFF|start:ACTIVE) break;; esac; sleep 5; done'

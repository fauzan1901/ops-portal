#!/usr/bin/env bash
# Demo of the Ops Portal on this laptop: every module with mock systems, nothing real is touched.
#   mock APIC (DCB/DCA/DCC)     https://127.0.0.1:9441-9443   ACI module
#   mock ONTAP (DCB/DCA/DCC)    https://127.0.0.1:9451-9453   ONTAP Restore + Operation Automation (same account)
#   mock vCenter + NSX-T        https://127.0.0.1:9461        Operation Automation (Acme Prime)
#   mock BMCs (Lenovo, Inspur)  https://127.0.0.1:9471-9472   Operation Automation: Server hardware (BMC, Redfish)
#   fake OpenStack director     (program, no port)            ONTAP Restore + Operation Automation
#   fake hosts over "SSH"       (program, no port)            Operation Automation: CDN, DNS, VyOS, Huawei, Linux VMs, SIEM, ESXi, GB200
#   fake Active Directory       ldaps://localhost:9636        sign-in
#   portal                      http://localhost:8083
# Ctrl+C stops everything.
#   DEMO_DUO=1 ./test_mode.sh       fake Duo prompt (Approve/Deny) after the AD password
#   DEMO_SSO=1 ./test_mode.sh       "Sign in with Duo SSO" button with a fake Duo SSO
#   MOCK_REJECT=DCC ./test_mode.sh  the DCC mock APIC and mock ONTAP refuse their service accounts
#   PORT=8090 ./test_mode.sh        another port for the portal
set -euo pipefail
cd "$(dirname "$0")"
PORT="${PORT:-8083}"
PY="$PWD/.venv/bin/python"
LDAP_PORT="${LDAP_PORT:-9636}"
DUO_PORT="${DUO_PORT:-9444}"
SSO_PORT="${SSO_PORT:-9446}"
VMWARE_PORT="${VMWARE_PORT:-9461}"
DEMO_DUO="${DEMO_DUO:-0}"
DEMO_SSO="${DEMO_SSO:-0}"
[ -x "$PY" ] || { echo "Create the venv first: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt" >&2; exit 1; }
case "$DEMO_DUO$DEMO_SSO" in 00|01|10|11) ;; *) echo "DEMO_DUO and DEMO_SSO must be 0 or 1" >&2; exit 1 ;; esac

port_open() { "$PY" -c "import socket,sys; s=socket.socket(); sys.exit(s.connect_ex(('127.0.0.1', $1)) != 0)"; }
ports=("$PORT" 9441 9442 9443 9451 9452 9453 "$VMWARE_PORT" "$LDAP_PORT" 9471 9472)
if [ "$DEMO_DUO" = 1 ]; then ports+=("$DUO_PORT"); fi
if [ "$DEMO_SSO" = 1 ]; then ports+=("$SSO_PORT"); fi
for p in "${ports[@]}"; do
  case "$p" in ''|*[!0-9]*) echo "Invalid port: $p" >&2; exit 1 ;; esac
  if port_open "$p"; then
    echo "Port $p is already in use (another demo still running?). Stop that process first, or set PORT=..." >&2
    exit 1
  fi
done

WORK="$(mktemp -d)"
PIDS=()
cleanup() {
  if [ ${#PIDS[@]} -gt 0 ]; then kill "${PIDS[@]}" 2>/dev/null || true; wait "${PIDS[@]}" 2>/dev/null || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# ---------------------------------------------------------------- sites.yml of the demo
FAKE_HOSTS="FAKE_HOSTS_STATE=$WORK/hosts-state.json $PY $PWD/tests/fake_hosts.py {name}"
{
  # One vCloud Director serves every site (one read-only account: ro-vcd).
  echo "vcd: {host: \"127.0.0.1:$VMWARE_PORT\"}"
  echo "sites:"
  for entry in DCB:9441:9451 DCA:9442:9452 DCC:9443:9453; do
    IFS=: read -r site apic ontap <<<"$entry"
    low="$(echo "$site" | tr '[:upper:]' '[:lower:]')"
    cat <<EOF
  $site:
    timezone: "+07:00"
    apic: {host: "127.0.0.1:$apic"}
    ontap: {host: "127.0.0.1:$ontap", validate_certs: false, used_poll_seconds: 2, used_stable_seconds: 10, used_wait_seconds: 300}
    mgmt: {host: localhost, connection: local}
    director:
      host: director.demo
      user: admin
      command: "FAKE_DIRECTOR_STATE=$WORK/$site.json FAKE_CLOUD_STATE=$WORK/$site-cloud.json FAKE_POOL_PREFIX=${site}OPNSTACK FAKE_ONTAP_URL=https://127.0.0.1:$ontap FAKE_DIRECTOR_PY=$PWD/tests/fake_director.py $PY $PWD/tests/fake_cloud.py"
    wi: {siem_collector: "172.26.0.40:541", esxi_collector: "172.26.80.73:514",
         vyos_image_url: "https://mirror.example.com/vyos/vyos-1.5-generic-amd64.iso",
         test_ssh_command: "$FAKE_HOSTS"}
EOF
    # Like production: DCA overcommits 2:1 and still has the old volume types; vCenter / NSX-T only on DCA in the demo.
    if [ "$site" = DCA ]; then
      cat <<EOF
    openstack: {overcommit_ratio: 2, legacy_volume_types: {standard: fas500f-standard, basic: fas500f-basic, premium: affa-premium}}
    vcenter: {host: "127.0.0.1:$VMWARE_PORT", inventory_command: "$PY $PWD/tests/fake_vsphere.py"}
    nsxt: {host: "127.0.0.1:$VMWARE_PORT"}
EOF
    else
      echo "    openstack: {legacy_volume_types: {}}"
    fi
    cat <<EOF
    hosts:
      cdn: {user: wi-ro, sudo: true, connection: local, command: "$FAKE_HOSTS",
            members: {$low-cdn-lb-01: 172.31.10.67, $low-cdn-lb-02: 172.31.10.68, $low-cdn-vcp-2: 172.31.10.71}}
      repo: {user: wi-ro, sudo: true, connection: local, command: "$FAKE_HOSTS", members: {$low-repo-01: 172.31.20.5}}
      dns: {user: wi-ro, sudo: true, connection: local, command: "$FAKE_HOSTS", members: {$low-dns-recursive: 172.31.30.9}}
      vyos: {user: wi-ro, connection: local, command: "$FAKE_HOSTS", members: {$low-natgw-01: 11.7.101.238}}
      linux: {user: wi-ro, sudo: true, connection: local, command: "$FAKE_HOSTS", members: {app-vm-01: 10.249.1.20, rhel-vm-01: 10.249.1.21}}
      siem: {user: wi-ro, sudo: true, connection: local, command: "$FAKE_HOSTS", members: {siem-collector-01: 172.26.0.40}}
      esxi: {user: wi-ro, connection: local, command: "$FAKE_HOSTS", members: {esxi-$low-07: 172.25.10.7}}
      gb200: {user: wi-ro, sudo: true, connection: local, command: "$FAKE_HOSTS", members: {gb200-ct-01: 10.243.0.11}}
EOF
    if [ "$site" = DCB ]; then
      echo "      huawei: {user: wi-ro, connection: local, command: \"$FAKE_HOSTS\", upstream_peer: 11.18.9.157, members: {DCB02RCGW03: 172.26.15.15}}"
    fi
  done
} > "$WORK/sites.yml"

# ---------------------------------------------------------------- mocks and fakes
"$PY" -u tests/mock_apic.py > "$WORK/mock_apic.log" 2>&1 &
PIDS+=($!)
"$PY" -u tests/mock_ontap.py > "$WORK/mock_ontap.log" 2>&1 &
PIDS+=($!)
"$PY" -u tests/mock_vmware.py "$VMWARE_PORT" > "$WORK/mock_vmware.log" 2>&1 &
PIDS+=($!)
"$PY" -u tests/mock_redfish.py lenovo 9471 "$WORK" > "$WORK/mock_bmc_lenovo.log" 2>&1 &
PIDS+=($!)
"$PY" -u tests/mock_redfish.py inspur 9472 "$WORK" > "$WORK/mock_bmc_inspur.log" 2>&1 &
PIDS+=($!)
"$PY" - "$WORK" "$LDAP_PORT" "$DUO_PORT" "$DEMO_DUO" "$SSO_PORT" "$DEMO_SSO" <<'PY' &
import sys
import time

sys.path.insert(0, "tests")
import fake_duo
import fake_ldap
import fake_sso

work, ldap_port, duo_port, with_duo = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4] == "1"
sso_port, with_sso = int(sys.argv[5]), sys.argv[6] == "1"
cert, key = fake_ldap.make_cert(work, "demo-ad")
people = {"operator": {"password": "demo-operator", "display_name": "Demo Operator"},
          "l1": {"password": "demo-l1", "display_name": "Demo L1 NOC"}}
fake_ldap.FakeLdap(cert, key, people, port=ldap_port).start()
if with_duo:
    fake_duo.FakeDuo(cert, key, port=duo_port, auto_approve=False).start()
if with_sso:
    fake_sso.FakeSso(cert, key, port=sso_port, auto_approve=False, people={k: v["display_name"] for k, v in people.items()}).start()
while True:
    time.sleep(3600)
PY
PIDS+=($!)

wait_port() {
  for _ in $(seq 1 75); do
    if port_open "$1"; then return 0; fi
    sleep 0.2
  done
  echo "$2 did not start on port $1." >&2
  exit 1
}
wait_port 9443 "Mock APIC"
wait_port 9453 "Mock ONTAP"
wait_port "$VMWARE_PORT" "Mock vCenter / NSX-T"
wait_port 9471 "Mock Lenovo BMC"
wait_port 9472 "Mock Inspur BMC"
wait_port "$LDAP_PORT" "Fake Active Directory"
if [ "$DEMO_DUO" = 1 ]; then wait_port "$DUO_PORT" "Fake Duo"; fi
if [ "$DEMO_SSO" = 1 ]; then wait_port "$SSO_PORT" "Fake Duo SSO"; fi

# ---------------------------------------------------------------- auth.yml of the demo
read -r DUO_ID DUO_SECRET < <("$PY" -c 'import sys; sys.path.insert(0, "tests"); import fake_duo; print(fake_duo.CLIENT_ID, fake_duo.CLIENT_SECRET)')
read -r SSO_ID SSO_SECRET < <("$PY" -c 'import sys; sys.path.insert(0, "tests"); import fake_sso; print(fake_sso.CLIENT_ID, fake_sso.CLIENT_SECRET)')
cat > "$WORK/auth.yml" <<EOF
ldap:
  url: [ldaps://localhost:$LDAP_PORT]
  user_format: "{username}@example.local"
  ca_file: "$WORK/demo-ad.crt"
  verify_tls: true
  base_dn: "DC=example,DC=local"
  timeout_seconds: 5
duo:
  enabled: $([ "$DEMO_DUO" = 1 ] && echo true || echo false)
  client_id: "$DUO_ID"
  client_secret: "$DUO_SECRET"
  api_host: "localhost:$DUO_PORT"
  ca_file: "$WORK/demo-ad.crt"
  redirect_uri: "http://localhost:$PORT/auth/duo/callback"
  fail_mode: closed
sso:
  enabled: $([ "$DEMO_SSO" = 1 ] && echo true || echo false)
  issuer: "https://localhost:$SSO_PORT/oidc/$SSO_ID"
  client_id: "$SSO_ID"
  client_secret: "$SSO_SECRET"
  ca_file: "$WORK/demo-ad.crt"
  redirect_uri: "http://localhost:$PORT/auth/sso/callback"
  username_claim: preferred_username
admins: []
session:
  idle_minutes: 30
  max_hours: 8
EOF

# ---------------------------------------------------------------- what an administrator would set up
# The local portal administrator (deploy/local-admin.sh add), the AD users with their modules (Users page), and the
# service accounts (Credentials page), encrypted with the demo key.
PORTAL_SITES="$WORK/sites.yml" PORTAL_DATA="$WORK/data" PORTAL_AUTH="$WORK/auth.yml" PORTAL_CREDENTIALS_KEY="$WORK/credentials.key" \
  "$PY" - <<'PY'
import os
import sys

sys.path.insert(0, ".")
sys.path.insert(0, "tests")
import mock_apic
import mock_ontap
import mock_vmware
import portal_auth
import settings

store = portal_auth.Store(settings.DB_PATH)
vault = portal_auth.Vault(settings.CREDENTIALS_KEY)
store.add_local_user("portaladmin", portal_auth.hash_password("demo-portal-admin"), "admin", "Demo Portal Admin", "", "test_mode.sh")
store.add_user("operator", "operator", "test_mode.sh", "wi,wi-fix,wi-fix-openstack,ontap,aci")
store.add_user("l1", "operator", "test_mode.sh", "wi")
for site in ("DCB", "DCA", "DCC"):
    store.set_credential(f"apic:{site}", "svc_aci_demo", vault.encrypt(mock_apic.PASSWORD), "test_mode.sh")
    user, password = mock_ontap.DEMO_ACCOUNTS[site]
    store.set_credential(f"ontap:{site}", user, vault.encrypt(password), "test_mode.sh")
for name in ("ro-vcenter:DCA", "ro-nsxt:DCA"):
    store.set_credential(name, mock_vmware.READONLY_USER, vault.encrypt(mock_vmware.READONLY_PASSWORD), "test_mode.sh")
store.set_credential("ro-vcd", f"{mock_vmware.READONLY_USER}@System", vault.encrypt(mock_vmware.READONLY_PASSWORD), "test_mode.sh")

# Hosts & SSH: the DCA hosts with a credential that may run fixes (a test-mode key: the fake hosts never use it), the
# GB200 tray with a read-only one. DCB and DCC keep only the read-only hosts of sites.yml.
import importlib.util
spec = importlib.util.spec_from_file_location("wi_hosts", "modules/wi/hosts.py")
hosts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hosts)
hosts.init()
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
demo_key = ed25519.Ed25519PrivateKey.generate().private_bytes(   # a fresh key: the fake hosts never check it
    serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()).decode()
fix = hosts.save_credential(vault, "test_mode.sh", {"name": "ops-root-key", "username": "root", "auth": "key", "privilege": "root",
                                                     "fixes": True, "secret": demo_key})
ro = hosts.save_credential(vault, "test_mode.sh", {"name": "wi-ro-password", "username": "wi-ro", "auth": "password",
                                                    "privilege": "sudo_password", "fixes": False, "secret": "demo-wi-ro-ssh"})
for grp, name, address in [("cdn", "dca-cdn-lb-01", "172.31.10.67"), ("cdn", "dca-cdn-lb-02", "172.31.10.68"),
                           ("cdn", "dca-cdn-vcp-2", "172.31.10.71"), ("repo", "dca-repo-01", "172.31.20.5"),
                           ("dns", "dca-dns-recursive", "172.31.30.9"), ("vyos", "dca-natgw-01", "11.7.101.238"),
                           ("linux", "app-vm-01", "10.249.1.20"), ("linux", "rhel-vm-01", "10.249.1.21"),
                           ("siem", "siem-collector-01", "172.26.0.40"), ("esxi", "esxi-dca-07", "172.25.10.7")]:
    hosts.save_host("test_mode.sh", {"site": "DCA", "group": grp, "name": name, "address": address, "credential_id": fix})
hosts.save_host("test_mode.sh", {"site": "DCA", "group": "gb200", "name": "gb200-ct-01", "address": "10.243.0.11", "credential_id": ro})

# BMC: the web account of the BMCs and two servers (mock Lenovo XCC and Inspur BMC, Redfish over HTTPS).
import mock_redfish
spec = importlib.util.spec_from_file_location("wi_bmcs", "modules/wi/bmcs.py")
bmcs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bmcs)
bmcs.init()
cred = bmcs.save_credential(vault, "test_mode.sh", {"name": "bmc-readonly", "username": mock_redfish.USER, "secret": mock_redfish.PASSWORD})
bmcs.save_bmc("test_mode.sh", {"site": "DCA", "name": "dca-compute-07", "address": "127.0.0.1:9471", "vendor": "lenovo", "credential_id": cred,
                               "note": "ThinkSystem SR650 V2 (mock XCC)"})
bmcs.save_bmc("test_mode.sh", {"site": "DCA", "name": "dca-storage-02", "address": "localhost:9472", "vendor": "inspur", "credential_id": cred,
                               "note": "NF5280M6 (mock Inspur BMC)"})
PY

if [ "$DEMO_DUO" = 1 ]; then DUO_TEXT="Duo (fake): after the AD password the browser opens a Duo page (accept its self-signed certificate once, then Approve)."
else DUO_TEXT="Duo: off (DEMO_DUO=1 adds a fake Duo step)."; fi
if [ "$DEMO_SSO" = 1 ]; then SSO_TEXT="Duo SSO (fake): \"Sign in with Duo SSO\" on the sign-in page; type operator or l1, Approve."
else SSO_TEXT="Duo SSO: off (DEMO_SSO=1 adds the \"Sign in with Duo SSO\" button)."; fi

cat <<EOF

==================== ACME CLOUD PORTAL - DEMO MODE ====================
Open:  http://localhost:$PORT     (use localhost, not 127.0.0.1, for Duo / Duo SSO)

Sign in with:
  portaladmin / demo-portal-admin   local administrator: every module + Users and Credentials
  operator    / demo-operator       AD account: Operation Automation (and run fixes), ONTAP Restore, ACI
  l1          / demo-l1             AD account: Operation Automation only, checks without fixes (try opening /aci/)
$DUO_TEXT
$SSO_TEXT

Operation Automation — things to try (vCenter/NSX-T only on DCA; one vCloud Director for every site):
  Cinder volume over 80%                        (no parameter)
  Alert: Custom Port TCP DCC 6600 is DOWN       IP 203.0.113.10, port 6600
  Instance cannot be reached                    5e5e5e5e-0000-4000-8000-000000000002 (SHUTOFF)
  Project quota full                            customer-a80
  Volume cannot be attached again               11111111-0000-4000-8000-000000000006, instance 5e5e5e5e-0000-4000-8000-000000000001
  Alert: disk full on /run                      dca-cdn-lb-01 (or type 172.31.10.67:9100)
  Alert: DatasourceError                        dca-cdn-lb-02
  VyOS SNAT / DNAT not working                  dca-natgw-01
  Service not answering / port conflict         app-vm-01, port 80, service nginx
  Port blocked on a Linux VM                    app-vm-01, port 27017, source 10.249.2.15
  Datastore low free space / SNAT priority      DCA only (Tier-1 t1-cust-a)
  Host high CPU / memory, VM resource pool      DCA only (host esxi-dca-02, or empty for every host)
  VM power on fails (vCloud, one for all sites)  erp-app-01 (quota), web-02 (IP conflict), db-03 (inconsistent),
                                                app-04 (resource pool), report-05 (task stuck on a cell); vCenter of DCA
  Edge gateway (vCloud, one for all sites)      CUST-A-EDGE, VM IP 10.249.10.16, port 8443, public IP 11.4.20.31
  Huawei RCGW prefix                            site DCB, DCB02RCGW03, 11.5.244.0/23
Platform health (not from a KB page):
  OpenStack services and agents                 (no parameter) — nova-compute down on compute-03, dead OVN agents
  Bare metal nodes (BMC power state)            (no parameter) — overcloud-novacompute-3: power failure
  Pacemaker and fencing (controllers)           (no parameter) — rabbitmq FAILED, a stonith device stopped, failed fencing
  Overcloud logs                                (no parameter), or instance 5e5e5e5e-0000-4000-8000-000000000001 (timeline)
  Overcloud node health                         (no parameter) — controller-0 / at 95%, neutron_api unhealthy on controller-1
  Compute capacity                              (no parameter) — compute-07 above 80% of vCPU / RAM
  ONTAP capacity                                DCA (ONTAP of the demo): an aggregate at 91%, a broken disk
  Server resources (CPU, memory, disk)          app-vm-01 (/ at 93%, memory 91%, nginx failed)
  Certificates expiring                         any site (the demo certificates live 2 days)
  vCenter alarms, events and hardware           DCA only
  NSX-T alarms and transport nodes              DCA only
  Server hardware (BMC)                         dca-compute-07 (Lenovo: DIMM, PSU, drive) or dca-storage-02 (Inspur); page BMC

Every result: Export CSV / Export PDF (title bar of the run).
Fixes ("Run this fix" under How to fix it): DCA hosts have the SSH credential ops-root-key that may run fixes (Hosts & SSH);
  high-risk fixes ask for the host name. The check runs again after a fix. ONTAP cluster health on DCC: revert cluster_mgmt.

ONTAP Restore and ACI: the same demo data as their own test_mode.sh
  (volume a80a1a07-06b8-489b-a984-b046981f68b9; APIC service accounts any user / secret).
=====================================================================

EOF
PORTAL_SITES="$WORK/sites.yml" PORTAL_DATA="$WORK/data" PORTAL_AUTH="$WORK/auth.yml" PORTAL_CREDENTIALS_KEY="$WORK/credentials.key" \
  HOST=127.0.0.1 PORT="$PORT" "$PY" app.py

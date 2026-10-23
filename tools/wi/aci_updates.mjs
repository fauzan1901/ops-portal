// ACI Web UI WI image that changed with the activity log (27 Sep 2026): Users with the filtered activity log.
// Demo: PORT=8092 ACI_TRUSTED_PROXIES=1 ACI_AUDIT_DB=<temporary file> ./test_mode.sh
import { BASTION, REMOTE_PC, apiSession, browserSignIn } from './common.mjs';
const base = 'http://localhost:8092';

export default async (b, out) => {
  // An operator on another computer: static port with the Acme Flex product.
  const operator = await apiSession(base, 'operator', 'demo-operator', REMOTE_PC);
  await operator.call('/api/static-port/apply?site=DCB', {tenant: 'CLOUD-1', app: 'MGMT-InBand', epg: 'MGMT-VYOS', product: 'flex',
    paths: [{tdn: 'topology/pod-1/paths-101/pathep-[eth1/13]', vlan: '1850'}, {tdn: 'topology/pod-1/paths-106/pathep-[eth1/20]', vlan: '1850'}]});
  // The administrator in a Remote Desktop session on the bastion: provisioning of a new BD and EPG.
  const admin = await apiSession(base, 'portaladmin', 'demo-portal-admin', BASTION);
  await admin.call('/api/provision/apply?site=DCB', {
    tenant: {mode: 'existing', name: 'CLOUD-1', descr: ''}, vrf: {mode: 'existing', name: 'VRF-1', descr: ''},
    bd: {mode: 'new', name: 'BD-ACME-FLEX-1860', descr: '', unknown_unicast: 'proxy', arp_flood: false,
         subnets: [{ip: '10.241.0.1/24', scope: 'public', preferred: false, virtual: false}], l3outs: []},
    app: {mode: 'existing', name: 'PUBLIC-CLOUD-OPENSTACK', descr: ''}, epg: {name: 'Acme-Flex-1860', descr: ''},
    domains: ['uni/phys-DCB-PHYS'], deployment: 'immediate', resolution: 'immediate'});

  await browserSignIn(b, base, 'aci_webui_sid', 'portaladmin', 'demo-portal-admin', BASTION);
  await b.goto(`${base}/?s=1#users`, 2500);
  await b.waitFor(`document.querySelectorAll('#eventsTable tbody tr').length > 3 && document.querySelector('#eventsTable a[data-audit]')`, 20000);
  // Filtered on changes sent to APIC: one from another computer, one from the bastion (RDP).
  await b.eval(`(() => { const k = document.querySelector('#evKind'); k.value = 'static_port,provisioning'; k.dispatchEvent(new Event('change')); })()`);
  await b.waitFor(`document.querySelectorAll('#eventsTable tbody tr').length === 2`, 20000);
  await b.sleep(500);
  await b.mark([['#userAddBtn', '1'], ['#evUser', '2'], ['#evKind', '3'], ['#eventsTable a[data-audit]', '4'],
                ['#eventsTable td.ev-client', '5']]);
  await b.shot(`${out}/aci_18_users.png`, {selector: '#tab-users', pad: 0, maxHeight: 1400});
  await b.unmark();
};

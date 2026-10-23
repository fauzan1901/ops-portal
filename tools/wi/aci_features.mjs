// ACI Web UI WI images of 29 Sep 2026: Suggest free VLAN, the source of every binding in the Report, undo of a static-port
// change from History, and Users with the date filters and Export CSV of the activity log.
// Demo: PORT=8092 LDAP_PORT=9656 ACI_TRUSTED_PROXIES=1 ACI_AUDIT_DB=<temporary file> ./test_mode.sh
import { BASTION, REMOTE_PC, apiSession, browserSignIn, click } from './common.mjs';
const base = 'http://localhost:8092';
const TARGET = {tenant: 'CLOUD-1', app: 'MGMT-InBand', epg: 'MGMT-VYOS'};

const pick = (id, value) => `(async () => { const s = document.querySelector('${id}');
  for (let i = 0; i < 40 && ![...s.options].some(o => o.value === '${value}'); i++) await new Promise(r => setTimeout(r, 250));
  s.value = '${value}'; s.dispatchEvent(new Event('change', {bubbles: true})); })()`;

export default async (b, out) => {
  // An operator on another computer adds two paths with the Acme Flex product (change #1).
  const operator = await apiSession(base, 'operator', 'demo-operator', REMOTE_PC);
  await operator.call('/api/static-port/apply?site=DCB', {...TARGET, product: 'flex',
    paths: [{tdn: 'topology/pod-1/paths-101/pathep-[eth1/13]', vlan: '1850'}, {tdn: 'topology/pod-1/paths-106/pathep-[eth1/20]', vlan: '1850'}]});
  // The administrator in a Remote Desktop session on the bastion: provisioning of a new BD and EPG (change #2).
  const admin = await apiSession(base, 'portaladmin', 'demo-portal-admin', BASTION);
  await admin.call('/api/provision/apply?site=DCB', {
    tenant: {mode: 'existing', name: 'CLOUD-1', descr: ''}, vrf: {mode: 'existing', name: 'VRF-1', descr: ''},
    bd: {mode: 'new', name: 'BD-ACME-FLEX-1860', descr: '', unknown_unicast: 'proxy', arp_flood: false,
         subnets: [{ip: '10.241.0.1/24', scope: 'public', preferred: false, virtual: false}], l3outs: []},
    app: {mode: 'existing', name: 'PUBLIC-CLOUD-OPENSTACK', descr: ''}, epg: {name: 'Acme-Flex-1860', descr: ''},
    domains: ['uni/phys-DCB-PHYS'], deployment: 'immediate', resolution: 'immediate'});
  await browserSignIn(b, base, 'aci_webui_sid', 'portaladmin', 'demo-portal-admin', BASTION);

  // 1. Static Port: the free VLANs of the EPG's VLAN pool.
  await b.goto(`${base}/?s=${Date.now()}#static`, 2500);
  await b.eval(`[...document.querySelectorAll('a')].find(a => a.getAttribute('href') === '#static')?.click()`);
  await b.sleep(800);
  await b.eval(pick('#spTenant', TARGET.tenant));
  await b.sleep(800);
  await b.eval(pick('#spApp', TARGET.app));
  await b.sleep(800);
  await b.eval(pick('#spEpg', TARGET.epg));
  await b.sleep(1200);
  // The comboboxes show the chosen names (the script set the selects behind them).
  await b.eval(`(() => { for (const [id, v] of [['#spTenantCombo', '${TARGET.tenant}'], ['#spAppCombo', '${TARGET.app}'], ['#spEpgCombo', '${TARGET.epg}']]) {
    const i = document.querySelector(id); if (i) i.value = v; } })()`);
  await b.waitFor(`document.querySelector('input[name="product"][value="flex"]:not([disabled])')`, 20000);
  await b.eval(click('input[name="product"][value="flex"]'));
  await b.waitFor(`document.querySelector('#productVlan') && document.querySelector('#productVlan').offsetParent`, 20000);
  await b.eval(`document.querySelector('#productVlan').scrollIntoView({block: 'center'})`);
  await b.sleep(600);
  await b.eval(click('[data-suggest="productVlan"]'));
  await b.waitFor(`document.querySelector('#vlanSuggest') && !document.querySelector('#vlanSuggest').hidden && document.querySelector('#vlanSuggest').innerText.includes('Free')`, 20000);
  await b.sleep(400);
  await b.mark([['[data-suggest="productVlan"]', '1'], ['#vlanSuggest', '2']]);
  const card = await b.eval(`(() => { const r1 = document.querySelector('#productVlan').closest('.card, section').getBoundingClientRect();
    const r2 = document.querySelector('#vlanSuggest').getBoundingClientRect();
    const top = Math.min(r1.top, r2.top) + scrollY - 12, bottom = Math.max(r2.bottom, r1.bottom) + scrollY + 12;
    return {x: Math.max(0, r1.left + scrollX - 12), y: Math.max(0, top), width: r1.width + 24, height: bottom - Math.max(0, top)}; })()`);
  await b.eval(`document.querySelectorAll('.actionbar').forEach(e => { e.style.visibility = 'hidden'; })`);
  await b.shot(`${out}/aci_03b_vlan_suggest.png`, { clip: card });   // no scrolling: the panel closes when the page scrolls
  await b.eval(`document.querySelectorAll('.actionbar').forEach(e => { e.style.visibility = ''; })`);
  await b.unmark();
  await b.eval(`document.querySelector('#vlanSuggest button[aria-label], #vlanSuggest .suggest-close, #vlanSuggest [data-close]')?.click()`);

  // 2. Report: the source of every binding (a wide window, so the Source column is in view).
  await b.send('Emulation.setDeviceMetricsOverride', { width: 1920, height: 1000, deviceScaleFactor: 1, mobile: false });
  await b.goto(`${base}/?s=${Date.now()}#report`, 2500);
  await b.eval(`[...document.querySelectorAll('a')].find(a => a.getAttribute('href') === '#report')?.click()`);
  await b.sleep(800);
  await b.eval(pick('#rpTenant', TARGET.tenant));
  await b.sleep(800);
  await b.eval(`[...document.querySelectorAll('#tab-report button')].find(x => x.textContent.trim() === 'Show').click()`);
  await b.waitFor(`document.querySelectorAll('#tab-report tbody tr').length > 3`, 20000);
  await b.sleep(600);
  await b.mark([['#rpSource', '1'], ['#tab-report tbody tr td a', '2'], ['#tab-report [data-export="xlsx"], #tab-report [data-export="csv"]', '3']]);
  await b.shot(`${out}/aci_15_report.png`, { selector: '#tab-report', pad: 0, maxHeight: 1100 });
  await b.unmark();
  await b.send('Emulation.setDeviceMetricsOverride', { width: b.width, height: b.height, deviceScaleFactor: 1, mobile: false });

  // 3. History: undo change #1 (review only; nothing is sent).
  await b.goto(`${base}/?s=${Date.now()}#audit`, 2500);
  await b.eval(`[...document.querySelectorAll('a')].find(a => a.getAttribute('href') === '#audit')?.click()`);
  await b.waitFor(`document.querySelector('#auTable tbody tr[data-id="1"]')`, 20000);
  await b.eval(click('#auTable tbody tr[data-id="1"]'));
  await b.waitFor(`document.querySelector('#auditDialog[open] [data-act="undo"]')`, 20000);
  await b.sleep(500);
  await b.mark([['#auditDialog [data-act="undo"]', '1']]);
  await b.shot(`${out}/aci_17a_undo_button.png`, { selector: '#auditDialog', pad: 8, page: true });
  await b.unmark();
  await b.eval(click('#auditDialog [data-act="undo"]'));
  await b.waitFor(`[...document.querySelectorAll('dialog[open]')].some(d => /Undo change #1/.test(d.innerText) && /to delete/.test(d.innerText))`, 20000);
  await b.sleep(500);
  const dlg = `[...document.querySelectorAll('dialog[open]')].find(d => /Undo change #1/.test(d.innerText))`;
  await b.eval(`(() => { const d = ${dlg}; d.id = 'wiUndo'; })()`);
  await b.mark([['#wiUndo table', '1'], ['#wiUndo .btn-danger, #wiUndo button.btn-primary', '2']]);
  await b.shot(`${out}/aci_17b_undo.png`, { selector: '#wiUndo', pad: 8, page: true });
  await b.unmark();

  // 4. Users: activity of one kind between two dates, and its Export CSV.
  await b.goto(`${base}/?s=${Date.now()}#users`, 2500);
  await b.eval(`[...document.querySelectorAll('a')].find(a => a.getAttribute('href') === '#users')?.click()`);
  await b.waitFor(`document.querySelectorAll('#eventsTable tbody tr').length > 2 && document.querySelector('#eventsTable a[data-audit]')`, 20000);
  const today = new Date().toISOString().slice(0, 10);
  await b.eval(`(() => { const k = document.querySelector('#evKind'); k.value = 'static_port,provisioning'; k.dispatchEvent(new Event('change'));
    for (const id of ['#evSince', '#evUntil']) { const d = document.querySelector(id); d.value = '${today}'; d.dispatchEvent(new Event('change')); } })()`);
  await b.sleep(1500);
  await b.mark([['#userAddBtn', '1'], ['#evUser', '2'], ['#evKind', '3'], ['#evSince', '4'], ['#eventsExport', '5'],
                ['#eventsTable a[data-audit]', '6'], ['#eventsTable td.ev-client', '7']]);
  await b.shot(`${out}/aci_18_users.png`, { selector: '#tab-users', pad: 0, maxHeight: 1400 });
  await b.unmark();
};

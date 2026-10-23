// ACI WI images of 19 Oct 2026: Fabric -> Templates (editing a product template), its review, New product, and the
// permission "ACI: edit product templates" on the Users page of the portal.
// Demo of the portal: PORT=8083 bash portal/test_mode.sh (fresh, so the templates are the shipped ones)
//   node tools/wi/cdp.mjs tools/wi/aci_templates.mjs WI/images
import { apiSession, browserSignIn, click } from './common.mjs';
const base = 'http://localhost:8083';
const value = (sel, v) => `(() => { const e = document.querySelector(${JSON.stringify(sel)}); e.value = ${JSON.stringify(v)};
  e.dispatchEvent(new Event('input', {bubbles: true})); e.dispatchEvent(new Event('change', {bubbles: true})); })()`;

// The whole page in the viewport (sticky bars at their place), or back to the normal window.
async function fit(b, on) {
  const height = on ? await b.eval('document.documentElement.scrollHeight') : b.height;
  await b.send('Emulation.setDeviceMetricsOverride', { width: b.width, height, deviceScaleFactor: 1, mobile: false });
  await b.sleep(400);
  return height;
}

export default async (b, out) => {
  // Again from the shipped RHOSO template of DCB, when an earlier run saved it.
  const admin = await apiSession(base, 'portaladmin', 'demo-portal-admin');
  const rhoso = (await admin.call('/aci/api/templates?site=DCB')).products.find(p => p.id === 'rhoso');
  if (rhoso.edited) await admin.call('/aci/api/templates/rhoso/save?site=DCB', {version: rhoso.version, reset: true});
  await browserSignIn(b, base, 'ops_portal_sid', 'portaladmin', 'demo-portal-admin');

  // 1. Templates: RHOSO on DCB; a vPC from Search APIC and a mistyped one that is not on APIC.
  await b.goto(`${base}/aci/?s=${Date.now()}#templates`, 2500);
  await b.waitFor(`document.querySelector('#tpPicker input[value="rhoso"]')`, 20000);
  await b.eval(click('#tpPicker input[value="rhoso"]'));
  await b.waitFor(`Templates.productId === 'rhoso' && document.querySelectorAll('#tpGroupsTable tbody tr[data-key]').length === 3`);
  await b.eval(click('#tpKind [data-kind="paths"]'));
  await b.eval(click('[data-tp-tool="search"]'));
  await b.eval(value('#tpSearchQ', 'RHOSO-TRAFFIC'));
  await b.eval(click('#tpSearchBtn'));
  await b.waitFor(`document.querySelectorAll('#tpSearchResults input').length >= 7`);
  await b.eval(`[...document.querySelectorAll('#tpSearchResults label')].filter(l => /RHOSO-TRAFFIC-[FG]-PG/.test(l.textContent))
    .forEach(l => { const i = l.querySelector('input'); i.checked = true; i.dispatchEvent(new Event('change', {bubbles: true})); })`);
  await b.eval(click('#tpSearchAdd'));
  await b.eval(click('[data-tp-tool="search"]'));   // close the panel again
  await b.eval(click('#tpAddRow'));
  await b.eval(value('#tpPathsTable tbody tr:last-child input[data-k="tdn"]', 'topology/pod-1/protpaths-122-123/pathep-[RHOSO-TRAFIC-H-PG]'));
  await b.waitFor(`document.querySelector('#tpPathsTable tbody tr:last-child .tp-apic .badge-danger')`, 20000);
  await b.eval(`document.querySelectorAll('#toasts .toast').forEach(t => t.remove())`);
  await fit(b, true);
  await b.mark([['#siteSwitch', '1'], ['#tpPicker label:has(input[value="rhoso"]) .product-card', '2'], ['#tpGroupsTable', '3'],
                ['#tpDefGroup', '4'], ['#tpPathsCard .toolbar', '4'], ['#tpPathsTable tbody tr:nth-child(2) [data-act="del"]', '5'],
                ['#tpPathsTable tbody tr:last-child .tp-apic .badge', '6'], ['#tpReviewBtn', '7']]);
  await b.shot(`${out}/aci_03c_templates.png`);
  await b.unmark();
  await fit(b, false);

  // 2. Review: the mistyped row removed; two vPCs added.
  await b.eval(click('#tpPathsTable tbody tr:last-child [data-act="del"]'));
  await b.eval(click('#tpReviewBtn'));
  await b.waitFor(`document.querySelector('#reviewDialog[open]') && /Save template for DCB/.test(document.querySelector('#reviewConfirm').textContent)`, 20000);
  await b.sleep(500);
  await b.mark([['#reviewBody .pills', '1'], ['#reviewBody table', '1'], ['#reviewConfirm', '2']]);
  await b.shot(`${out}/aci_03d_template_review.png`, { selector: '#reviewDialog', pad: 8, page: true });
  await b.unmark();
  await b.eval(click('#reviewConfirm'));
  await b.waitFor(`/template saved for DCB/.test(document.querySelector('#reviewBody').textContent)`, 20000);
  await b.eval(click('#reviewCancel'));
  await b.eval(`document.querySelectorAll('#toasts .toast').forEach(t => t.remove())`);

  // 3. New product.
  await b.eval(click('#tpNewProduct'));
  await b.waitFor(`document.querySelector('#productDialog[open]')`);
  await b.eval(value('#pdLabel', 'Acme GPU'));
  await b.eval(value('#pdPlatform', 'Bare metal'));
  await b.sleep(300);
  await b.mark([['#pdLabel', '1'], ['#pdPlatform', '2'], ['#pdMode', '3'], ['#pdImm', '3'], ['#pdSave', '4']]);
  await b.shot(`${out}/aci_03e_new_product.png`, { selector: '#productDialog', pad: 8, page: true });
  await b.unmark();
  await b.eval(click('#productDialog [data-close]'));

  // 4. Users (portal): the permission under the ACI module of Add user.
  await b.goto(`${base}/?s=${Date.now()}#/users`, 2500);
  await b.waitFor(`document.querySelector('#addUserBtn') && document.querySelector('#addUserBtn').offsetParent`, 20000);
  await b.eval(click('#addUserBtn'));
  await b.waitFor(`document.querySelector('#addUserDialog[open] #addUserModules input[value="aci-templates"]')`, 20000);
  await b.eval(value('#addUserName', 'jdoe'));
  await b.eval(`for (const v of ['aci', 'aci-templates']) { const i = document.querySelector('#addUserModules input[value="' + v + '"]');
    if (!i.checked) { i.checked = true; i.dispatchEvent(new Event('change', {bubbles: true})); } }`);
  await b.sleep(300);
  await b.mark([['#addUserModules label:has(input[value="aci"])', '1'], ['#addUserModules label:has(input[value="aci-templates"])', '2'],
                ['#addUserSave', '3']]);
  await b.shot(`${out}/aci_18b_template_permission.png`, { selector: '#addUserDialog', pad: 8, page: true });
  await b.unmark();
};

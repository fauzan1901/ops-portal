// ONTAP Restore WI image of 29 Sep 2026: a boot volume restored as a new instance in ANOTHER project, whose network
// interfaces go to the networks (VPCs) of that project.
// Demo: PORT=8091 LDAP_PORT=9646 ONTAP_TRUSTED_PROXIES=1 ./test_mode.sh
import { BASTION, browserSignIn, click } from './common.mjs';
const base = 'http://localhost:8091';
const BOOT = '55555555-5555-4555-8555-555555555555';        // vda of vm-01 (project customer-a80)
const OTHER_PROJECT = 'c0ffee00000000000000000000000002';    // customer-other: VPCs vpc-other and vpc-other-db
const VPC_DB = '0e000000-0000-4000-8000-00000000000d';        // vpc-other-db, two subnets

export default async (b, out) => {
  await browserSignIn(b, base, 'ontap_restore_sid', 'portaladmin', 'demo-portal-admin', BASTION);
  await b.send('Network.setExtraHTTPHeaders', { headers: BASTION });
  await b.goto(`${base}/?s=${Date.now()}#/restore`, 1500);
  await b.eval(click('#siteSwitch input[value="DCA"]'));
  await b.sleep(400);
  await b.eval(`(() => { const i = document.querySelector('#volumeId'); i.value = '${BOOT}'; i.dispatchEvent(new Event('input')); })()`);
  await b.eval(click('#findBtn'));
  await b.waitFor(`document.querySelector('#volumeInfo').innerText.includes('LUN found')`, 60000);
  await b.eval(click('#wizNext'));
  await b.sleep(400);
  await b.eval(click('#snapList tr[data-snap="hourly.2025-12-17_1905"]'));
  await b.eval(click('#wizNext'));
  await b.sleep(300);
  await b.eval(`(() => { const i = document.querySelector('#projectId'); i.value = '${OTHER_PROJECT}'; i.dispatchEvent(new Event('input')); })()`);
  await b.sleep(300);
  await b.eval(click('#wizNext'));
  await b.waitFor(`!document.querySelector('#wizHint').textContent.startsWith('Checking') && document.querySelector('#reviewBody h3')`, 120000);
  await b.sleep(500);
  await b.eval(click('#reviewBody tr[data-pool]:not(.is-disabled)'));
  await b.eval(click('input[name="afterAction"][value="instance"]'));
  await b.sleep(500);
  // Network interface 1 was on net-app of the original project: choose vpc-other-db of the target project.
  await b.eval(`(() => { const s = document.querySelector('[data-port-net="1"]'); s.value = '${VPC_DB}';
    s.dispatchEvent(new Event('change', {bubbles: true})); })()`);
  await b.sleep(500);
  await b.eval(`(() => { const hs = [...document.querySelectorAll('#reviewBody h3')];
    hs.find(h => h.textContent.startsWith('After the restore')).id = 'wiAfterTop';
    hs.find(h => h.textContent.startsWith('Commands')).id = 'wiCmdTop';
    document.querySelector('input[name="afterAction"][value="instance"]').closest('label').id = 'wiInstanceCard';
    document.querySelector('#wiAfterTop').scrollIntoView({block: 'start'}); })()`);
  await b.mark([['#wiInstanceCard', '1'], ['#instanceName', '2'], ['[data-port-net="1"]', '3'], ['[data-port-subnet="1"]', '4'],
                ['#afterDetail table tbody tr:first-child td:nth-child(4)', '5']]);
  const clip = await b.area('#reviewBody', '#wiAfterTop', '#wiCmdTop', 12);
  await b.shot(`${out}/ontap_08b_after_instance.png`, { clip, page: true });
  await b.unmark();
};

// ACI WI images of 19 Oct 2026: Fabric -> IP Usage (endpoint IPs learned per EPG subnet, free addresses, suggestions)
// and the details of one EPG subnet.
// Demo of the portal: PORT=8083 bash portal/test_mode.sh
//   node tools/wi/cdp.mjs tools/wi/aci_ip_usage.mjs WI/images
import { browserSignIn, click } from './common.mjs';
const base = 'http://localhost:8083';

export default async (b, out) => {
  await browserSignIn(b, base, 'ops_portal_sid', 'operator', 'demo-operator');
  await b.goto(`${base}/aci/?s=${Date.now()}#ips`, 2500);
  await b.waitFor(`document.querySelector('#ipShowBtn') && !document.querySelector('#ipTenant').disabled`, 20000);
  await b.eval(click('#ipShowBtn'));
  await b.waitFor(`document.querySelectorAll('#ipTable tbody tr[data-id]').length >= 3`, 20000);
  await b.eval(`document.querySelectorAll('#toasts .toast').forEach(t => t.remove())`);
  await b.sleep(400);
  await b.mark([['#tab-ips .report-filters', '1'], ['#ipScope', '2'], ['#tab-ips label.check', '2'], ['#ipTable tbody tr:first-child td:nth-child(4)', '3'],
                ['#ipTable tbody tr:first-child td:nth-child(5)', '4'], ['#ipTable tbody tr:first-child .ip-suggest', '5'], ['#ipExportBtn', '6']]);
  await b.shot(`${out}/aci_15b_ip_usage.png`, { selector: '#tab-ips', pad: 0, maxHeight: 1200 });
  await b.unmark();

  await b.eval(click('#ipTable tbody tr:first-child'));
  await b.waitFor(`document.querySelector('#ipDialog[open]')`, 10000);
  await b.sleep(400);
  await b.mark([['#ipDialogBody .meta-grid', '1'], ['#ipDialogBody .chips', '2'], ['#ipDialogBody table', '3']]);
  await b.shot(`${out}/aci_15c_ip_detail.png`, { selector: '#ipDialog', pad: 8, page: true, maxHeight: 1100 });
  await b.unmark();
};

// ONTAP Restore WI images of 29 Sep 2026: several volumes of one instance (step 1, Review, group page), the volume type of
// the new volume with the pools of that type (DCA: Cinder overcommit 2:1), Jobs with Export CSV and groups, and Users with
// the date filters and Export CSV of the activity log.
// Demo: PORT=8091 LDAP_PORT=9646 ONTAP_TRUSTED_PROXIES=1 ./test_mode.sh
import { BASTION, browserSignIn, click } from './common.mjs';
const base = 'http://localhost:8091';
const VDB = 'a80a1a07-06b8-489b-a984-b046981f68b9';

// Wizard up to the Review step on DCA: volume vdb of vm-01, optionally with its boot disk vda.
async function toReview(b, withBoot) {
  await b.goto(`${base}/?s=${Date.now()}#/restore`, 1500);
  await b.eval(click('#siteSwitch input[value="DCA"]'));
  await b.sleep(400);
  await b.eval(`(() => { const i = document.querySelector('#volumeId'); i.value = '${VDB}'; i.dispatchEvent(new Event('input')); })()`);
  await b.eval(click('#findBtn'));
  await b.waitFor(`document.querySelector('#volumeInfo').innerText.includes('LUN found') && document.querySelector('input[name="groupVol"]')`, 60000);
  if (withBoot) {
    await b.eval(click('input[name="groupVol"]'));
    await b.waitFor(`document.querySelector('#groupPick').innerText.includes('LUN found')`, 30000);
  }
}

async function nextToReview(b) {
  await b.eval(click('#wizNext'));
  await b.sleep(400);
  await b.eval(click('#snapList tr[data-snap="hourly.2025-12-17_1905"]'));
  await b.eval(click('#wizNext'));
  await b.sleep(300);
  await b.eval(click('#wizNext'));
  await b.waitFor(`!document.querySelector('#wizHint').textContent.startsWith('Checking') && document.querySelector('#reviewBody h3')`, 120000);
  await b.sleep(500);
}

// A shot of the page from the top of one element to the top of another (both inside the review).
async function between(b, path, top, bottom) {
  const clip = await b.area('#reviewBody', top, bottom, 12);
  await b.shot(path, { clip, page: true });
}

export default async (b, out) => {
  await browserSignIn(b, base, 'ontap_restore_sid', 'portaladmin', 'demo-portal-admin', BASTION);
  // Every browser request comes from a Remote Desktop session on the bastion (the demo trusts these headers like nginx).
  await b.send('Network.setExtraHTTPHeaders', { headers: BASTION });

  // 1. Step 1: the other disk of the instance, ticked and read from ONTAP.
  await toReview(b, true);
  await b.eval(`document.querySelector('#groupPick').scrollIntoView({block: 'center'})`);
  await b.mark([['#groupPick input[name="groupVol"]', '1'], ['#groupPick tbody td:last-child', '2']]);
  await b.shot(`${out}/ontap_03b_group_pick.png`, { selector: '#groupPick', pad: 12, page: true });
  await b.unmark();

  // 2. Review of the group: pools per volume, a new instance with all new volumes.
  await nextToReview(b);
  for (const i of [0, 1]) await b.eval(click(`#reviewBody tr[data-pool][data-plan="${i}"]:not(.is-disabled)`));
  await b.eval(`(() => { const r = document.querySelector('input[name="afterAction"][value="instance"]'); r.click(); })()`);
  await b.sleep(600);
  await b.eval(`document.querySelector('#reviewBody').scrollIntoView({block: 'start'})`);
  await b.mark([['#reviewBody dl', '1'], ['#reviewBody table[aria-label="Volumes to restore"]', '2']]);
  await between(b, `${out}/ontap_09d_group_review.png`, '#reviewBody > h3', '#reviewBody > h3:nth-of-type(2)');
  await b.unmark();
  await b.eval(click('#reviewAck'));
  await b.sleep(300);
  await b.eval(click('#wizNext'));
  await b.waitFor(`location.hash.startsWith('#/groups/')`, 20000);
  await b.waitFor(`/Successful|stopped|Unknown/.test(document.querySelector('#groupStatus').innerText)`, 240000);
  await b.sleep(800);
  await b.mark([['#groupStatus', '1'], ['#groupList tr:last-child td:nth-child(5)', '2'], ['#groupList tr:last-child td:last-child a', '3']]);
  await b.shot(`${out}/ontap_11c_group_page.png`, { selector: '#page-group', pad: 0, maxHeight: 1200 });
  await b.unmark();

  // 3. One volume: the volume type and the pools that follow it (DCA overcommits 2:1).
  await toReview(b, false);
  await nextToReview(b);
  await b.eval(`[...document.querySelectorAll('#reviewBody h3')].find(h => h.textContent.startsWith('Volume type and Cinder pool')).scrollIntoView({block: 'start'})`);
  await b.mark([['#targetType', '1'], ['#reviewBody tr[data-pool]', '2'], ['#reviewBody tr[data-pool] td:nth-child(4)', '3']]);
  const poolsTop = `[...document.querySelectorAll('#reviewBody h3')].find(h => h.textContent.startsWith('Volume type and Cinder pool'))`;
  await b.eval(`(() => { const h = ${poolsTop}; h.id = 'wiPoolsTop'; const a = [...document.querySelectorAll('#reviewBody h3')].find(x => x.textContent.startsWith('After the restore')); a.id = 'wiAfterTop'; })()`);
  await between(b, `${out}/ontap_07_pools.png`, '#wiPoolsTop', '#wiAfterTop');
  await b.unmark();
  await b.eval(`(() => { const s = document.querySelector('#targetType'); s.value = 'nvme-premium'; s.dispatchEvent(new Event('change', {bubbles: true})); })()`);
  await b.sleep(600);
  await b.eval(`(() => { const h = ${poolsTop}; h.id = 'wiPoolsTop'; const a = [...document.querySelectorAll('#reviewBody h3')].find(x => x.textContent.startsWith('After the restore')); a.id = 'wiAfterTop'; h.scrollIntoView({block: 'start'}); })()`);
  await b.mark([['#targetType', '1'], ['.type-field .pf-helper-text', '2'], ['#reviewBody tr[data-pool]', '3']]);
  await between(b, `${out}/ontap_07b_type_change.png`, '#wiPoolsTop', '#wiAfterTop');
  await b.unmark();
  await b.eval(click('#wizCancel'));

  // 4. Jobs: Export CSV and the restores of a group.
  await b.goto(`${base}/?s=${Date.now()}#/jobs`, 2000);
  await b.waitFor(`document.querySelectorAll('#hiList tr[data-id]').length >= 2`, 20000);
  await b.mark([['#hiQ', '1'], ['#hiExportBtn', '2'], ['#hiList a[href^="#/groups/"]', '3'], ['#hiList tr[data-id] td:nth-child(6)', '4']]);
  await b.shot(`${out}/ontap_12_jobs.png`, { selector: '#page-jobs', pad: 0, maxHeight: 900 });
  await b.unmark();

  // 5. Users: activity of one kind between two dates, and its Export CSV.
  await b.goto(`${base}/?s=${Date.now()}#/users`, 2000);
  await b.waitFor(`document.querySelectorAll('#eventList tr').length > 3`, 20000);
  const today = new Date().toISOString().slice(0, 10);
  await b.eval(`(() => { const k = document.querySelector('#evKind'); k.value = 'restore'; k.dispatchEvent(new Event('change'));
    for (const id of ['#evSince', '#evUntil']) { const d = document.querySelector(id); d.value = '${today}'; d.dispatchEvent(new Event('change')); } })()`);
  await b.sleep(1500);
  await b.mark([['#addUserBtn', '1'], ['#evUser', '2'], ['#evKind', '3'], ['#evSince', '4'], ['#evExportBtn', '5'],
                ['#eventList a[href^="#/groups/"]', '6'], ['#eventList td.ev-client', '7']]);
  await b.shot(`${out}/ontap_18_users.png`, { selector: '#page-users', pad: 0, maxHeight: 1700 });
  await b.unmark();
};

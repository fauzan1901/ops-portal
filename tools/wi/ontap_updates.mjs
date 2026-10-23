// ONTAP Restore WI images that changed with the activity log (27 Sep 2026): Jobs list (Target = project, action after the
// restore, Cinder pool) and Users with the filtered activity log. Demo: PORT=8091 ONTAP_TRUSTED_PROXIES=1 ./test_mode.sh
import { BASTION, REMOTE_PC, apiSession, browserSignIn } from './common.mjs';
const base = 'http://localhost:8091';

async function waitJob(call, jobId) {
  for (;;) {
    const d = await call(`/api/jobs/${jobId}`);
    if (d.status !== 'running') return d;
    await new Promise(r => setTimeout(r, 1000));
  }
}

async function restore(session, volumeId, poolSuffix, extra) {
  const p = await session.call('/api/plan', {site: 'DCB', volume_id: volumeId, snapshot: 'hourly.2025-12-17_1905', project_id: ''});
  const plan = await waitJob(session.call, p.job_id);
  if (plan.status !== 'success') throw new Error(`plan failed: ${plan.error}`);
  const pool = plan.result.pools.pools.find(x => x.host.endsWith(poolSuffix)).host;
  const r = await session.call('/api/restore', {plan_job_id: p.job_id, confirm: true, target_pool: pool, schedule_delete: true, ...extra});
  const job = await waitJob(session.call, r.job_id);
  if (job.status !== 'success') throw new Error(`restore failed: ${job.error}`);
}

export default async (b, out) => {
  if (!process.env.WI_CAPTURE_ONLY) await makeData();
  await capture(b, out);
};

async function makeData() {
  // An operator on another computer: extended disk (vdb) to another pool (lun move), attached to vm-02.
  const operator = await apiSession(base, 'operator', 'demo-operator', REMOTE_PC);
  await restore(operator, 'a80a1a07-06b8-489b-a984-b046981f68b9', '_CINDER_16_vol',
                {post_action: 'attach', attach_server_id: '5e000000-0000-4000-8000-000000000002'});
  // The administrator in a Remote Desktop session on the bastion: boot disk (vda) as a new instance.
  const admin = await apiSession(base, 'portaladmin', 'demo-portal-admin', BASTION);
  await restore(admin, '55555555-5555-4555-8555-555555555555', '_CINDER_14_vol',
                {post_action: 'instance', new_instance_name: 'vm-01-restore-20251217-1905'});
  await new Promise(r => setTimeout(r, 1500));   // the finish entries are written right after the jobs end
}

async function capture(b, out) {
  await browserSignIn(b, base, 'ontap_restore_sid', 'portaladmin', 'demo-portal-admin', BASTION);
  await b.goto(`${base}/?s=1#/jobs`, 2000);
  await b.waitFor(`document.querySelectorAll('#hiList tr[data-id]').length >= 2`, 20000);
  await b.sleep(500);
  await b.mark([['#hiQ', '1'], ['#hiList tr[data-id]', '2'], ['#hiList tr[data-id] td:nth-child(6)', '3']]);
  await b.shot(`${out}/ontap_12_jobs.png`, {selector: '#page-jobs', pad: 0, maxHeight: 900});
  await b.unmark();

  await b.goto(`${base}/?s=2#/users`, 2000);
  await b.waitFor(`document.querySelectorAll('#eventList tr').length > 3 && document.querySelector('#eventList a')`, 20000);
  // Filtered on restores: both restores of the demo, from the bastion (RDP) and from another computer.
  await b.eval(`(() => { const k = document.querySelector('#evKind'); k.value = 'restore'; k.dispatchEvent(new Event('change')); })()`);
  await b.waitFor(`[...document.querySelectorAll('#eventList tr')].length === 4`, 20000);
  await b.sleep(500);
  await b.mark([['#addUserBtn', '1'], ['#evUser', '2'], ['#evKind', '3'], ['#eventList a', '4'], ['#eventList td.ev-client', '5']]);
  await b.shot(`${out}/ontap_18_users.png`, {selector: '#page-users', pad: 0, maxHeight: 1600});
  await b.unmark();
}

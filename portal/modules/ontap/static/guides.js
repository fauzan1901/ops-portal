'use strict';
/* Guides of ONTAP Restore, one per page (data-page), and on the Restore page two: the steps Volume, Snapshot and Target
   project, and the Review step (shown while the wizard is on it). Each is built from the page as it is now, with the
   page's own markup functions (Wizard.infoHtml / osHtml / groupPicker / snapshotsView / reviewHtml / afterDetail /
   commandsHtml…, History.rowHtml, Approvals.rowHtml, approveBody) on a copy of the wizard state. The volume of the
   restore guides: the one in the wizard; else the newest check (plan) of this session, from GET /api/guide (jobs that
   already ran); else the volume of the last restore of this site. A guide never starts a job (no plan, no OpenStack
   read, no restore, no check) and never changes the wizard. The player is the portal's (static/guide.js, PortalGuide). */
const {M} = PortalGuide;

const GO = {
  page(name) {
    const copy = M.clone($(`#page-${name}`));
    copy.hidden = false;
    return copy;
  },
  toast(kind, text, key) { return M.key(M.el(`<div class="pg-toast" hidden>${alertBox(kind, esc(text))}</div>`), key); },
  // a step of the wizard in the copy, as Wizard.render shows it (volumes: how many are restored together)
  step(k, volumes = 1) {
    return s => {
      $$('[data-step]', s).forEach(el => { el.hidden = Number(el.dataset.step) !== k; });
      $$('[data-g="wizNav"] button', s).forEach((b, i) => {
        b.classList.toggle('is-current', i === k);
        b.classList.toggle('is-done', i < k);
        b.disabled = i > k;
      });
      $('[data-g="wizBack"]', s).disabled = k === 0;
      $('[data-g="wizNext"]', s).textContent = k < 3 ? 'Next' : volumes > 1 ? `Launch restore of ${volumes} volumes` : 'Launch restore';
    };
  },
  // the wizard with its own state: the page's functions draw it, the wizard of the page is not touched
  shadow(state) {
    return Object.assign(Object.create(Wizard), {step: 0, filter: '', planRunning: false, data: null, os: null, extra: [], snapshot: '',
                                                 plan: null, plans: null}, state);
  },
  // the volume of the guides (see above): {source, data, os, extra, snapshot, project, plan, plans} or null
  async state() {
    const site = Site.current, copy = x => (x == null ? x : structuredClone(x));
    if (Wizard.data && Wizard.data.site === site) {
      const current = Boolean(Wizard.plan) && Wizard.plan.key === Wizard.planKey();
      return {source: 'wizard', data: copy(Wizard.data), os: Wizard.os?.status === 'running' ? null : copy(Wizard.os),
              extra: copy(Wizard.extra), snapshot: Wizard.snapshot, project: Wizard.projectId(),
              plan: current ? copy(Wizard.plan) : null, plans: current ? copy(Wizard.plans) : null};
    }
    const read = async id => {
      try { return {...await api(`${BASE}/api/snapshots?${qs({site, volume_id: id})}`), volume_id: id, site}; } catch (e) { return null; }
    };
    const g = await api(`${BASE}/api/guide?${qs({site})}`).catch(() => ({}));
    const id = g.plan?.params.volume_id || g.volume_info?.volume_id;
    const data = id ? await read(id) : null;
    if (data) {
      const os = g.volume_info && g.volume_info.volume_id === id ? {status: 'success', result: g.volume_info.result} : null;
      const snapshot = data.snapshots.some(x => x.name === g.plan?.params.snapshot) ? g.plan.params.snapshot : data.snapshots[0]?.name || '';
      const plan = g.plan && g.plan.params.snapshot === snapshot ? GO.shadow({}).planFrom(g.plan.job_id, '', g.plan.result) : null;
      return {source: 'check', data, os, extra: [], snapshot, project: g.plan?.params.project_id || '', plan, plans: null};
    }
    const last = ((await api(`${BASE}/api/history?${qs({limit: 20, site})}`)).items || []).find(x => x.site === site && UUID.test(x.volume_id || ''));
    const before = last ? await read(last.volume_id) : null;
    return before ? {source: 'restore', data: before, os: null, extra: [], snapshot: before.snapshots[0]?.name || '', project: '', plan: null, plans: null} : null;
  },
  // the Review step as the check left it: no pool chosen, only moved to the project, default names
  fresh(st) {
    const w = GO.shadow({...st, step: 3});
    if (st.plans) {
      w.plans.forEach(pl => { pl.pool = ''; pl.type = pl.result.volume.type || ''; pl.name = pl.result.default_new_name; });
      const ni = w.plan.result.after_restore?.new_instance || {};
      Object.assign(w.plan, {action: 'none', attachId: '', instanceName: ni.default_name || '', portNets: w.defaultPortNets(ni), scheduleDelete: true});
    } else {
      w.plan = w.planFrom(st.plan.jobId, st.plan.key, st.plan.result);
    }
    return w;
  },
};

const GUIDES = {
  // ---------------------------------------------------------------- Restore: Volume, Snapshot, Target project
  restore: {
    title: 'restore a volume: volume, snapshot and project',
    when: () => Wizard.step !== 3,
    async build() {
      const site = Site.current;
      if (!site || !Site.info(site).configured) return null;
      const st = await GO.state();
      const copy = GO.page('restore');
      GO.step(0)(copy);
      $('[data-g="volumeId"]', copy).value = '';
      ['volumeInfo', 'osInfo', 'reviewBody', 'snapList', 'snapFilter', 'snapCount'].forEach(k => { $(`[data-g="${k}"]`, copy).innerHTML = ''; });
      $('[data-g="projectId"]', copy).value = '';
      $('[data-g="wizHint"]', copy).textContent = 'Find the volume LUN first.';
      $('[data-g="wizNext"]', copy).disabled = true;
      $('[data-g="siteWarning"]', copy).innerHTML = '';
      const scenes = [];
      if (!st) {
        scenes.push({title: 'The volume ID', text: 'The OpenStack volume ID (openstack volume list, or Horizon). In ONTAP the volume is LUN <span class="mono">volume-&lt;ID&gt;</span>.',
          do: [['move', 'volumeId'], ['tip', 'volumeId', 'Paste the ID, then Find LUN']]});
        scenes.push({title: 'Snapshot, project, review', text: 'Then the snapshot of the FlexVol, the target project (empty = the original one), and a review that Ansible checks before the restore can run.',
          do: [['untip'], ['move', 'wizNav'], ['tip', 'wizNav', 'Volume → Snapshot → Target project → Review']]});
        return {html: copy.outerHTML, scenes};
      }
      const one = GO.shadow({...st, extra: []}), all = GO.shadow(st), volumes = st.extra.length + 1;
      scenes.push({title: 'Find the volume', text: 'Paste the OpenStack volume ID and <b>Find LUN</b>: the portal reads its LUN, FlexVol and the FlexVol snapshots from ONTAP, and at the same time the volume and its instance from OpenStack.',
        do: [['type', 'volumeId', st.data.volume_id], ['click', 'findBtn'],
          ['set', 'volumeInfo', M.frag('<p class="pf-text-secondary pf-mt-md"><span class="pf-spinner"></span> Reading the LUN and snapshots from ONTAP…</p>')],
          ['set', 'osInfo', M.frag(GO.shadow({os: {status: 'running'}}).osHtml())], ['wait', 1100],
          ['set', 'volumeInfo', M.frag(one.infoHtml(st.data))], ['set', 'wizHint', ''], ['attr', 'wizNext', 'disabled', null],
          ['tip', '@[data-g="volumeInfo"] .pf-alert', 'LUN, SVM, FlexVol, sizes, free space of the FlexVol and its snapshots']]});
      const os = st.os?.status === 'success' ? st.os.result : null;
      if (os) {
        scenes.push({title: 'The volume in OpenStack', text: 'The volume (size, status, type, Cinder pool), its role — boot disk or extended disk — and the instance it is attached to: flavor, network interfaces and its volumes.',
          do: [['untip'], ['set', 'osInfo', M.frag(one.osHtml())], ['move', '@[data-g="osInfo"] .pf-label'],
            ['tip', '@[data-g="osInfo"] .pf-label', os.instance?.id ? `Attached to ${esc(os.instance.name)}: its details follow below` : 'Not attached to an instance']]});
      } else {
        scenes.push({title: 'The volume in OpenStack', text: 'At the same time the portal reads the volume, its role (boot disk or extended disk) and its instance from OpenStack (10–60 seconds).',
          do: [['untip'], ['move', 'osInfo'], ['tip', 'osInfo', st.os?.status === 'failed' ? 'Not read now: the Review step checks OpenStack again' : 'Flavor, network interfaces and volumes of the instance appear here']]});
      }
      const others = (os?.instance?.volumes || []).filter(v => !v.this && UUID.test(String(v.id)));
      if (others.length) {
        const group = st.extra.length > 0;
        const v = group ? st.extra[0] : others[0];
        const box = `@[data-g="groupPick"] input[value="${v.id}"]`;
        const ticked = GO.shadow({...st, extra: [{id: v.id, device: v.device || '', role: v.role || '', status: 'loading', data: null, error: ''}]});
        scenes.push({title: `More volumes of ${os.instance.name}`, text: `The other disks of ${esc(os.instance.name)} can be restored with it: from the same snapshot time, into the same project, one volume after the other. `
            + 'Ticked, its LUN is read from ONTAP too; with the boot disk included, the Review step offers a new instance that gets all the new volumes.',
          do: [['untip'], ['move', '@[data-g="groupPick"] .group-pick'], ['click', box],
            ['set', 'groupPick', M.frag(group ? all.groupPicker() : ticked.groupPicker())],
            ['tip', `@[data-g="groupPick"] tr:has(input[value="${v.id}"])`, group ? `${volumes} volumes restored together` : `${esc(v.device || 'This disk')} too: same snapshot, same project`],
            ...(group ? [] : [['wait', 1400], ['click', box], ['set', 'groupPick', M.frag(one.groupPicker())],
              ['tip', '@[data-g="groupPick"] .group-pick', 'Not ticked: only this volume (this guide goes on with one)']])]});
      }
      const shown = GO.shadow({...(st.extra.length ? st : {...st, extra: []}), snapshot: ''}).snapshotsView(8);
      const rowsView = GO.shadow({...st, snapshot: st.snapshot}).snapshotsView(8);
      const pick = (st.extra.length ? all : one).commonSnapshots().find(x => x.name === st.snapshot) || (st.extra.length ? all : one).commonSnapshots()[0];
      if (pick) {
        const row = `@[data-g="snapList"] tr[data-snap="${pick.name}"]`;
        scenes.push({title: 'Choose the snapshot', text: `The snapshots of the FlexVol${volumes > 1 ? ` that exist for all ${volumes} volumes` : ''}, newest first, grouped per day; the buttons keep one schedule (hourly, daily…).`,
          do: [['untip'], ['click', 'wizNext'], ['do', GO.step(1, volumes)], ['set', 'snapFilter', M.frag(all.filterHtml())],
            ['set', 'snapCount', shown.count], ['set', 'snapList', M.rows(rowsView.rows.replace(/ is-selected/g, '').replace(/ checked/g, ''))],
            ['set', 'wizHint', 'Select a snapshot.'], ['attr', 'wizNext', 'disabled', ''], ['tip', 'snapFilter', 'One schedule only'], ['untip'],
            ['click', row], ['cls', row, 'is-selected'], ['check', `${row} input`], ['set', 'wizHint', `Selected: ${pick.local_time}`], ['attr', 'wizNext', 'disabled', null]]});
      }
      scenes.push({title: 'Target project', text: 'The new volume is moved to this project with a volume transfer after <span class="mono">cinder manage</span>; empty = the project of the original volume.',
        do: [['untip'], ['click', 'wizNext'], ['do', GO.step(2, volumes)], ['set', 'wizHint', ''],
          st.project ? ['type', 'projectId', st.project] : ['move', 'projectId'], ['tip', 'projectId', st.project ? 'The project the new volume goes to' : 'Empty: the original project']]});
      scenes.push({title: 'Next: the check', text: '<b>Next</b> opens Review: Ansible checks every prerequisite on ONTAP and OpenStack (read-only, 10–60 seconds). '
          + 'The guide of the Review step then appears under the wizard: Cinder pool, after the restore (also a new instance), commands and launch.',
        do: [['untip'], ['click', 'wizNext'], ['do', GO.step(3, volumes)],
          ['set', 'reviewBody', M.frag(one.checkingHtml(volumes > 1 ? `Running playbook plan.yml for ${volumes} volumes…` : 'Running playbook plan.yml…'))],
          ['set', 'wizHint', 'Checking prerequisites…'], ['attr', 'wizNext', 'disabled', ''], ['tip', '@[data-g="reviewBody"] .pf-empty-state', 'Then: Guide — review and launch the restore']]});
      return {html: copy.outerHTML, scenes};
    },
  },

  // ---------------------------------------------------------------- Restore: the Review step
  review: {
    title: 'review and launch the restore',
    page: 'restore',
    width: 1000,
    when: () => Wizard.step === 3,
    async build() {
      const site = Site.current;
      if (!site || !Wizard.data || Wizard.data.site !== site) return null;
      const st = await GO.state();
      const volumes = st.extra.length + 1, group = volumes > 1;
      const copy = GO.page('restore');
      GO.step(3, volumes)(copy);
      $('[data-g="siteWarning"]', copy).innerHTML = '';
      $('[data-g="reviewBody"]', copy).innerHTML = '';
      $('[data-g="wizNext"]', copy).disabled = true;
      const html = copy.outerHTML;
      if (!st.plan || (group && !st.plans)) {   // the check runs, or it failed: the step as it is now
        const now = M.frag($('#reviewBody').innerHTML);
        const running = Wizard.planRunning;
        return {html, scenes: [{title: running ? 'The check is running' : 'The check failed', text: running
            ? 'Ansible checks every prerequisite (read-only). Open this guide again when the check is done: it then shows the Cinder pool, the action after the restore, the commands and the launch.'
            : 'The check did not finish: the error is shown, with the Ansible output. Fix the cause, then <b>Check again</b>.',
          do: [['set', 'reviewBody', now], ['set', 'wizHint', Wizard.hint()], ['move', 'reviewBody'],
            ['tip', running ? '@[data-g="reviewBody"] .pf-empty-state' : '@[data-g="reviewBody"] .pf-alert', running ? 'plan.yml, read-only' : 'Why the check failed']]}]};
      }
      const w = GO.fresh(st);
      const body = () => M.frag(group ? w.groupReviewHtml() : w.reviewHtml());
      const cmds = () => M.frag(w.commandsHtml());
      const plans = group ? w.runOrder() : [w.plan];
      const notReady = plans.filter(pl => !pl.result.ready);
      const scenes = [];
      scenes.push({title: 'The check', text: `When Review opens, Ansible (plan.yml) checks every prerequisite${group ? ` of the ${volumes} volumes` : ''} read-only: the volume, its project, the LUN and FlexVol, the snapshot, the Cinder pools and the target project.`,
        do: [['set', 'reviewBody', M.frag(w.checkingHtml(group ? `Running playbook plan.yml for ${volumes} volumes…` : 'Running playbook plan.yml…'))],
          ['set', 'wizHint', 'Checking prerequisites…'], ['wait', 1300], ['set', 'reviewBody', body()], ['set', 'reviewCmds', cmds()], ['set', 'wizHint', w.hint()],
          ...(notReady.length
            ? [['tip', '@[data-g="reviewBody"] .pf-alert', 'Not met: fix it, then Check again']]
            : group ? [['move', '@[data-g="reviewBody"] .pf-table-wrap'], ['tip', '@[data-g="reviewBody"] .pf-table-wrap', 'Each volume: its prerequisites, Cinder pool and new name']]
            : [['move', '@[data-g="reviewBody"] .pf-checks'], ['tip', '@[data-g="reviewBody"] .pf-checks', 'Read from ONTAP and OpenStack: nothing was changed']])]});
      if (notReady.length) {
        scenes.push({title: 'Check again', text: 'The restore cannot run while a prerequisite is not met. Fix it (for example detach or free space), then <b>Check again</b>.',
          do: [['untip'], ['move', 'recheckBtn'], ['tip', 'recheckBtn', 'Runs the check again']]});
        return {html, scenes};
      }
      if (!group) {
        scenes.push({title: 'Source and result', text: 'From which LUN and snapshot, to which restored LUN, Cinder pool and project; a volume transfer moves it to another project.',
          do: [['untip'], ['move', '@[data-g="reviewBody"] .pf-dl'], ['tip', '@[data-g="reviewBody"] .pf-dl', 'The source volume and the snapshot']]});
      }
      // the Cinder pool of each volume: the pool of the LUN when it can take it (no lun move), else the first that can
      const poolDo = [];
      plans.forEach(pl => {
        const pools = w.pools(pl).pools, p = pools.find(x => x.current && x.selectable) || pools.find(x => x.selectable);
        if (!p) return;
        const i = group ? w.plans.indexOf(pl) : null;
        const row = `@[data-g="reviewBody"] tr[data-pool="${p.host}"]${group ? `[data-plan="${i}"]` : ''}`;
        pl.pool = p.host;
        poolDo.push(['click', row], ['cls', row, 'is-selected'], ['check', `${row} input`],
          group ? ['set', `@[data-pool-summary="${i}"]`, M.frag(w.poolSummary(pl))] : ['set', 'poolSummary', M.frag(w.poolSummary(pl))]);
      });
      poolDo.push(['set', 'reviewCmds', cmds()], ['set', 'wizHint', w.hint()]);
      const typed = (w.plan.result.type_options || []).length > 1;
      scenes.push({title: 'Volume type and Cinder pool', text: `Nothing is selected for you: choose the Cinder pool${group ? ' of each volume' : ''}. The pool of the LUN needs no lun move; another pool of the same SVM is reached with lun move (used data only). `
          + (typed ? 'Another volume type changes the tier: its pools are listed.' : 'A pool that is full or offline cannot be chosen.'),
        do: [['untip'], ['move', '@[data-g="reviewBody"] .pool-table'],
          ...(typed ? [['tip', '@[data-g="reviewBody"] select[data-g^="targetType"], [data-g="reviewBody"] [data-type-for]', 'Same type as the original by default']] : []),
          ['tip', '@[data-g="reviewBody"] .pool-table', 'Used against the capacity; full at the limit of the site'], ['untip'], ...poolDo]});
      // after the restore: only move, attach to an instance, or (boot disk) a new instance
      const a = w.after(), ni = a.new_instance || {}, role = w.plan.result.role?.role;
      const card = v => `@[data-g="reviewBody"] .pf-radio-card:has(input[value="${v}"])`;
      const cards = role === 'boot' ? ['none', 'attach', 'instance'] : ['none', 'attach'];
      const choose = v => [['click', `${card(v)} input`], ...cards.map(x => ['cls', card(x), 'is-selected', x === v])];
      scenes.push({title: 'After the restore', text: `By default the new volume${group ? 's are' : ' is'} only moved to the target project. ${role === 'boot' ? 'For this boot disk there are two more choices: attach to an instance, or a new instance like the original.' : 'It can also be attached to an instance of that project.'}`,
        do: [['untip'], ['move', '@[data-g="reviewBody"] .pf-radio-cards'], ['tip', '@[data-g="reviewBody"] .pf-radio-cards', 'One choice; the commands follow it']]});
      const server = a.servers.find(x => x.attachable) || a.servers[0];
      w.plan.action = 'attach';
      const attachEmpty = M.frag(w.afterDetail());
      w.plan.attachId = server ? server.id : '';
      const attachDone = M.frag(w.afterDetail()), attachCmds = cmds();
      scenes.push({title: 'Attach to an instance', text: `Enter the ID of an instance in the target project (the list offers them); the volume${group ? 's are' : ' is'} attached after the transfer. The instance of the original volume gets a warning: same filesystem UUIDs.`,
        do: [['untip'], ...choose('attach'), ['set', 'afterDetail', attachEmpty],
          ...(server ? [['type', 'attachId', server.id], ['set', 'afterDetail', attachDone], ['set', 'reviewCmds', attachCmds],
            ['tip', 'attachHelp', `${esc(server.name)} · ${esc(server.status)}`]] : [['tip', 'attachId', 'No instance in the target project was read']])]});
      if (role === 'boot') {
        if (ni.possible) {
          w.plan.action = 'instance';
          w.plan.attachId = '';
          const detail = M.frag(w.afterDetail()), instCmds = cmds();
          const port = (ni.ports || [])[0];
          scenes.push({title: 'Create a new instance', text: `A new instance like ${esc(ni.source_name || 'the original')}: same flavor and availability zone, booting from the new volume${group ? ', with the other new volumes attached' : ''}. `
              + 'Its name is filled in; each network interface gets a new port (new IP) on the original network, or on a network of the target project you choose.',
            do: [['untip'], ...choose('instance'), ['set', 'afterDetail', detail], ['set', 'reviewCmds', instCmds],
              ['move', 'instanceName'], ['tip', 'instanceName', 'The name of the new instance'], ['untip'],
              ['move', '@[data-g="afterDetail"] .pf-dl'], ['tip', '@[data-g="afterDetail"] .pf-dl', 'Copied from the original: flavor, zone, properties'], ['untip'],
              ...(port ? [['move', '@[data-g="afterDetail"] .pf-table-wrap'], ['tip', '@[data-g="afterDetail"] .pf-table-wrap', ni.networks_read ? 'The network of each interface: choose it here' : 'Each interface: a new port, a new IP']] : []),
              ['untip'], ['move', '@[data-g="afterDetail"] .pf-alert'], ['tip', '@[data-g="afterDetail"] .pf-alert:last-child', 'Read before launching']]});
        } else {
          scenes.push({title: 'Create a new instance', text: `For a boot disk the portal can create a new instance like the original; here it is not possible: ${esc(ni.reason || 'see the reason')}.`,
            do: [['untip'], ['move', card('instance')], ['tip', card('instance'), 'Not possible for this volume']]});
        }
      } else {
        scenes.push({title: 'A new instance (boot disk)', text: 'When the restored volume is a boot disk (vda), a third choice appears: <b>Create a new instance like</b> the original, with the same flavor, network interfaces and security groups. '
            + 'Restore the boot disk with the other disks (Volume step) to get one instance with all the new volumes.',
          do: [['untip'], ['move', '@[data-g="reviewBody"] .pf-radio-cards'], ['tip', '@[data-g="reviewBody"] .pf-radio-cards', 'Only with the boot disk']]});
      }
      scenes.push({title: 'The commands', text: 'Exactly what runs, in order, following your choices: restore-file, lun move (another pool), cinder manage, the transfer and the action after the restore.',
        do: [['untip'], ['move', 'reviewCmds'], ['tip', 'reviewCmds', 'Shown before anything runs']]});
      const names = group ? '@[data-g="reviewBody"] [data-name-for]' : 'newName';
      scenes.push({title: 'Name, deletion of the original, launch', text: `The new volume name is filled in${group ? ' for each volume' : ''}. By default an administrator is asked to approve deleting the original volume${group ? 's' : ''} after ${esc(w.plan.result.delete_after_hours || 72)} hours (menu Approvals); `
          + 'nothing is deleted without it. Tick the confirmation, then <b>Launch restore</b>: the job opens in Jobs.',
        do: [['untip'], ['move', names], ['tip', names, 'Letters, digits, _ . : -'], ['untip'], ['move', 'scheduleDelete'],
          ['tip', 'scheduleDelete', 'An administrator approves it later'], ['untip'], ['check', 'reviewAck'], ['set', 'wizHint', ''], ['attr', 'wizNext', 'disabled', null],
          ['move', 'wizNext'], ['tip', 'wizNext', 'The job: progress and full output']]});
      return {html, scenes};
    },
  },

  // ---------------------------------------------------------------- Jobs
  jobs: {
    title: 'find a restore',
    async build() {
      const items = History.items.length ? History.items : ((await api(`${BASE}/api/history?${qs({limit: 20})}`)).items || []);
      const copy = GO.page('jobs');
      $('[data-g="hiList"]', copy).innerHTML = M.rows(items.slice(0, 6).map(x => History.rowHtml(x)).join(''))
        || M.rows(`<tr><td colspan="8"><div class="pf-empty-state">${icon('cubes')}<h2 class="pf-title">No restores yet</h2><span>Restores launched from this app are listed here.</span></div></td></tr>`);
      $('[data-g="hiQ"]', copy).value = '';
      const scenes = [{title: 'Every restore', text: 'Each restore by every user and site, recorded before it runs: the volume, status, snapshot, target project and who ran it.',
        do: [['move', 'hiList'], ['tip', '@[data-g="hiList"] tr', 'A running restore updates by itself']]}];
      const x = items[0];
      if (x) {
        const word = String(x.volume_name || x.volume_id).split(/[-_ ]/)[0];
        scenes.push({title: 'Search and filter', text: 'Search by volume ID or name, project or snapshot; filter by user, site and status.',
          do: [['untip'], ['type', 'hiQ', word], ['pick', 'hiStatus', 'Successful']]});
        scenes.push({title: 'Open a restore', text: 'A row opens the job: its steps, the details and the full Ansible output; a restore of several volumes opens its group.',
          do: [['click', `@[data-g="hiList"] tr[data-id="${x.id}"] td`], ['tip', `@[data-g="hiList"] tr[data-id="${x.id}"]`, `Opens job #${x.id}`]]});
      }
      scenes.push({title: 'Export', text: '<b>Export CSV</b> saves the jobs of the filter.', do: [['untip'], ['move', 'hiExportBtn'], ['tip', 'hiExportBtn', 'jobs.csv']]});
      return {html: copy.outerHTML, scenes};
    },
  },

  // ---------------------------------------------------------------- one job
  job: {
    title: 'follow a restore',
    build() {
      if (!$('#jobTitle').textContent.trim()) return null;
      const copy = GO.page('job');
      M.keep(copy, '[data-g="jobLog"] > *', 30);
      const scenes = [
        {title: 'Its status', text: 'The status of the restore, and at the top the result or the error, with what to do next.',
          do: [['move', 'jobStatus'], ...($('#jobOutcome').innerHTML.trim() ? [['tip', 'jobOutcome', 'The result of the restore']] : [])]},
        {title: 'Details', text: 'Volume, snapshot, new volume, project, Cinder pool and the action after the restore.',
          do: [['untip'], ['move', 'jobDetail']]},
        {title: 'Progress', text: 'Each step of the restore (ONTAP restore-file, cinder manage, transfer…): done, running or failed.',
          do: [['move', 'jobSteps'], ['tip', 'jobSteps', 'Updated while it runs; you may leave the page']]},
        {title: 'The full output', text: 'Every Ansible task with its result, the same as in the job file on the server.',
          do: [['untip'], ['move', 'jobLog']]},
      ];
      return {html: copy.outerHTML, scenes};
    },
  },

  // ---------------------------------------------------------------- a group of volumes
  group: {
    title: 'follow a restore of several volumes',
    build() {
      if (!$('#groupTitle').textContent.trim()) return null;
      const copy = GO.page('group');
      const scenes = [
        {title: 'The volumes of one instance', text: 'The volumes of an instance restored from the same snapshot, one restore (job) after the other.',
          do: [['move', 'groupList'], ['tip', '@[data-g="groupList"] tr', 'Device, source volume, new volume, status and its job']]},
        {title: 'Details', text: 'The snapshot, the project and what happens after the restore (for example a new instance with the restored disks).',
          do: [['untip'], ['move', 'groupDetail']]},
      ];
      return {html: copy.outerHTML, scenes};
    },
  },

  // ---------------------------------------------------------------- Approvals
  approvals: {
    title: 'decide on the original volumes',
    async build() {
      const items = Approvals.items.length ? Approvals.items : ((await api(`${BASE}/api/deletions?view=open`)).items || []);
      const admin = Session.isAdmin();
      const copy = GO.page('approvals');
      $('[data-g="apList"]', copy).innerHTML = M.rows(items.slice(0, 5).map(d => Approvals.rowHtml(d, admin)).join(''))
        || M.rows(`<tr><td colspan="6"><div class="pf-empty-state">${icon('check-circle')}<h2 class="pf-title">Nothing here</h2>`
          + '<span>Original volumes appear here when a restore schedules them for deletion (Review step).</span></div></td></tr>');
      const scenes = [{title: 'What waits for a decision', text: 'The original volumes of restores that were scheduled for deletion; nothing is deleted automatically. <b>Needs a decision</b> keeps the ones that are due.',
        do: [['click', '@[data-g="apView"] input[value="awaiting"]'], ['check', '@[data-g="apView"] input[value="awaiting"]'], ['move', 'apList']]}];
      const d = items.find(x => x.check_result && ['awaiting', 'failed'].includes(x.state)) || items.find(x => x.check_result) || items[0];
      if (!d) return {html: copy.outerHTML, scenes};
      const result = Approvals.checks[d.id]?.result || (d.check_result ? safeJson(d.check_result) : null);
      scenes.push({title: 'Check', text: 'Check reads the volume in OpenStack and its LUN in NetApp now (read-only): project, status, attachments, Cinder snapshots, LUN.',
        do: [['click', `@[data-g="apList"] [data-act="check"][data-id="${d.id}"]`], ...(result ? [['tip', `@[data-g="apList"] tr:has([data-id="${d.id}"]) .ap-check`, 'The last check, with every point']] : [])]});
      const overlay = [];
      if (admin && result && !result.error && ['awaiting', 'failed'].includes(d.state)) {
        const dlg = M.dialog('#approveDialog');
        $('[data-g="approveTitle"]', dlg).textContent = `Delete original volume ${d.volume_name || d.volume_id}?`;
        $('[data-g="approveBody"]', dlg).innerHTML = M.frag(approveBody(d, result));
        const n = (result.snapshots || []).length;
        $('[data-g="approveFooter"]', dlg).innerHTML = M.frag([
          result.can_delete ? `<button type="button" class="pf-btn pf-m-danger" value="delete">${n ? `Delete ${n} snapshot${n > 1 ? 's' : ''} and the volume` : 'Delete volume'}</button>` : '',
          result.can_detach ? '<button type="button" class="pf-btn pf-m-danger" value="detach">Detach and delete</button>' : '',
          result.gone ? '<button type="button" class="pf-btn pf-m-primary" value="gone">Close as already deleted</button>' : '',
          '<button type="button" class="pf-btn pf-m-link" value="cancel">Cancel</button>'].join(''));
        overlay.push(dlg);
        scenes.push({title: 'Approve', text: `<b>Approve…</b> checks again and shows what will be done. ${n ? `This volume has ${n} Cinder snapshot${n > 1 ? 's' : ''}: they are deleted first, then the volume. ` : ''}`
            + 'An attached data disk is detached first; a boot disk only with its instance (its name typed). Never --force or --cascade.',
          do: [['untip'], ['click', `@[data-g="apList"] [data-act="approve"][data-id="${d.id}"]`], ['show', 'approveDialog'],
            ...(n ? [['tip', '@[data-g="approveBody"] dl dd:last-of-type', 'Deleted first, one by one, then the volume']] : [['move', 'approveBody']]),
            ['wait', 1600], ['untip'], ['move', '@[data-g="approveFooter"] button'], ['hide', 'approveDialog']]});
      }
      if (admin && items.slice(0, 5).some(x => ['scheduled', 'awaiting', 'failed'].includes(x.state))) {
        scenes.push({title: 'Or keep it, or later', text: '<b>Postpone</b> moves the due time by 1, 3 or 7 days; <b>Keep volume</b> takes it off the list without deleting it. Every decision is recorded.',
          do: [['untip'], ['move', `@[data-g="apList"] [data-act="postpone"]`], ['move', `@[data-g="apList"] [data-act="keep"]`]]});
      }
      return {html: copy.outerHTML, overlay, scenes};
    },
  },
};

PortalGuide.mount(GUIDES, {page: name => document.querySelector(`[data-page="${name}"]`)});

'use strict';
/* Guides of Operation Automation, one per page (data-page): each built from the page as it is now, with the page's own
   functions and dialogs. The player is the portal's (static/guide.js, PortalGuide). */
const {M} = PortalGuide;

const GH = {
  toast(kind, text, key) { return M.key(M.el(`<div class="pg-toast" hidden>${alertBox(kind, esc(text))}</div>`), key); },
  visible(el) { return !!el && !el.hidden && !el.closest('[hidden]'); },
  // an example for an empty field of a check: its own "e.g." (placeholder or help), else one of its type
  example(p, input) {
    const eg = s => (/e\.g\.\s*([^,;\s]+)/.exec(String(s || '')) || [])[1];
    const own = eg(input?.getAttribute('placeholder')) || eg(p.help);
    if (own) return own.replace(/[.)]+$/, '');
    return {port: '80', int: String(p.min ?? 1), ip: '10.249.1.20', ip_list: '10.249.1.20', cidr: '10.249.1.0/24', ip_port: '10.249.1.20:443',
      uuid: 'a80a1a07-06b8-489b-a984-b046981f68b9'}[p.type] || '';
  },
  me() { return Session.user?.username || 'you'; },
  now() { return new Date().toISOString(); },
  admin(scenes) {
    if (!Session.admin || !GH.visible($(`[data-page="${Router.page}"] [data-create-template]`))) return;
    scenes.push({title: 'Make your own check', text: 'Administrators: <b>Create template</b> adds a check made of your own commands, without writing Ansible.',
      do: [['untip'], ['move', '@[data-create-template]'], ['tip', '@[data-create-template]', 'A form, step by step: its page has its own guide']]});
  },
};

const GUIDES = {
  // ---------------------------------------------------------------- All checks
  checks: {
    title: 'find the right check',
    width: 1140,   // with the menu on the left
    build() {
      const data = Catalog.data;
      if (!data) return null;
      const site = Site.current;
      const page = $('#page-checks');
      const mast = M.el(`<div class="pg-mast"><span class="pg-brand">${icon('checklist')}Operation Automation</span></div>`);
      mast.append(M.clone($('#siteSwitch')));
      const nav = M.clone($('#sidebar .pf-nav'));
      $$('[data-g="navSites"], .admin-only', nav).forEach(x => x.remove());
      M.keep(nav, '[data-g="navProducts"] li', 6);
      $$('.pf-nav__link', nav).forEach(a => a.classList.toggle('is-current', a.dataset.route === 'checks'));
      const head = M.clone($('section.pf-m-light', page));
      // a word that finds a few checks, and those checks drawn as the search draws them
      const found = q => data.checks.filter(c => Catalog.matches(c, q.toLowerCase()));
      const q = ['nginx', 'certificate', 'disk', 'port', 'quota', 'volume'].find(w => found(w).length && found(w).length <= 8)
        || data.checks[0]?.title.split(/\s+/).find(w => w.length > 3) || 'check';
      const shown = found(q);
      const results = M.clone($('#ovResults'));
      results.hidden = true;
      $('[data-g="ovShown"]', results).textContent = `${shown.length} check${shown.length === 1 ? '' : 's'}`;
      $('[data-g="ovList"]', results).innerHTML = M.frag(Catalog.listHtml(shown.slice(0, 3), ['product', 'type', 'last'], 'Search results'));
      $$('tr.ck-detail', results).forEach(x => { x.hidden = true; });
      const recent = GH.visible($('#ovRecent')) && $$('#ovRecentList tr').length ? M.clone($('#ovRecent')) : null;
      if (recent) M.keep(recent, 'tbody tr', 2);
      const symptoms = M.clone($('#ovSymptoms'));
      M.keep(symptoms, '.ov-symptom', 4);
      $$('.ov-symptom', symptoms).forEach(card => M.keep(card, 'li', 3));
      const html = mast.outerHTML + '<div class="pg-shell">'
        + `<aside class="pf-sidebar pg-sidebar">${nav.outerHTML}</aside><div class="pg-main">${head.outerHTML}`
        + `<section class="pf-page__section">${results.outerHTML}${recent ? recent.outerHTML : ''}`
        + `<h2 class="ov-heading">What is the problem?</h2>${symptoms.outerHTML}</section></div></div>`;
      const others = Site.list.map(s => s.name).filter(n => n !== site);
      const siteTo = name => s => $$('.site-name-current', s).forEach(x => { x.textContent = name; });
      const radio = name => `@.pg-mast input[value="${name}"]`;
      const first = data.checks.find(c => c.id === $('tr.ck-row', results)?.dataset.check);   // the first row as drawn
      const act = (data.activities || []).find(a => data.checks.some(c => c.activity === a.id));
      const cat = data.categories.find(c => data.checks.some(x => x.category === c.id));
      const scenes = [];
      scenes.push(others.length
        ? {title: 'Choose the site first', text: `Every check runs on the site chosen in the masthead (${Site.list.map(s => esc(s.name)).join(', ')}). What can run, and the runs, follow it.`,
          do: [['check', radio(others[0])], ['do', siteTo(others[0])], ['tip', radio(others[0]), `The checks now run on <b>${esc(others[0])}</b>`],
            ['wait', 1100], ['untip'], ['check', radio(site)], ['do', siteTo(site)]]}
        : {title: 'The site', text: `Every check runs on the site chosen in the masthead, here <b>${esc(site)}</b>.`,
          do: [['move', radio(site)], ['tip', radio(site), `The checks run on <b>${esc(site)}</b>`]]});
      if (first) {
        const runs = first.status === 'ready' && first.access.runnable;
        scenes.push({title: 'Search with what you see', text: 'Type an alert name, a word of the problem, a service or a WI title: the checks that match show at once, with what they can do.',
          do: [['untip'], ['type', 'ovQ', q], ['show', 'ovResults'],
            ['tip', `@[data-g="ovResults"] tr.ck-row .ck-name a`, runs ? `The name opens the check; ▶ runs it on <b>${esc(site)}</b>` : 'The name opens the check; the button on the right says why it cannot run here']]});
      }
      scenes.push({title: 'Or start from the problem', text: 'Under <b>What is the problem?</b> the checks are grouped by what a customer reports: a link opens the check.',
        do: [['untip'], ...(first ? [['type', 'ovQ', ''], ['hide', 'ovResults']] : []), ['move', '@[data-g="ovSymptoms"] .ov-symptom'],
          ['click', '@[data-g="ovSymptoms"] .ov-symptom li a'], ['tip', '@[data-g="ovSymptoms"] .ov-symptom li a', 'Opens this check, ready to run']]});
      if (recent) {
        scenes.push({title: 'Pick up a recent problem', text: `<b>Recent problems on ${esc(site)}</b> lists the last runs that found something: a row opens its result.`,
          do: [['untip'], ['click', '@[data-g="ovRecentList"] tr'], ['tip', '@[data-g="ovRecentList"] tr', 'Opens the result of that run']]});
      }
      if (act && cat) {
        const link = route => `@.pg-sidebar [data-route="${route}"]`;
        scenes.push({title: 'Browse by activity or product', text: 'The menu on the left lists the checks per activity and per product, with their number.',
          do: [['untip'], ['click', link(`activity:${act.id}`)], ['tip', link(`activity:${act.id}`), `Every check of <b>${esc(act.short || act.title)}</b>`],
            ['wait', 1100], ['click', link(`product:${cat.id}`)], ['tip', link(`product:${cat.id}`), `Every check of <b>${esc(cat.short || cat.title)}</b>`]]});
      }
      GH.admin(scenes);
      return {html, scenes};
    },
  },

  // ---------------------------------------------------------------- the checks of a product or an activity
  product: {
    title: 'pick and run a check from the list',
    build() {
      const data = Catalog.data;
      if (!data || !Catalog.id) return null;
      const site = Site.current;
      const all = Catalog.inScope();
      const rows = Catalog.ordered(all, Catalog.mode === 'activity' ? 'category' : 'activity').slice(0, 4);
      if (!rows.length) return null;
      const page = $('#page-product');
      const head = M.clone($('section.pf-m-light', page));
      const card = M.clone($('section:not(.pf-m-light) .pf-card', page));
      $('[data-g="ckList"]', card).innerHTML = M.frag(Catalog.listHtml(rows, Catalog.mode === 'activity' ? ['product', 'type', 'last'] : ['type', 'last'], 'Checks'));
      $$('tr.ck-detail', card).forEach(x => { x.hidden = true; });
      $$('tr.ck-row', card).forEach(x => x.classList.remove('is-expanded'));
      $$('[data-toggle], [data-expand-all]', card).forEach(x => x.setAttribute('aria-expanded', 'false'));
      const count = n => `${n} of ${all.length} · ${Catalog.counts(all).runnable} runnable on ${site}`;
      $('[data-g="ckShown"]', card).textContent = count(all.length);
      const html = head.outerHTML + `<section class="pf-page__section">${card.outerHTML}</section>`;
      // the row the guide follows: the first that runs here; the filters keep it
      const target = rows.find(c => c.status === 'ready' && c.access.runnable) || rows[0];
      const filters = [];
      const apply = s => {
        const ok = c => filters.every(f => f(c));
        $$('tr.ck-row', s).forEach(tr => { tr.closest('tbody').hidden = !ok(data.checks.find(x => x.id === tr.dataset.check)); });
        $('[data-g="ckShown"]', s).textContent = count(all.filter(ok).length);
      };
      const scenes = [];
      if (Catalog.mode !== 'activity') {
        const radio = $(`[data-g="ckFilter"] input[value="${target.activity}"]`, card);
        if (radio) {
          scenes.push({title: 'Keep one activity', text: 'The buttons above the table keep the checks of one activity (with their number); the search box filters by any word.',
            do: [['check', `@[data-g="ckFilter"] input[value="${target.activity}"]`], ['do', s => { filters.length = 0; filters.push(c => c.activity === target.activity); apply(s); }]]});
        }
      } else {
        const option = [...$$('[data-g="ckProduct"] option', card)].find(o => o.value === target.category);
        if (option) {
          scenes.push({title: 'Keep one product', text: 'The list above the table keeps the checks of one product; the search box filters by any word.',
            do: [['pick', 'ckProduct', option.text], ['do', s => { filters.length = 0; filters.push(c => c.category === target.category); apply(s); }]]});
        }
      }
      if (target.status === 'ready' && target.access.runnable) {
        scenes.push({title: `Only what runs on ${site}`, text: `<b>Runnable on ${esc(site)}</b> hides what cannot run here: manual WIs, planned checks, and checks without the hosts or accounts they need on this site.`,
          do: [['check', 'ckRunnable'], ['do', s => { if (!scenes.some(x => x.title.startsWith('Keep'))) filters.length = 0; filters.push(c => c.status === 'ready' && c.access.runnable); apply(s); }]]});
      }
      const row = `@tr.ck-row[data-check="${target.id}"]`;
      const can = $(`tr.ck-row[data-check="${target.id}"] .ck-can`, card);
      const action = $(`tr.ck-row[data-check="${target.id}"] .ck-col-action .pf-btn`, card);
      scenes.push({title: 'Open the details', text: 'The arrow (or a click on the row) shows the description, the last runs on this site, the work instructions and what the check reads.',
        do: [['untip'], ['click', `${row} [data-toggle]`], ['attr', `${row} [data-toggle]`, 'aria-expanded', 'true'], ['cls', row, 'is-expanded'], ['show', `ckd-${target.id}`]]});
      if (can) {
        scenes.push({title: 'What it can do', text: '<b>Check only</b> reads. <b>Check + fix</b> also offers a fix that you start yourself. <b>Makes a change</b> changes only after you confirm. <b>Collects files</b> makes a bundle to download. <b>Manual</b> follows the WI.',
          do: [['move', `${row} .ck-can`], ['tip', `${row} .ck-can`, esc(can.title || can.textContent)]]});
      }
      if (action) {
        scenes.push({title: 'Run it', text: `The button at the end of the row opens the page of the check on <b>${esc(site)}</b>, where you choose the host and the values.`,
          do: [['untip'], ['click', `${row} .ck-col-action .pf-btn`], ['tip', `${row} .ck-col-action .pf-btn`, `${esc(action.title)}: next, the page of this check`]]});
      }
      GH.admin(scenes);
      return {html, scenes};
    },
  },

  // ---------------------------------------------------------------- the page of one check: run it
  launch: {
    title: 'run this check',
    build() {
      const c = Launch.check;
      if (!c) return null;
      const site = Site.current;
      const page = $('#page-launch');
      const head = M.clone($('section.pf-m-light', page));
      const main = M.clone($('section:not(.pf-m-light)', page));
      $$('select[data-param]', main).forEach(x => { if (x.options[0]?.value === '') x.selectedIndex = 0; });   // hosts: none chosen yet
      const runnable = c.status === 'ready' && c.access.runnable;
      const scenes = [];
      if (c.status !== 'ready' || !runnable) {
        scenes.push({title: c.status === 'ready' ? `Why it cannot run on ${site}` : 'How this one is done',
          text: 'The box at the top says what is missing on this site (and where to add it), or that this WI is followed by hand.',
          do: [['move', '@[data-g="lnNotice"] .pf-alert'], ['tip', '@[data-g="lnNotice"] .pf-alert', 'Read this first']]});
      }
      if (c.status === 'ready') {
        scenes.push({title: 'Check the site', text: `The check runs on the site of the masthead: the card says <b>${esc(site)}</b> before anything runs.`,
          do: [['untip'], ['move', 'lnSite'], ['tip', 'lnSite', `Runs on <b>${esc(site)}</b>; for another site, change it in the masthead`]]});
        const steps = [];
        for (const p of c.params) {
          const sel = `@[data-param="${p.name}"]`;
          const input = $(`[data-param="${p.name}"]`, main);
          if (p.type === 'host') {
            const h = (c.hosts[p.name] || [])[0];
            steps.push(h ? ['pick', sel, `${h.name} — ${h.address} (${h.group})`]
              : ['tip', sel, 'No host of this kind on this site: an administrator adds it on <b>Hosts &amp; SSH</b>']);
          } else if (p.type === 'uuid_list') {
            steps.push(['type', `@[data-list="${p.name}"] [data-item]`, 'a80a1a07-06b8-489b-a984-b046981f68b9']);
          } else if (p.type === 'select' || String(p.default ?? '') !== '' || !input) {
            steps.push(['move', input ? sel : 'lnParams']);
          } else {
            const value = GH.example(p, input);
            steps.push(value && (p.required || /e\.g\./.test(`${p.help || ''} ${input.getAttribute('placeholder') || ''}`)) ? ['type', sel, value] : ['move', sel]);
          }
        }
        scenes.push(c.params.length
          ? {title: 'Fill in the values', text: `This check asks: ${c.params.map(p => `<b>${esc(p.label)}</b>`).join(', ')}. A * means required; a value already there is its default.`,
            do: [['untip'], ...steps]}
          : {title: 'Nothing to fill in', text: 'This check has no parameters.', do: [['untip'], ['move', 'lnParams']]});
      }
      scenes.push({title: 'Read what it checks', text: '<b>What is checked</b> lists the steps, the work instruction and what the check reads; each step gets OK, Warning or Problem in the result.',
        do: [['untip'], ['move', 'lnAbout'], ['tip', $('#lnAbout ol') ? '@[data-g="lnAbout"] ol' : 'lnAbout', 'The same steps show in the result']]});
      if (GH.visible($('#lnTopoCard'))) {
        scenes.push({title: 'Where it reads', text: 'From the portal to the system it reads, on this site, with read-only accounts: nothing is changed.',
          do: [['untip'], ['move', 'lnTopo'], ['tip', 'lnTopo', 'The path of this check']]});
      }
      if (runnable) {
        scenes.push({title: 'Run', text: 'The result page opens at once and fills in while the check runs; you may leave it and come back from <b>Runs</b>.',
          do: [['untip'], ['move', 'lnHint'], ['click', 'lnRun'], ['cls', 'lnRun', 'is-loading'], ['attr', 'lnRun', 'disabled', ''],
            ['tip', 'lnRun', 'Next: the result page, live']]});
      }
      return {html: head.outerHTML + main.outerHTML, scenes};
    },
  },

  // ---------------------------------------------------------------- the result of a run, and its fix
  run: {
    title: 'read the result and fix what was found',
    build() {
      const r = RunPage.record;
      if (!r) return null;
      const res = r.result || {};
      const steps = res.steps || [];
      const recs = res.recommendations || [];
      const fixes = r.fixes || [];
      const page = $('#page-run');
      const head = M.clone($('section.pf-m-light', page));
      const main = M.el('<section class="pf-page__section"></section>');
      const outcome = M.clone($('#runOutcome'));
      const scenes = [];
      if (r.status === 'running') {   // still running: it fills in by itself
        main.append(outcome, M.clone($('#runStepsCard')));
        scenes.push({title: 'Follow it live', text: 'The bar shows what runs now; each step gets its result as soon as the check has read it. You may leave the page: it keeps running.',
          do: [['move', 'runOutcome'], ['tip', 'runOutcome', 'Open this guide again when the run has ended: it then follows its result']]});
        return {title: 'follow the run', html: head.outerHTML + main.outerHTML, scenes};
      }
      const failed = ['error', 'unknown'].includes(r.status) || (r.status === 'skip' && !steps.length);
      const found = steps.map((s, i) => [s, i]).filter(([s]) => s.status === 'fail' || s.status === 'warn');
      // the buttons of a finished run show at its end, as on the page
      const actions = ['runAgainBtn', 'runNoteBtn', 'runExportWrap', 'runBundleBtn'].filter(k => GH.visible($(`#${k}`)));
      actions.forEach(k => { $(`[data-g="${k}"]`, head).hidden = true; });
      const status = $('[data-g="runStatus"]', head);
      const realStatus = status.innerHTML;
      status.innerHTML = resultLabel('running');
      const progress = M.key(M.el(Progress.html(null, null, 'Progress of the check')), 'gprogress');
      $('[data-now]', progress).textContent = 'Starting…';
      $('.wi-progress__pct', progress).textContent = '0%';
      // the steps shown: the findings (up to three) and the first steps, five in all
      const shownFound = found.slice(0, 3).map(([, i]) => i);
      const keepIdx = new Set(shownFound);
      steps.forEach((s, i) => { if (keepIdx.size < 5 && i < 5) keepIdx.add(i); });
      const stepsCard = M.clone($('#runStepsCard'));
      $$('.wi-steps > li', stepsCard).forEach(li => {
        const i = Number((li.dataset.g || '').replace('step-', ''));
        if (li.dataset.g && !keepIdx.has(i)) li.remove(); else li.hidden = true;
      });
      $$('details', stepsCard).forEach(d => d.removeAttribute('open'));
      $$('table', stepsCard).forEach(t => M.keep(t, 'tbody tr', 3));
      $$('pre', stepsCard).forEach(p => { p.textContent = p.textContent.split('\n').slice(0, 5).join('\n'); });
      outcome.hidden = true;
      main.append(progress, outcome, stepsCard);
      // the recommendations (up to three); the guide follows the one whose fix can run, else one with a fix, else the first
      let ri = fixes.findIndex(fx => fx && fx.available);
      if (ri < 0) ri = fixes.findIndex(Boolean);
      if (ri < 0) ri = recs.length ? 0 : -1;
      const fx = ri >= 0 ? fixes[ri] : null;
      const ran = (r.actions || []).filter(a => a.rec_index === ri);   // fixes already run from this result
      let pickItem = -1;
      if (fx?.selectable && fx.available && !ran.length) pickItem = fx.items.findIndex(it => !it.disabled);
      const shownRecs = recs.map((x, i) => i).filter(i => i === ri || i < 3).slice(0, 3);
      let recsCard = null;
      if (ri >= 0 && GH.visible($('#runRecsCard'))) {
        recsCard = M.clone($('#runRecsCard'));
        $$('.wi-rec', recsCard).forEach(x => { if (!shownRecs.includes(Number(x.dataset.rec))) x.remove(); });
        $$('.wi-rec', recsCard).forEach(x => { if (x.dataset.rec !== String(ri)) $$('.wi-fix__run', x).forEach(y => y.remove()); });
        $$(`[data-rec="${ri}"] .wi-fix__run`, recsCard).slice(0, -1).forEach(y => y.remove());   // the last fix run from it
        $$('.wi-fix__live, .wi-fix__progress', recsCard).forEach(y => y.remove());
        $$('pre', recsCard).forEach(p => { p.textContent = p.textContent.split('\n').slice(0, 5).join('\n'); });
        $$('.wi-rec__body, .wi-rec__refs', recsCard).forEach(x => x.remove());
        $$('.wi-rec__items table', recsCard).forEach(t => M.keep(t, 'tbody tr', Math.max(3, pickItem + 1)));
        main.append(recsCard);
      }
      if (failed) {   // where it stopped: the full output
        const output = M.key(M.clone($('#runLog').closest('.pf-card')), 'goutput');
        $$('.pf-card__body', output).forEach(x => x.remove());
        main.append(output);
      }
      const overlay = [];
      // 1. live: the bar, then each step, then the result
      const order = [...keepIdx].sort((a, b) => a - b);
      const reveal = order.flatMap((i, k) => [['show', `step-${i}`], ...(k === Math.floor(order.length / 2) ? [['fill', 'gprogress', 70, 'Rating what was read']] : [])]);
      scenes.push({title: 'Follow it live', text: 'The result opens at once: the bar shows what runs now, and each step gets its result as soon as the check has read it.',
        do: [['fill', 'gprogress', 35, r.host ? `${r.host} (read-only)` : 'Reading (read-only)'], ...reveal, ['fill', 'gprogress', 100, 'Rating what was read'],
          ['hide', 'gprogress'], ['set', 'runStatus', realStatus], ...actions.map(k => ['show', k]), ['show', 'runOutcome']]});
      // 2. the result as it is: everything OK, what was found, or why it could not run
      if (failed) {
        scenes.push({title: 'Why it could not run', text: 'The red box says why the check stopped (an account, a host that does not answer, a timeout…) and at which step. Nothing was rated.',
          do: [['move', '@[data-g="runOutcome"] .pf-alert'], ['tip', '@[data-g="runOutcome"] .pf-alert', esc(String(r.error || res.error || r.summary || '').slice(0, 160))]]});
        scenes.push({title: 'Look where it stopped', text: '<b>Output</b> at the bottom has the full Ansible output, with the task that failed; <b>Export → Raw output</b> keeps it.',
          do: [['untip'], ['move', 'goutput'], ['tip', 'goutput', 'The task that failed, with its message']]});
      } else if (found.length) {
        const visit = shownFound.flatMap((i, k) => {
          const more = $(`#step-${i} details`);
          return [['untip'], ['click', `@[data-g="runOutcome"] .wi-jump[data-goto="#step-${i}"]`], ['cls', `step-${i}`, 'pg-flash'],
            ...(more ? [['attr', `@[data-g="step-${i}"] details`, 'open', '']] : []),
            ['tip', `@[data-g="step-${i}"] .wi-step__title`, `Finding ${k + 1} of ${found.length}: ${esc(String(steps[i].detail || steps[i].title).slice(0, 110))}`],
            ['wait', 900]];
        });
        const n = found.length;
        scenes.push({title: n > 1 ? `Go to the ${n} findings` : 'Go to what was found',
          text: `The box at the top lists ${n > 1 ? `the ${n} findings` : 'the finding'}: one click goes to its step, with the evidence (the lines of the output that show it).${n > 3 ? ' The guide shows the first three.' : ''}`,
          do: visit});
      } else {
        const first = steps.findIndex((st, i) => keepIdx.has(i) && $(`#step-${i} details`));   // the first step with details
        scenes.push({title: r.status === 'ok' ? 'Everything is OK' : 'Read the result', text: `${r.status === 'ok' ? 'No problem found: there is nothing to fix.' : 'The box at the top sums up the result.'} Every step shows what was read; the details open under a step.`,
          do: [['move', '@[data-g="runOutcome"] .pf-alert'], ['tip', '@[data-g="runOutcome"] .pf-alert', esc(String(r.summary || '').slice(0, 140)) || 'No problem found'],
            ...(first >= 0 ? [['wait', 1000], ['untip'], ['click', `@[data-g="step-${first}"] summary`], ['attr', `@[data-g="step-${first}"] details`, 'open', ''],
              ['tip', `@[data-g="step-${first}"] .wi-step__title`, 'What was read for this step']] : [])]});
      }
      // 3. how to fix it, and the fix
      if (recsCard) {
        const many = shownRecs.length > 1;
        const own = fixes.some(Boolean);
        scenes.push({title: 'How to fix it', text: `${recs.length > 1 ? `${recs.length} recommendations` : 'The recommendation'}: what to do, the commands for this run with the values found, and where to run them. `
            + (own ? 'Copy the commands, or let the portal run them (<b>Run this fix</b>).' : 'Copy the commands (the copy button) and run them where it says.'),
          do: [['untip'], ...($('#runOutcome .wi-jump-fix') ? [['click', '@[data-g="runOutcome"] .wi-jump-fix']] : []), ['move', 'runRecsCard'],
            ...shownRecs.flatMap(i => [['tip', `@[data-rec="${i}"] .wi-rec__title`, many ? `${i + 1} of ${recs.length}${fixes[i] ? ': with a fix the portal can run' : ': commands to run yourself'}`
              : ($(`[data-rec="${i}"] .wi-cmd`) ? 'The commands are under it; the copy button copies them' : 'From the work instruction')], ['wait', many ? 1300 : 0]])]});
      }
      if (fx && recsCard && ran.length) {   // a fix already ran from this result: what happened to it
        const a = ran[ran.length - 1];
        const label = {running: 'still running: its progress shows here and on every page', ok: 'done', failed: 'failed: its error is under it', unknown: 'ended without a result'}[a.status] || a.status;
        scenes.push({title: 'The fix of this result', text: `Fix #${a.id} already ran from this result (${esc(a.username)}) and is ${label}.`
            + (a.verify_run_id ? ' The check ran again by itself after it: the new run says whether the problem is gone.' : ''),
          do: [['untip'], ['move', `@[data-rec="${ri}"] .wi-fix__run`], ['tip', `@[data-rec="${ri}"] .wi-fix__run ${a.verify_run_id ? 'a' : '.pf-label'}`,
            a.verify_run_id ? `Open run #${a.verify_run_id}: the result after the fix` : `Fix #${a.id}: ${esc(label)}`]]});
      } else if (fx && recsCard) {
        const btn = `@[data-rec="${ri}"] [data-fix="${ri}"]`;
        if (fx.available && (!fx.selectable || pickItem >= 0)) {
          const picked = pickItem >= 0 ? [pickItem] : [];
          const pre = pickItem >= 0 ? [['check', `@[data-rec="${ri}"] input[data-sel="${ri}"][value="${pickItem}"]`], ['attr', btn, 'disabled', null]] : [];
          const d = FixDialog.content(r, ri, picked);
          const dlg = M.dialog('#fixDialog');
          const set = (k, v, text = true) => { const x = $(`[data-g="${k}"]`, dlg); if (text) x.textContent = v; else x.innerHTML = v; };
          set('fixTitle', d.title);
          set('fixRisk', d.risk, false);
          set('fixText', d.text);
          set('fixWhere', d.where, false);
          set('fixCommands', d.commands.slice(0, 10).join('\n') + (d.commands.length > 10 ? '\n…' : ''));
          set('fixStopNote', d.stopNote);
          $('[data-g="fixStopNote"]', dlg).hidden = d.stopHidden;
          $('[data-g="fixCheckNote"]', dlg).hidden = d.checkHidden;
          $('[data-g="fixConfirmGroup"]', dlg).hidden = !d.high;
          set('fixConfirmName', d.expected);
          $('[data-g="fixError"]', dlg).hidden = true;
          $('[data-g="fixRun"]', dlg).className = `pf-btn ${d.high ? 'pf-m-danger' : 'pf-m-primary'}`;
          const n = (r.actions || []).length + 1;
          overlay.push(dlg, GH.toast('info', `Fix #${n} started on ${fx.target}.`, 'gtoast'));
          // the fix running, then done: drawn by the page's own function
          const a = {id: n, username: GH.me(), ts: GH.now(), risk: d.high ? 'high' : 'normal', rec_index: ri};
          const running = M.key(M.el(RunPage.fixHtml(null, [{...a, status: 'running'}], ri)), 'gfixrun');
          $('[data-bar]', running).innerHTML = M.frag(Progress.html(null, null, 'Progress of the fix'));
          const done = M.key(M.el(RunPage.fixHtml(null, [{...a, status: 'ok', verify_run_id: r.id + 1,
            output: d.commands.filter(x => !x.startsWith('#')).map(command => ({command, rc: 0}))}], ri)), 'gfixdone');
          running.hidden = done.hidden = true;
          $(`[data-rec="${ri}"] .wi-fix`, recsCard).after(running, done);
          const cmds = d.commands.filter(x => !x.startsWith('#'));
          scenes.push({title: d.high ? 'Run this fix: type to confirm' : 'Run this fix',
            text: `${pre.length ? 'Tick the items to fix. ' : ''}The dialog shows every command, in order, and where it runs. ${d.high ? `A high-risk fix runs only after you type <b>${esc(d.expected)}</b>.` : 'A standard fix runs with <b>Run fix</b>.'} Your account needs the fix permission.`,
            do: [['untip'], ...pre, ['click', btn], ['show', 'fixDialog'], ...(d.high ? [['type', 'fixConfirm', d.expected]] : []), ['click', 'fixRun'],
              ['hide', 'fixDialog'], ['show', 'gtoast']]});
          scenes.push({title: 'It runs, then the check runs again', text: 'The fix shows its progress here and on every page (it keeps running when you leave). Afterwards the check runs again by itself: open the new run to see that the problem is gone.',
            do: [['hide', 'gtoast'], ['show', 'gfixrun'], ['fill', '@[data-g="gfixrun"] .wi-progress', 40, String(cmds[0] || '').slice(0, 70)],
              ['fill', '@[data-g="gfixrun"] .wi-progress', 100, String(cmds[cmds.length - 1] || '').slice(0, 70)],
              ['hide', 'gfixrun'], ['show', 'gfixdone'], ['tip', '@[data-g="gfixdone"] a', 'The new run: the result after the fix']]});
        } else {
          scenes.push({title: 'Why the fix cannot run here', text: 'Under the button the portal says why: the fix permission of your account, a host that is only read, or a result that is too old (run the check again). The commands above can still be run by hand.',
            do: [['untip'], ['move', btn], ['tip', `@[data-rec="${ri}"] .wi-fix__why`, esc(fx.reason || '')]]});
        }
      }
      // 4. share it, or run it again (after a problem was solved by hand, or the cause of a failed run)
      const share = [];
      if (actions.includes('runExportWrap')) {
        share.push(['click', 'runExportToggle'], ['show', 'runExportMenu'], ['tip', 'runExportMenu', 'Every step as CSV, the PDF report, or the raw output'], ['wait', 1400], ['untip'], ['hide', 'runExportMenu']);
      }
      if (actions.includes('runNoteBtn')) share.push(['move', 'runNoteBtn'], ['tip', 'runNoteBtn', 'A summary of the result for the ticket'], ['wait', 1100], ['untip']);
      if (actions.includes('runAgainBtn')) {
        share.push(['move', 'runAgainBtn'], ['tip', 'runAgainBtn', failed ? 'Once the cause is fixed: the same check, with the same values'
          : found.length && !fx ? 'After running the commands: check that the problem is gone' : 'The same check, with the same values']);
      }
      if (share.length) {
        scenes.push({title: failed ? 'Fix the cause, then run it again' : 'Share it, or run it again',
          text: (failed ? 'Once the cause is fixed, <b>Run again</b> runs the same check with the same values. ' : '')
            + '<b>Export</b> gives the steps as CSV, a PDF report or the raw output; <b>Copy ticket note</b> a summary for the ticket.',
          do: [['untip'], ...share]});
      }
      const title = failed ? 'see why it could not run' : found.length ? 'read the result and fix what was found' : 'read the result';
      return {title, html: head.outerHTML + main.outerHTML, overlay, scenes};
    },
  },

  // ---------------------------------------------------------------- runs
  runs: {
    title: 'find a past run',
    build() {
      const page = $('#page-runs');
      const head = M.clone($('section.pf-m-light', page));
      const card = M.clone($('section:not(.pf-m-light) .pf-card', page));
      M.keep(card, '[data-g="rnList"] tr', 5);
      $$('[data-g="rnMore"]', card).forEach(x => { x.hidden = true; });
      const html = head.outerHTML + `<section class="pf-page__section">${card.outerHTML}</section>`;
      const items = Runs.items.slice(0, 5);
      const scenes = [];
      if (!items.length) {
        scenes.push({title: 'Every run is here', text: 'Each check is recorded before it runs, with its result and the full output. No run yet: run a check from the Checks page.',
          do: [['move', 'rnList'], ['tip', 'rnList', 'The runs appear here']]});
        scenes.push({title: 'Search and filter', text: 'Search by check, host, parameter or summary; filter by user, site and result.',
          do: [['untip'], ['move', 'rnQ'], ['move', 'rnStatus']]});
        return {html, scenes};
      }
      const target = r => Runs.target(r).replace(/<[^>]+>/g, '').trim();
      const first = items[0];
      const word = target(first) !== '-' ? target(first) : first.check_title.split(/\s+/).find(w => w.length > 3) || first.check_title;
      const hit = r => `${r.check_title} ${r.summary || ''} ${target(r)} ${Object.values(r.params || {}).join(' ')}`.toLowerCase().includes(word.toLowerCase());
      const st = first.status;
      const label = {fail: 'Problem found', warn: 'Warning', ok: 'OK', error: 'Could not run', running: 'Running'}[st];
      const keep = ok => s => {
        $$('[data-g="rnList"] tr[data-id]', s).forEach(tr => { tr.hidden = !ok(items.find(r => String(r.id) === tr.dataset.id)); });
        const n = Runs.items.filter(ok).length;
        $('[data-g="rnShown"]', s).textContent = `${n} of ${n}`;
      };
      scenes.push({title: 'Search', text: 'Any word of the check, the host, a parameter or the summary.',
        do: [['type', 'rnQ', word], ['do', keep(hit)]]});
      if (label) {
        scenes.push({title: 'Filter by result', text: 'Keep the problems, the warnings, the runs that could not run, or a fix still running. User and site filter the same way.',
          do: [['pick', 'rnStatus', label], ['do', keep(r => hit(r) && r.status === st)]]});
      }
      scenes.push({title: 'Open a run', text: 'A row opens its result as it was: the steps, the fixes run from it and the full output.',
        do: [['click', `@[data-g="rnList"] tr[data-id="${first.id}"]`], ['tip', `@[data-g="rnList"] tr[data-id="${first.id}"]`, `Opens run #${first.id}`]]});
      scenes.push({title: 'Export', text: '<b>Export CSV</b> downloads the runs of the filter, for a report.',
        do: [['untip'], ['click', 'rnExportBtn'], ['tip', 'rnExportBtn', 'runs.csv']]});
      return {html, scenes};
    },
  },

  // ---------------------------------------------------------------- create a template
  template: {
    title: 'create a template (and wait between steps)',
    width: 1100,
    build() {
      if (!Session.admin || !TemplateForm.meta || !Catalog.data) return null;
      const page = $('#page-template');
      const head = M.clone($('section.pf-m-light', page));
      $('[data-g="tpTitle"]', head).textContent = 'Create template';
      $('[data-g="tpCrumb"]', head).textContent = 'Create template';
      const form = M.clone($('#tpForm'));
      ['tpError', 'tpDelete'].forEach(k => { const x = $(`[data-g="${k}"]`, form); if (x) x.hidden = true; });
      $('[data-g="tpName"]', form).value = '';
      $('[data-g="tpSummary"]', form).value = '';
      // the choices of the page; the example runs on Linux VMs (else the first group that may change)
      const groups = TemplateForm.meta.groups;
      const grp = groups.find(g => g.id === 'linux') || groups.find(g => !g.read_only) || groups[0];
      const opts = (items, current, empty) => (empty ? `<option value="">${empty}</option>` : '')
        + items.map(([value, label]) => `<option value="${esc(value)}"${value === current ? ' selected' : ''}>${esc(label)}</option>`).join('');
      $('[data-g="tpGroup"]', form).innerHTML = opts(groups.map(g => [g.id, g.label + (g.read_only ? ' (read-only)' : '')]), '', 'Choose a host group');
      $('[data-g="tpActivity"]', form).innerHTML = opts((Catalog.data.activities || []).map(a => [a.id, a.title]), 'troubleshoot');
      $('[data-g="tpCategory"]', form).innerHTML = opts(Catalog.data.categories.map(c => [c.id, c.title]), '', 'Choose a product');
      const cat = Catalog.data.categories.find(c => c.id === grp.id) || Catalog.data.categories[0];
      const step = (n, k) => {
        const li = M.key(M.el(`<li class="tp-step">${TemplateForm.stepHtml({fail_on_error: true}, n)}</li>`), k);
        $('.tp-step__n', li).textContent = `Step ${k.slice(-1)}`;
        $('[data-mode]', li).innerHTML = TemplateForm.modeHtml('', '');
        $('[data-wait-help]', li).textContent = TemplateForm.waitHelp('read');
        $$('[data-step-tool]', li).forEach(b => { b.disabled = true; });
        return li;
      };
      const s1 = step(901, 'gstep1'), s2 = step(902, 'gstep2');
      s2.hidden = true;
      $('[data-g="tpSteps"]', form).replaceChildren(s1, s2);
      const read = 'systemctl is-active nginx', change = 'sudo systemctl restart nginx';
      const flow = M.el('<div class="pg-flowwrap" data-g="gflow" hidden><div class="pg-flowcard"><h3>How this template runs</h3><ol class="pg-flow">'
        + `<li data-g="f1">${icon('search')}<b>Check</b><span>Step 1 reads: nginx is not active → Problem</span></li>`
        + `<li data-g="f2">${icon('tool')}<b>Run this fix</b><span>The operator types the host name</span></li>`
        + `<li data-g="f3">${icon('play')}<b>Step 2</b><span>${esc(change)}</span></li>`
        + `<li data-g="f4">${icon('in-progress')}<b>Wait</b><span data-g="fcount">30 seconds</span></li>`
        + `<li data-g="f5">${icon('refresh')}<b>Check again</b><span>Step 1: active → OK</span></li></ol>`
        + '<p class="pf-text-secondary pf-text-sm">Read steps run with the check, on the host chosen at launch. Change steps never run with the check: the result offers them as one fix, in order, with their waits.</p></div></div>');
      const tools = (li, up, down, remove) => s => {
        const t = name => $(`[data-g="${li}"] [data-step-tool="${name}"]`, s);
        t('up').disabled = !up; t('down').disabled = !down; t('remove').disabled = !remove;
      };
      const scenes = [
        {title: 'Name it and choose where it runs', text: '<b>Runs on</b> is a host group of Hosts &amp; SSH: when running the template, the operator picks one of its hosts. <b>Activity</b> and <b>Product</b> say where it is listed.',
          do: [['type', 'tpName', `nginx of a ${grp.label.replace(/s$/, '')}`], ['pick', 'tpGroup', grp.label + (grp.read_only ? ' (read-only)' : '')],
            ['do', s => $$('[data-mode]', s).forEach(x => { x.innerHTML = ''; })], ['pick', 'tpCategory', cat.title]]},
        {title: 'A step that reads', text: 'One command per step, as you would type it on the host (with sudo when it needs root). The portal says at once whether it only reads: then it runs with the check.',
          do: [['type', 'tp901_title', 'nginx is active'], ['type', 'tp901_command', read],
            ['set', '@[data-g="gstep1"] [data-mode]', TemplateForm.modeHtml(grp.id, 'read')], ['set', 'tp901_why', TemplateForm.whyText('read')],
            ['tip', '@[data-g="gstep1"] [data-mode]', 'Only reads: runs with the check']]},
        {title: 'When is it a problem?', text: 'Rules on the output: a text or a pattern that makes the step a <b>Problem</b> or a <b>Warning</b>, or that must be in it; and a command that fails.',
          do: [['untip'], ['type', 'tp901_expect', '^active'], ['tip', 'tp901_expect', 'A problem when the output does not start with <b>active</b>']]},
        {title: 'A step that changes the host', text: 'A command that changes something (restart, delete, write a file) never runs with the check: the result offers it as a fix, after a typed confirmation.',
          do: [['untip'], ['click', 'tpAdd'], ['show', 'gstep2'], ['do', tools('gstep1', false, true, true)], ['do', tools('gstep2', true, false, true)],
            ['type', 'tp902_title', 'Restart nginx'], ['type', 'tp902_command', change],
            ['set', '@[data-g="gstep2"] [data-mode]', TemplateForm.modeHtml(grp.id, 'change')],
            ['set', 'tp902_why', TemplateForm.whyText('change', 'systemctl with these arguments can change the system')],
            ['set', '@[data-g="gstep2"] [data-wait-help]', TemplateForm.waitHelp('change')],
            ['hide', '@[data-g="gstep2"] [data-rules]'], ['show', '@[data-g="gstep2"] [data-change]']]},
        {title: 'Wait before the next step', text: 'Time for the host: up to 30 minutes per step, in seconds or minutes (60 minutes in all). After the last change step, the check that runs again after the fix waits too.',
          do: [['type', 'tp902_wait', '30'], ['pick', '@[data-g="gstep2"] [data-f="wait_unit"]', 'seconds'],
            ['tip', 'tp902_wait', 'nginx gets <b>30 seconds</b> before the check runs again']]},
        {title: 'Save, then run it', text: 'The template is listed with the checks of its activity and product, and its page opens: choose a host and run it like any check.',
          do: [['untip'], ['click', 'tpSave'], ['show', 'gtoast'], ['wait', 1500], ['hide', 'gtoast']]},
        {title: 'How it runs', text: 'The check reads; when a step finds a problem, the fix runs the change steps in order with their waits, then the check runs again.',
          do: [['show', 'gflow'], ['cls', 'f1', 'is-on'], ['wait', 700], ['cls', 'f2', 'is-on'], ['wait', 700], ['cls', 'f3', 'is-on'], ['wait', 600],
            ['cls', 'f4', 'is-on'], ['count', 'fcount', 30, 0, '{n} seconds'], ['cls', 'f5', 'is-on'], ['wait', 1500]]},
      ];
      return {html: head.outerHTML + `<section class="pf-page__section">${form.outerHTML}</section>`,
        overlay: [GH.toast('success', 'Template created: choose a host and run it', 'gtoast'), flow], scenes};
    },
  },

  // ---------------------------------------------------------------- Hosts & SSH
  hosts: {
    title: 'add hosts and their SSH credential',
    build() {
      const d = Hosts.data;
      if (!d) return null;
      const page = $('#page-hosts');
      const site = Site.current || d.sites[0];
      const head = M.clone($('section.pf-m-light', page));
      const main = M.clone($('section:not(.pf-m-light)', page));
      M.keep(main, '[data-g="hsCreds"] tr', 3);
      M.keep(main, '[data-g="hsHosts"] tr', 3);
      $('[data-g="hsNotice"]', main).innerHTML = '';
      const grp = d.groups.cdn ? 'cdn' : Object.keys(d.groups)[0];
      const prefix = String(site).toLowerCase();
      const cred = {id: 0, name: `${grp}-ops`, username: 'ops', auth: 'key', fingerprint: 'SHA256:Q8kx…9aT', privilege: 'sudo', fixes: true,
        hosts: 1, updated: GH.now(), updated_by: GH.me()};
      const host = {id: 0, site, grp, name: `${prefix}-${grp}-demo-03`, address: '172.31.10.69', port: 22, credential: cred.name,
        credential_id: -1, fixes: true, note: ''};
      const credRow = M.key(M.row(Hosts.credRow(cred)), 'gcred');
      const hostRow = M.key(M.row(Hosts.hostRow(host)), 'ghost');
      credRow.hidden = hostRow.hidden = true;
      $('[data-g="hsCreds"]', main).prepend(credRow);
      $('[data-g="hsHosts"]', main).prepend(hostRow);
      // the dialogs of the page, as they open for a new credential and a new host
      const ssh = M.dialog('#sshDialog');
      $('[data-g="sshTitle"]', ssh).textContent = 'Add SSH credential';
      $('[data-g="sshPrivilege"]', ssh).innerHTML = Hosts.privilegeOptions('sudo');
      $('[data-g="sshKeyGroup"]', ssh).hidden = false;
      $('[data-g="sshPassGroup"]', ssh).hidden = true;
      $('[data-g="sshError"]', ssh).hidden = true;
      $('[data-g="sshKeyHelp"]', ssh).textContent = 'Without a passphrase. Stored encrypted, never shown again.';
      $('[data-g="sshKey"]', ssh).setAttribute('placeholder', '-----BEGIN OPENSSH PRIVATE KEY-----\n…\n-----END OPENSSH PRIVATE KEY-----');
      const credOption = `${cred.name} (${cred.username}, may run fixes)`;
      const hd = M.dialog('#hostDialog');
      $('[data-g="hostTitle"]', hd).textContent = 'Add host';
      $('[data-g="hostSite"]', hd).innerHTML = Hosts.siteOptions(site);
      $('[data-g="hostGroup"]', hd).innerHTML = Hosts.groupOptions('');
      $('[data-g="hostCred"]', hd).innerHTML = Hosts.credOptions(null) + `<option>${esc(credOption)}</option>`;
      $('[data-g="hostJump"]', hd).innerHTML = '<option value="">Direct (the portal reaches the address)</option>';
      $('[data-g="hostSingle"]', hd).hidden = false;
      $('[data-g="hostMany"]', hd).hidden = true;
      $('[data-g="hostError"]', hd).hidden = true;
      $('[data-g="hostPort"]', hd).value = '22';
      const notice = alertBox('success', `Connection test of ${esc(host.name)} (${host.address}): connected as ${cred.username} on ${esc(host.name)}.`);
      const scenes = [
        {title: 'Add the SSH credential', text: 'The account the portal signs in with: a private key (without a passphrase) or a password, stored encrypted and never shown again.',
          do: [['click', 'hsCredAdd'], ['show', 'sshDialog'], ['type', 'sshName', cred.name], ['type', 'sshUser', cred.username],
            ['type', 'sshKey', '-----BEGIN OPENSSH PRIVATE KEY-----\n(paste the private key)\n-----END OPENSSH PRIVATE KEY-----']]},
        {title: 'Root, and may it run fixes?', text: 'How the account becomes root, and whether operators with the fix permission may run fixes with it. Without <b>May run fixes</b> its hosts are only read.',
          do: [['move', 'sshPrivilege'], ['tip', 'sshPrivilege', 'Here: sudo without a password'], ['wait', 900], ['untip'], ['check', 'sshFixes'],
            ['click', 'sshSave'], ['hide', 'sshDialog'], ...(d.credentials.length ? [] : [['hide', '@[data-g="hsCreds"] tr:not([data-g])']]), ['show', 'gcred']]},
        {title: 'Add a host', text: 'Site, product group (the checks and templates of that group read it), name, address and its credential.',
          do: [['click', 'hsHostAdd'], ['show', 'hostDialog'], ['pick', 'hostGroup', d.groups[grp]], ['type', 'hostName', host.name], ['type', 'hostAddress', host.address],
            ['pick', 'hostCred', credOption], ['click', 'hostSave'], ['hide', 'hostDialog'],
            ...(d.hosts.length ? [] : [['hide', '@[data-g="hsHosts"] tr:not([data-g])']]), ['show', 'ghost']]},
        {title: 'Test the connection', text: '<b>Test</b> signs in to the host and says what works (the account, sudo, the jump host), or what to change when it fails.',
          do: [['click', '@[data-g="ghost"] [data-act="test"]'], ['wait', 700], ['set', 'hsNotice', notice], ['tip', 'hsNotice', 'The result stays here until the next test']]},
        {title: 'Many hosts, or hosts behind a jump host', text: '<b>Add many</b> takes one host per line. A VM the portal cannot reach directly is added with <b>Add hosts behind</b> on a host it reaches.',
          do: [['untip'], ['click', 'hsBulk'], ['do', s => {
            $('[data-g="hostTitle"]', s).textContent = 'Add many hosts';
            $('[data-g="hostSingle"]', s).hidden = true;
            $('[data-g="hostMany"]', s).hidden = false;
          }], ['show', 'hostDialog'], ['type', 'hostLines', `${prefix}-${grp}-demo-04 172.31.10.70\n${prefix}-${grp}-demo-05 172.31.10.71`],
            ['wait', 800], ['hide', 'hostDialog'], ['move', '@[data-g="ghost"] [data-act="behind"]'],
            ['tip', '@[data-g="ghost"] [data-act="behind"]', 'The portal goes through this host (jump host)']]},
      ];
      return {html: head.outerHTML + main.outerHTML, overlay: [ssh, hd], scenes};
    },
  },

  // ---------------------------------------------------------------- BMC
  bmc: {
    title: 'add BMCs for the hardware checks',
    build() {
      const d = Bmcs.data;
      if (!d) return null;
      const page = $('#page-bmc');
      const site = Site.current || d.sites[0];
      const prefix = String(site).toLowerCase();
      const head = M.clone($('section.pf-m-light', page));
      const main = M.clone($('section:not(.pf-m-light)', page));
      M.keep(main, '[data-g="bmCreds"] tr', 3);
      M.keep(main, '[data-g="bmList"] tr', 3);
      const acct = {id: 0, name: 'xcc-readonly', username: 'wi-ro', bmcs: 1, updated: GH.now(), updated_by: GH.me()};
      const bmc = {id: 0, site, name: `${prefix}-compute-07`, address: '10.248.0.57', port: 443, vendor: '', credential: acct.name, credential_id: -1, note: ''};
      const credRow = M.key(M.row(Bmcs.credRow(acct)), 'gacct');
      const row = M.key(M.row(Bmcs.row(bmc)), 'gbmc');
      credRow.hidden = row.hidden = true;
      $('[data-g="bmCreds"]', main).prepend(credRow);
      $('[data-g="bmList"]', main).prepend(row);
      const cd = M.dialog('#bmCredDialog');
      $('[data-g="bmCredTitle"]', cd).textContent = 'Add BMC account';
      $('[data-g="bmCredError"]', cd).hidden = true;
      $('[data-g="bmCredPassReq"]', cd).hidden = false;
      $('[data-g="bmCredPassHelp"]', cd).textContent = 'The BMC web login. Stored encrypted, never shown again.';
      const acctOption = `${acct.name} (${acct.username})`;
      const bd = M.dialog('#bmDialog');
      $('[data-g="bmTitle"]', bd).textContent = 'Add BMC';
      $('[data-g="bmSiteSel"]', bd).innerHTML = Bmcs.siteOptions(site);
      $('[data-g="bmVendor"]', bd).innerHTML = Bmcs.vendorOptions('');
      $('[data-g="bmCred"]', bd).innerHTML = Bmcs.credOptions(null) + `<option>${esc(acctOption)}</option>`;
      $('[data-g="bmSingle"]', bd).hidden = false;
      $('[data-g="bmMany"]', bd).hidden = true;
      $('[data-g="bmError"]', bd).hidden = true;
      $('[data-g="bmPort"]', bd).value = '443';
      const scenes = [
        {title: 'Add the BMC account', text: 'The web login of the BMC; an account with the read-only role is enough. One account serves many BMCs.',
          do: [['click', 'bmCredAdd'], ['show', 'bmCredDialog'], ['type', 'bmCredName', acct.name], ['type', 'bmCredUser', acct.username],
            ['type', 'bmCredPass', 'example-password'], ['click', 'bmCredSave'], ['hide', 'bmCredDialog'],
            ...(d.credentials.length ? [] : [['hide', '@[data-g="bmCreds"] tr:not([data-g])']]), ['show', 'gacct']]},
        {title: 'Add the BMC', text: 'The server name and its management IP (the address of its web page); the vendor is detected by itself.',
          do: [['click', 'bmAdd'], ['show', 'bmDialog'], ['type', 'bmName', bmc.name], ['type', 'bmAddress', bmc.address],
            ['move', 'bmVendor'], ['tip', 'bmVendor', '“Detect”: the portal asks Redfish'], ['wait', 900], ['untip'],
            ['pick', 'bmCred', acctOption], ['click', 'bmSave'], ['hide', 'bmDialog'],
            ...(d.bmcs.length ? [] : [['hide', '@[data-g="bmList"] tr:not([data-g])']]), ['show', 'gbmc']]},
        {title: 'Check it', text: '<b>Check</b> runs <b>Server hardware (BMC)</b> on this server at once and opens its result: health, power, fans, temperatures, memory, disks and the event log.',
          do: [['click', '@[data-g="gbmc"] [data-act="check"]'], ['tip', '@[data-g="gbmc"] [data-act="check"]', 'Opens the result of the check (read-only, Redfish GET)']]},
        {title: 'Many at once', text: '<b>Add many</b> takes one BMC per line, all with the same account.',
          do: [['untip'], ['click', 'bmBulk'], ['do', s => {
            $('[data-g="bmTitle"]', s).textContent = 'Add many BMCs';
            $('[data-g="bmSingle"]', s).hidden = true;
            $('[data-g="bmMany"]', s).hidden = false;
          }], ['show', 'bmDialog'], ['type', 'bmLines', `${prefix}-compute-08 10.248.0.58\n${prefix}-compute-09 10.248.0.59`],
            ['wait', 900], ['hide', 'bmDialog']]},
      ];
      return {html: head.outerHTML + main.outerHTML, overlay: [cd, bd], scenes};
    },
  },
};

PortalGuide.mount(GUIDES, {page: name => document.querySelector(`[data-page="${name}"]`)});

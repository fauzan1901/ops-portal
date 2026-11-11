'use strict';
/* Guides of Runbook Automation, one per page (data-page): each built from the page as it is now, with the page's own
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
    return {port: '80', int: String(p.min ?? 1), ip: '10.249.129.20', ip_list: '10.249.129.20', cidr: '10.249.129.0/24', ip_port: '10.249.129.20:443',
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
      const mast = M.el(`<div class="pg-mast"><span class="pg-brand">${icon('checklist')}Runbook Automation</span></div>`);
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
      const asked = (r.requests || []).find(q => q.rec_index === ri && OPEN_REQUEST.includes(q.status));   // a fix request going on
      let pickItem = -1;
      if (fx?.selectable && fx.available && !ran.length) pickItem = fx.items.findIndex(it => !it.disabled);
      const shownRecs = recs.map((x, i) => i).filter(i => i === ri || i < 3).slice(0, 3);
      let recsCard = null;
      if (ri >= 0 && GH.visible($('#runRecsCard'))) {
        recsCard = M.clone($('#runRecsCard'));
        $$('.wi-rec', recsCard).forEach(x => { if (!shownRecs.includes(Number(x.dataset.rec))) x.remove(); });
        $$('.wi-rec', recsCard).forEach(x => { if (x.dataset.rec !== String(ri)) $$('.wi-fix__run', x).forEach(y => y.remove()); });
        $$('[data-request]', recsCard).forEach(y => { if (!asked || y.dataset.request !== String(asked.id)) y.remove(); });   // the open request only
        $$(`[data-rec="${ri}"] .wi-fix__run:not([data-request])`, recsCard).slice(0, -1).forEach(y => y.remove());   // the last fix run from it
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
      } else if (fx && recsCard && asked) {   // asked for already: where its request is
        const what = {prechecking: 'its pre-check (the check again, read-only) is running', waiting: 'it waits for an engineer (Fix reviews)',
          approved: `it is approved: ${esc(asked.username)} has Run now until ${esc(clock(asked.approved_until))}`, starting: 'its fix is starting'}[asked.status] || esc(asked.state);
        scenes.push({title: 'The fix request of this result', text: `Fix request #${asked.id} (${esc(asked.username)}): ${what}. A fix runs only after its pre-check and an engineer's approval, within ${Session.reviewMinutes || 15} minutes.`,
          do: [['untip'], ['move', `@[data-request="${asked.id}"]`], ['tip', `@[data-request="${asked.id}"] .pf-label`, esc(asked.state)]]});
      } else if (fx && recsCard) {
        const btn = `@[data-rec="${ri}"] [data-fix="${ri}"]`;
        if (fx.available && (!fx.selectable || pickItem >= 0)) {
          const picked = pickItem >= 0 ? [pickItem] : [];
          const pre = pickItem >= 0 ? [['check', `@[data-rec="${ri}"] input[data-sel="${ri}"][value="${pickItem}"]`], ['attr', btn, 'disabled', null]] : [];
          const d = FixDialog.content(r, ri, picked);
          const minutes = Session.reviewMinutes || 15;
          // the dialog as it opens to ask for the fix, then as it opens for Run now of the approved request
          const fill = (dlg, x, typed) => {
            const set = (k, v, text = true) => { const el = $(`[data-g="${k}"]`, dlg); if (text) el.textContent = v; else el.innerHTML = M.frag(v); };
            set('fixTitle', x.title);
            set('fixRisk', x.risk, false);
            set('fixText', x.text);
            set('fixWhere', x.where, false);
            set('fixReview', x.review, false);
            set('fixCommands', x.commands.slice(0, 10).join('\n') + (x.commands.length > 10 ? '\n…' : ''));
            set('fixStopNote', x.stopNote);
            $('[data-g="fixStopNote"]', dlg).hidden = x.stopHidden;
            $('[data-g="fixCheckNote"]', dlg).hidden = x.checkHidden;
            $('[data-g="fixConfirmGroup"]', dlg).hidden = !typed;
            set('fixConfirmName', x.expected);
            set('fixRunText', x.button);
            $('[data-g="fixError"]', dlg).hidden = true;
            $('[data-g="fixRun"]', dlg).className = `pf-btn ${x.high ? 'pf-m-danger' : 'pf-m-primary'}`;
            return dlg;
          };
          const ask = fill(M.dialog('#fixDialog'), d, false);
          // the request as it goes on, drawn by the page's own function: pre-check, waiting for review, approved
          const reqId = Math.max(0, ...(r.requests || []).map(q => q.id)) + 1;
          const preRun = r.id + 1;
          const later = m => new Date(Date.now() + m * 60000).toISOString();
          const q = {id: reqId, run_id: r.id, rec_index: ri, username: GH.me(), ts: GH.now(), status: 'prechecking', state: 'Pre-check running',
            items: picked.map(j => fx.items[j]), noun: fx.noun || '', precheck_run_id: preRun, risk: d.high ? 'high' : 'normal', kind: fx.kind,
            target: fx.target, site: r.site, title: d.text, can_withdraw: true};
          const approved = {...q, status: 'approved', state: 'Approved', reviewed_by: 'engineer', reviewed_at: GH.now(), approved_until: later(minutes),
            precheck_commands: d.commands, precheck_selected: picked.map((j, k) => k), precheck_finished: GH.now(), can_run: true};
          const rows = [[q, 'greqpre'], [{...q, status: 'waiting', state: 'Waiting for review', review_until: later(120)}, 'greqwait'], [approved, 'greqok']]
            .map(([x, key]) => M.key(M.el(RunPage.requestsHtml([x])), key));
          rows.forEach(x => { x.hidden = true; });
          $(`[data-rec="${ri}"] [data-requests="${ri}"]`, recsCard)?.append(...rows);
          const now = M.key(fill(M.dialog('#fixDialog'), FixDialog.runContent(approved), d.high), 'gfixnow');
          const n = (r.actions || []).length + 1;
          overlay.push(ask, now, GH.toast('info', `Fix request #${reqId}: the pre-check runs now (run #${preRun}); an engineer reviews it next.`, 'gtoastask'),
            GH.toast('info', `Fix #${n} started on ${fx.target} (fix request #${reqId}).`, 'gtoast'));
          // the fix running, then done: drawn by the page's own function
          const a = {id: n, username: GH.me(), ts: GH.now(), risk: d.high ? 'high' : 'normal', rec_index: ri, review: {request_id: reqId, reviewed_by: 'engineer'}};
          const running = M.key(M.el(RunPage.fixHtml(null, [{...a, status: 'running'}], ri)), 'gfixrun');
          $('[data-bar]', running).innerHTML = M.frag(Progress.html(null, null, 'Progress of the fix'));
          const done = M.key(M.el(RunPage.fixHtml(null, [{...a, status: 'ok', verify_run_id: r.id + 2,
            output: d.commands.filter(x => !x.startsWith('#')).map(command => ({command, rc: 0}))}], ri)), 'gfixdone');
          running.hidden = done.hidden = true;
          $(`[data-rec="${ri}"] .wi-fix`, recsCard).after(running, done);
          const cmds = d.commands.filter(x => !x.startsWith('#'));
          const inAsk = k => `@[data-g="fixDialog"] [data-g="${k}"]`, inNow = k => `@[data-g="gfixnow"] [data-g="${k}"]`;
          scenes.push({title: 'Run this fix: ask for it',
            text: `${pre.length ? 'Tick the items to fix. ' : ''}The dialog shows every command, in order, and where it runs. Nothing runs yet: <b>Ask for review</b> `
              + 'runs the check again first (the pre-check, read-only). Your account needs the fix permission.',
            do: [['untip'], ...pre, ['click', btn], ['show', 'fixDialog'], ['tip', inAsk('fixReview'), 'Nothing runs yet'], ['wait', 1100], ['untip'],
              ['click', inAsk('fixRun')], ['hide', 'fixDialog'], ['show', 'gtoastask'], ['show', 'greqpre']]});
          scenes.push({title: 'The pre-check, then an engineer',
            text: 'When the pre-check still offers the same fix with the same commands' + (pre.length ? ' and the ticked items' : '') + ', the request waits for an '
              + 'engineer (permission <b>review fixes</b>): on <b>Fix reviews</b> they read the commands and the pre-check, then approve or reject it. Nobody reviews their own request.',
            do: [['hide', 'gtoastask'], ['tip', '@[data-g="greqpre"] .pf-label', 'The check runs again now'], ['wait', 1200], ['untip'], ['hide', 'greqpre'],
              ['show', 'greqwait'], ['tip', '@[data-g="greqwait"] .pf-label', 'An engineer reviews it'], ['wait', 1400], ['untip'], ['hide', 'greqwait'],
              ['show', 'greqok'], ['tip', '@[data-g="greqok"] [data-req-run]', `Approved: Run now for ${minutes} minutes`]]});
          scenes.push({title: d.high ? 'Run now: type to confirm' : 'Run now',
            text: `Within ${minutes} minutes of the approval, <b>Run now</b> shows the commands the engineer approved (those of the pre-check). `
              + (d.high ? `A high-risk fix runs only after you type <b>${esc(d.expected)}</b>. ` : '') + 'Later the request expires: a new pre-check and review are needed.',
            do: [['untip'], ['click', '@[data-g="greqok"] [data-req-run]'], ['show', 'gfixnow'], ...(d.high ? [['type', inNow('fixConfirm'), d.expected]] : []),
              ['click', inNow('fixRun')], ['hide', 'gfixnow'], ['hide', 'greqok'], ['show', 'gtoast']]});
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

  // ---------------------------------------------------------------- Fix reviews
  reviews: {
    title: 'review the fixes operators ask to run',
    build() {
      const d = Reviews.data;
      if (!d) return null;
      const page = $('#page-reviews');
      const head = M.clone($('section.pf-m-light', page));
      const main = M.clone($('section:not(.pf-m-light)', page));
      $$('[data-g="rvMore"]', main).forEach(x => { x.hidden = true; });
      if (!Session.admin) $$('.admin-only', main).forEach(x => x.remove());
      M.keep(main, '[data-g="rvList"] tr', 3);
      const site = Site.current || d.sites[0] || 'DCA';
      const minutes = d.settings.minutes;
      const later = m => new Date(Date.now() + m * 60000).toISOString();
      const check = (Catalog.data?.checks || []).find(c => c.id === 'cdn-datasource');
      const host = `${String(site).toLowerCase()}-cdn-lb-02`;
      const id = Math.max(0, ...Reviews.items.map(q => q.id)) + 1;
      const other = GH.me() === 'operator1' ? 'operator2' : 'operator1';   // the requester: never the one who reviews
      const q = {id, ts: GH.now(), username: Session.canReview ? other : GH.me(), client_ip: '10.246.145.21', site, check_id: 'cdn-datasource',
        check_title: check?.title || 'CDN Grafana datasource', host, run_id: 1234, rec_index: 0, kind: 'host', target: host, risk: 'normal',
        title: 'Start the HAProxy container lb again: the Grafana datasource comes back.', label: 'Run this fix', noun: '', items: [],
        commands: ['sudo docker start lb'], precheck_run_id: 1235, precheck_status: 'fail', precheck_finished: GH.now(),
        precheck_summary: 'Container lb exited; the datasource fails.', precheck_notes: ['The pre-check offers the same fix with the same commands.'],
        precheck_commands: ['sudo docker start lb'], status: 'waiting', state: 'Waiting for review', review_until: later(120),
        can_review: Session.canReview, can_withdraw: !Session.canReview, why_not: ''};
      const ok = {...q, status: 'approved', state: 'Approved', reviewed_by: Session.canReview ? GH.me() : 'engineer', reviewed_at: GH.now(),
        approved_until: later(minutes), can_review: false, can_run: !Session.canReview, can_withdraw: !Session.canReview};
      const wait = M.key(M.row(Reviews.row(q)), 'gwait');
      const done = M.key(M.row(Reviews.row(ok)), 'gok');
      wait.hidden = done.hidden = true;
      const empty = !Reviews.items.length;
      $('[data-g="rvList"]', main).prepend(wait, done);
      const overlay = [];
      const scenes = [{title: 'What waits for a review', text: 'Every fix an operator asked for, after its pre-check: the fix, where it runs, who asked from which run, '
          + 'and the check run again now (read-only). <b>Open</b> lists those still going: pre-check, waiting, approved.',
        do: [...(empty ? [['hide', '@[data-g="rvList"] tr:not([data-g])']] : []), ['show', 'gwait'],
          ['move', '@[data-g="gwait"] td:nth-child(6)'], ['tip', '@[data-g="gwait"] td:nth-child(6)', 'The pre-check: the problem is still there']]}];
      if (Session.canReview) {
        const rd = M.dialog('#reviewDialog');
        const c = ReviewDialog.content(q);
        const set = (k, v, text = true) => { const el = $(`[data-g="${k}"]`, rd); if (text) el.textContent = v; else el.innerHTML = M.frag(v); };
        set('reviewTitle', c.title);
        set('reviewRisk', c.risk, false);
        set('reviewText', c.text);
        set('reviewWhere', c.where, false);
        set('reviewPrecheck', c.precheck, false);
        set('reviewCommands', c.commands.join('\n'));
        set('reviewAfter', c.after);
        $('[data-g="reviewError"]', rd).hidden = true;
        scenes.push({title: 'Review it', text: 'The dialog shows exactly the commands that will run (those of the pre-check), where, who asked, and what the pre-check found.',
          do: [['untip'], ['click', '@[data-g="gwait"] [data-req-review]'], ['show', 'reviewDialog'], ['tip', 'reviewPrecheck', 'Same fix, same commands'],
            ['wait', 1200], ['untip'], ['move', 'reviewCommands'], ['tip', 'reviewCommands', 'Exactly what will run']]});
        scenes.push({title: 'Approve, or reject with a note', text: `Approved, ${esc(q.username)} has <b>Run now</b> for ${minutes} minutes; later the request expires. `
            + 'A rejection needs a note: the operator reads it. Nobody reviews their own request, administrators neither. Every step is in the activity log.',
          do: [['untip'], ['type', 'reviewNote', 'Checked Grafana: datasource down since 10:02'], ['click', 'reviewApprove'], ['hide', 'reviewDialog'],
            ['hide', 'gwait'], ['show', 'gok'], ['tip', '@[data-g="gok"] td:nth-child(7) .pf-label', `Run now for ${minutes} minutes`]]});
        overlay.push(rd);
      } else {
        scenes.push({title: 'An engineer reviews it', text: 'An account with the permission <b>review fixes</b> approves or rejects your request (never their own). '
            + `Approved, you have <b>Run now</b> for ${minutes} minutes, here or on the run; <b>Withdraw</b> drops a request you no longer need.`,
          do: [['untip'], ['tip', '@[data-g="gwait"] td:nth-child(7) .pf-label', 'An engineer reviews it'], ['wait', 1300], ['untip'], ['hide', 'gwait'], ['show', 'gok'],
            ['tip', '@[data-g="gok"] [data-req-run]', `Run now, within ${minutes} minutes`]]});
      }
      scenes.push({title: 'Filter', text: 'By state (waiting, approved, ran, rejected, pre-check failed, expired), site and who asked.',
        do: [['untip'], ['pick', 'rvStatus', 'Waiting for review'], ['move', 'rvSite']]});
      if (Session.admin) {
        scenes.push({title: 'How long Run now stays valid', text: `Administrators: ${minutes} minutes now, 5 to 30 (the owner refused 60). Never longer than the pre-check is recent.`,
          do: [['untip'], ['move', 'rvMinutesInput'], ['tip', 'rvMinutesInput', '5 to 30 minutes']]});
      }
      return {html: head.outerHTML + main.outerHTML, overlay, scenes};
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
      const host = {id: 0, site, grp, name: `${prefix}-${grp}-demo-03`, address: '172.31.138.69', port: 22, credential: cred.name,
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
          }], ['show', 'hostDialog'], ['type', 'hostLines', `${prefix}-${grp}-demo-04 172.31.138.70\n${prefix}-${grp}-demo-05 172.31.138.71`],
            ['wait', 800], ['hide', 'hostDialog'], ['move', '@[data-g="ghost"] [data-act="behind"]'],
            ['tip', '@[data-g="ghost"] [data-act="behind"]', 'The portal goes through this host (jump host)']]},
      ];
      return {html: head.outerHTML + main.outerHTML, overlay: [ssh, hd], scenes};
    },
  },

  // ---------------------------------------------------------------- BMC
  // ---------------------------------------------------------------- Alerts (Grafana)
  alerts: {
    title: 'let Grafana alerts run their checks',
    build() {
      const page = $('#page-alerts');
      const head = M.clone($('section.pf-m-light', page));
      const main = M.clone($('section:not(.pf-m-light)', page));
      $('[data-g="alNotice"]', main).innerHTML = '';
      $$('[data-g="alMore"]', main).forEach(x => { x.hidden = true; });
      M.keep(main, '[data-g="alList"] tr', 3);
      const site = Site.current || Site.list[0]?.name || 'DCB';
      const fixTitle = 'Create the HAProxy logrotate rule so the log cannot grow without limit again, test it.';
      const truncTitle = 'Restart HAProxy so it releases the deleted log file it still holds open.';
      const ev = {id: -1, ts: GH.now(), source: 'Grafana SRE', alertname: 'CDN root disk full', status: 'firing', site: '', rule_name: '',
        labels: {alertname: 'CDN root disk full', site: site.toLowerCase(), instance: '172.31.138.67:9100', severity: 'critical'},
        annotations: {summary: 'Root disk above 90%'}, state: 'no-rule', outcome: 'No rule matches this alert.'};
      const cdnTitle = (Catalog.data?.checks || []).find(c => c.id === 'cdn-root-disk')?.title || 'CDN root disk';
      const done = {...ev, id: -2, site, rule_name: 'CDN root disk', check_title: cdnTitle, state: 'checked', run_id: 1234, run_status: 'fail', fix_id: 88, fix_status: 'ok',
        fix_title: fixTitle, verify_run_id: 1235, verify_status: 'ok', action_id: 12,
        action: {id: 12, step: 'done', stop: 'gone', done: 1, ran: 1, max: 1, noun: '', title: fixTitle, impact: ''},
        outcome: `Checked: Problem found. Automatic action #12 (fix #88 ran): ${cdnTitle} (run #1235): Root filesystem: 41% used. The problem of dcb-cdn-lb-01 is gone: stopped.`};
      const rowNew = M.key(M.row(Alerts.row(ev)), 'gnew');
      const rowDone = M.key(M.row(Alerts.row(done)), 'gdone');
      rowNew.hidden = rowDone.hidden = true;
      $('[data-g="alList"]', main).prepend(rowDone);
      $('[data-g="alList"]', main).prepend(rowNew);
      const operatorScenes = [
        {title: 'The alerts Grafana sent', text: 'Every alert with the rule that matched it, the check that ran for it (its run, with the evidence) and the result.',
          do: [['show', 'gdone'], ['move', '@[data-g="gdone"] td:nth-child(5)'], ['tip', '@[data-g="gdone"] td:nth-child(5)', 'Opens the run of the check']]},
        {title: 'Fixes that ran by themselves', text: 'Only the automatic action an administrator set on the rule (a customer-impacting one only with the owner\'s '
          + 'approval recorded on it): one item at a time, the measuring check after each, until the problem of its target is gone. The result says what it did and why it stopped.',
          do: [['untip'], ['move', '@[data-g="gdone"] td:nth-child(6)'], ['tip', '@[data-g="gdone"] td:nth-child(6)', 'Action #12: the problem is gone']]},
        {title: 'Search and filter', text: 'Any word of the alert, its labels, the rule or the result; by site and by state. '
          + 'The alerts their source ignores are hidden (kept as history): the state <b>Ignored</b> lists them.',
          do: [['untip'], ['type', 'alQ', 'cdn'], ['move', 'alState']]},
      ];
      if (!Session.admin || !Alerts.cfg) {
        $$('.admin-only', main).forEach(x => x.remove());
        return {html: head.outerHTML + main.outerHTML, scenes: operatorScenes};
      }
      const cfg = Alerts.cfg;
      const check = cfg.checks.find(c => c.id === 'cdn-root-disk') || cfg.checks.find(c => c.params.some(p => p.type === 'host')) || cfg.checks[0];
      const check2 = cfg.checks.find(c => c.id === 'cdn-memory') || cfg.checks.find(c => c.id !== check.id && c.params.some(p => p.type === 'host'))
        || cfg.checks.find(c => c.id !== check.id) || check;
      const hostParam = (check.params.find(p => p.type === 'host') || check.params[0] || {}).name;
      const hostParam2 = (check2.params.find(p => p.type === 'host') || {}).name;
      const hostOf = p => (p ? {[p]: '{{labels.instance|host}}'} : {});
      $('[data-g="alAutoFix"]', main).checked = cfg.settings.auto_fix;
      $('[data-g="alFrozen"]', main).innerHTML = M.frag(Alerts.frozenHtml(cfg.sites.length ? cfg.sites : [site], []));
      $('[data-g="alFrozenNow"]', main).innerHTML = '';
      M.keep(main, '[data-g="alRules"] tr', 2);
      M.keep(main, '[data-g="alSources"] tr', 2);
      const checks = Object.fromEntries(cfg.checks.map(x => [x.id, x]));
      const rule = {id: -1, name: 'CDN root disk', enabled: true, alertname: 'CDN root disk*', matchers: [{label: 'severity', op: '=', value: 'critical'}],
        site: '{{labels.site}}', checks: [{check_id: check.id, params: hostOf(hostParam)}, {check_id: check2.id, params: hostOf(hostParam2)}],
        cooldown: 30, auto_per_hour: 3, stats: {}, approval: {needed: false, valid: false}, fixes_seen: [
          {key: 'a', check_id: check.id, title: fixTitle, eligible: true, impact: '', items: false, sized: false, run_id: 1234},
          {key: 'b', check_id: check.id, title: truncTitle, eligible: true, impact: 'high risk (deletes, restarts, kills, reboots)', items: false, sized: false, run_id: 1234}]};
      const approvedRule = {...rule, checks: [{...rule.checks[0], action: {fix: 'b', title: truncTitle, order: 'listed', max_items: 1, measure: 0, thresholds: {}}},
        rule.checks[1]], approval: {needed: true, valid: true, by: GH.me(), name: GH.me(), ticket: 'CHG-2026-1110', at: GH.now(), impact: [truncTitle]}};
      const withAction = (action, approval = false) => s => {   // the check blocks of the rule being edited, check 1 with this action
        const list = rule.checks.map((x, i) => (i === 0 && action ? {...x, action} : x));
        $('[data-g="ruleChecks"]', s).innerHTML = M.frag(list.map((x, i) => Alerts.checkBlock(x, i, list, rule)).join(''));
        $('[data-g="ruleApprovalGroup"]', s).hidden = !approval;
        $('[data-g="ruleApprovalNote"]', s).innerHTML = approval ? M.frag(alertBox('warning', `Customer-impacting: ${esc(truncTitle)}`,
          'It runs by itself only with the owner\'s approval: the ticket or reference of that approval, and the rule name typed. '
          + 'Without it the rule is saved with it locked (it does not run).')) : '';
      };
      const source = {id: -1, name: 'Grafana SRE', token_tail: 'x9Qa', networks: '10.246.145.5', enabled: true, last_seen: '', created: GH.now(), created_by: GH.me()};
      const ruleRow = M.key(M.row(Alerts.ruleRow(rule, checks)), 'grule');
      const sourceRow = M.key(M.row(Alerts.sourceRow(source)), 'gsrc');
      const freeSource = {...source, networks: '10.246.145.0/24', tokenless: '10.246.145.15'};   // a sender that cannot send the header
      const sample = {id: -1, received: GH.now(), source_name: source.name, client_ip: '10.246.145.15', user_agent: 'Example-Webhook/1.0',
        content_type: 'application/json', size: 96, reason: 'No alerts list (not a Grafana Alerting or Alertmanager notification)',
        body: '{"event": "disk_full", "host": "172.31.138.67", "value": 93.5, "severity": "critical"}'};
      const samplesBefore = $('[data-g="alSamples"]', main).innerHTML;
      ruleRow.hidden = sourceRow.hidden = true;
      $('[data-g="alRules"]', main).prepend(ruleRow);
      $('[data-g="alSources"]', main).prepend(sourceRow);
      const sd = M.dialog('#sourceDialog');
      $('[data-g="sourceTitle"]', sd).textContent = 'Add source';
      $('[data-g="sourceError"]', sd).hidden = true;
      $('[data-g="sourceEnabledGroup"]', sd).hidden = true;
      $('[data-g="sourceConfirmGroup"]', sd).hidden = true;
      const setup = M.dialog('#setupDialog');
      $('[data-g="setupTitle"]', setup).textContent = 'Connect Grafana SRE';
      $('[data-g="setupBody"]', setup).innerHTML = M.frag(Alerts.setupHtml(source, 'gfa_example-token-shown-only-once'));
      const rd = M.dialog('#ruleDialog');
      $('[data-g="ruleTitle"]', rd).textContent = 'Add rule';
      $('[data-g="ruleError"]', rd).hidden = true;
      $('[data-g="ruleFixes"]', rd).hidden = true;
      $('[data-g="ruleApprovalGroup"]', rd).hidden = true;
      $('[data-g="ruleConfirmGroup"]', rd).hidden = true;
      $('[data-g="ruleTry"]', rd).hidden = false;
      $('[data-g="ruleChecks"]', rd).innerHTML = M.frag(Alerts.checkBlock({check_id: '', params: {}}, 0, [{check_id: '', params: {}}], null));
      $('[data-g="ruleTryAlert"]', rd).innerHTML = `<option>${esc(shortTime(ev.ts))} · ${esc(ev.alertname)} · ${esc(ev.labels.instance)} · Grafana SRE</option>`;
      const paramKey = hostParam ? `ruleP0-${hostParam}` : '';
      const paramKey2 = hostParam2 ? `ruleP1-${hostParam2}` : '';
      const block = (list, n) => s => { $('[data-g="ruleChecks"]', s).innerHTML = M.frag(list.map((x, i) => Alerts.checkBlock(x, i, list, null)).join('')); };
      const scenes = [
        {title: 'Add a source for each Grafana', text: 'One per Grafana or team (the SRE team gets its own), optionally with the addresses it sends from.',
          do: [['click', 'alSourceAdd'], ['show', 'sourceDialog'], ['type', 'sourceName', source.name], ['type', 'sourceNetworks', source.networks],
            ['click', 'sourceSave'], ['hide', 'sourceDialog'], ['show', 'gsrc']]},
        {title: 'Give them the address and the token', text: 'The token is shown only this once (the portal keeps its hash): the team puts the URL in a Webhook contact point and the token in its Authorization header.',
          do: [['show', 'setupDialog'], ['move', '@[data-g="setupDialog"] .pf-dl'], ['tip', '@[data-g="setupDialog"] .pf-dl', 'URL, POST, Authorization: Bearer <token>'],
            ['wait', 1600], ['untip'], ['hide', 'setupDialog']]},
        {title: 'A sender without a header', text: 'Only when a sender cannot send the Authorization header (a webhook that is not Grafana): '
          + '<b>Edit</b> the source and list its exact IPv4 addresses (inside Allowed from, at most 10) under <b>Accept without a token from</b>; '
          + 'you type the source name. Its alerts then show <b>no token</b>, and every change is in the activity log.',
        do: [['click', '@[data-g="gsrc"] [data-act="edit"]'], ['do', s => { $('[data-g="sourceTitle"]', s).textContent = `Edit ${source.name}`; }],
          ['show', 'sourceDialog'], ['type', 'sourceNetworks', freeSource.networks], ['type', 'sourceTokenless', freeSource.tokenless],
          ['show', 'sourceConfirmGroup'], ['set', 'sourceConfirmName', esc(source.name)], ['type', 'sourceConfirm', source.name],
          ['click', 'sourceSave'], ['hide', 'sourceDialog'],
          ['do', s => { $('[data-g="gsrc"]', s).innerHTML = M.row(Alerts.sourceRow(freeSource)).innerHTML; }],
          ['tip', '@[data-g="gsrc"] td:nth-child(3)', 'without a token from 10.246.145.15']]},
        {title: 'Ignore what nobody needs', text: '<b>Ignore alerts named</b> on a source (e.g. <span class="mono">Speedtest*</span>): its notifications '
          + 'are still accepted, those alerts are not listed and run nothing, and the row of the source counts them. Its alerts received before '
          + 'are hidden too (never deleted: the filter <b>Ignored</b> shows them); removing the pattern shows them again.',
        do: [['untip'], ['click', '@[data-g="gsrc"] [data-act="edit"]'], ['show', 'sourceDialog'], ['type', 'sourceIgnore', 'Speedtest*'],
          ['click', 'sourceSave'], ['hide', 'sourceDialog'],
          ['do', s => { $('[data-g="gsrc"]', s).innerHTML = M.row(Alerts.sourceRow({...freeSource, ignore: ['Speedtest*'], ignored: 12, ignored_days: 7})).innerHTML; }],
          ['tip', '@[data-g="gsrc"] td:first-child', 'ignores Speedtest* · 12 ignored in 7 days']]},
        {title: 'What the portal could not read', text: 'A notification of a known sender that is not Grafana\'s (not JSON, no alerts list) is refused '
          + 'and kept here, the last 20, so a mapping for its format can be written. A row opens its body; <b>Read again</b> reads it with the '
          + 'mapping of now and, when it is readable, receives it as its source\'s alerts. Only administrators see this.',
        do: [['untip'], ['do', s => {
          const t = document.createElement('table');
          t.innerHTML = Alerts.samplesHtml([sample]);
          $('[data-g="alSamples"]', s).innerHTML = M.clean(t).innerHTML;
        }], ['click', '@[data-g="alSamples"] tr.ck-row'], ['show', '@[data-g="alSamples"] tr.ck-detail'],
          ['tip', '@[data-g="alSamples"] tr.ck-detail', 'The body as it came (cut to 8 KB)'], ['wait', 1400], ['untip'],
          ['move', '@[data-g="alSamples"] [data-act="read"]'], ['tip', '@[data-g="alSamples"] [data-act="read"]', 'Once a mapping reads it: its alerts show above'],
          ['wait', 1400], ['untip'],
          ['do', s => { $('[data-g="alSamples"]', s).innerHTML = samplesBefore; }]]},
        {title: 'An alert without a rule', text: 'Every alert shows here at once, with its labels. One without a rule offers <b>Create rule</b>.',
          do: [['show', 'gnew'], ['move', '@[data-g="gnew"] [data-act="rule"]'], ['tip', '@[data-g="gnew"] [data-act="rule"]', 'Made from this alert']]},
        {title: 'The rule: alert, site, check', text: 'The alert name (* matches any text) and labels it must have, the site (fixed, or from a label), and a check with its parameters from the labels.',
          do: [['untip'], ['click', '@[data-g="gnew"] [data-act="rule"]'], ['show', 'ruleDialog'], ['type', 'ruleName', rule.name], ['type', 'ruleAlert', rule.alertname],
            ['type', 'ruleMatchers', 'severity=critical'], ['type', 'ruleSite', rule.site], ['pick', 'ruleC0', check.title],
            ['do', block([{check_id: check.id, params: {}}], 0)],
            ...(paramKey ? [['type', paramKey, '{{labels.instance|host}}'], ['tip', paramKey, '172.31.138.67:9100 → 172.31.138.67']] : [])]},
        {title: 'More checks for the same alert', text: '<b>Add a check</b>: every check of the rule runs for the alert, each in its own run, each with its own parameters.',
          do: [['untip'], ['click', 'ruleCheckAdd'], ['do', block([{check_id: check.id, params: hostOf(hostParam)}, {check_id: '', params: {}}], 1)],
            ['pick', 'ruleC1', check2.title], ['do', block([{check_id: check.id, params: hostOf(hostParam)}, {check_id: check2.id, params: {}}], 1)],
            ...(paramKey2 ? [['type', paramKey2, '{{labels.instance|host}}']] : [['move', 'ruleC1']])]},
        {title: 'Try it before saving', text: 'With a received alert: does it match, which site, and the parameters of each check. Nothing runs.',
          do: [['untip'], ['click', 'ruleTryBtn'], ['set', 'ruleTryResult', M.frag(Alerts.tryHtml({matches: true, site, error: '', checks: [
            {title: check.title, params: hostParam ? {[hostParam]: 'dcb-cdn-lb-01'} : {}, error: ''},
            {title: check2.title, params: hostParam2 ? {[hostParam2]: 'dcb-cdn-lb-01'} : {}, error: ''}]}))], ['wait', 1400],
            ['click', 'ruleSave'], ['hide', 'ruleDialog'], ['show', 'grule']]},
        {title: 'The next alert runs the checks', text: 'At once, as <b>grafana</b>: one row and one run per check. The same check of the rule runs again only after its cooldown.',
          do: [['hide', 'gnew'], ['show', 'gdone'], ['move', '@[data-g="gdone"] td:nth-child(5)'], ['tip', '@[data-g="gdone"] td:nth-child(5)', 'Run #1234: Problem found']]},
        {title: 'An automatic action per check', text: 'Edit the rule: each check lists the fixes its results offered. Choose one under <b>Automatic action</b>, '
          + 'and how it stops: the measuring check (this one, or another check of the rule with its own thresholds, e.g. the memory of the node under 75%) runs '
          + 'after each item; while it still reports the problem of the target, the next item runs (ticked items such as live migrations: smallest or largest '
          + 'first, at most the number you set). A new action starts <b>Observe only</b>: on each alert it lists what it would run and changes nothing. '
          + 'You type the rule name to confirm.',
          do: [['untip'], ['click', '@[data-g="grule"] [data-act="edit"]'], ['do', s => {
            $('[data-g="ruleTitle"]', s).textContent = `Edit ${rule.name}`;
            $('[data-g="ruleTry"]', s).hidden = true;
            $('[data-g="ruleTryResult"]', s).innerHTML = '';
            $('[data-g="ruleFixes"]', s).hidden = false;
            $('[data-g="rulePerHour"]', s).value = '3';
            withAction(null)(s);
          }], ['show', 'ruleDialog'], ['pick', 'ruleAf0', fixTitle], ['do', withAction({fix: 'a', mode: 'observe'})],
            ['tip', 'ruleAd0', 'A pilot first: it records what it would do'], ['wait', 1400], ['untip'],
            ['tip', 'ruleAs0', 'Stops when this check no longer reports the host'], ['wait', 1400], ['untip'],
            ['show', 'ruleConfirmGroup'], ['set', 'ruleConfirmName', esc(rule.name)], ['type', 'ruleConfirm', rule.name]]},
        {title: 'Customer-impacting: the owner approves Run', text: 'OpenStack, ONTAP, VyOS, ticked items (live migrations), deletes, restarts, firewall or package '
          + 'changes: observe only needs no approval; switched to <b>Run</b> and saved without the owner\'s approval they are locked and do not run. The ticket of '
          + 'the approval and the rule name typed record it, with you as the approver (on the rule and in the activity log); changing what the rule matches or '
          + 'does (Observe only to Run too) locks it again. Never on VMware Cloud, ESXi or a database.',
          do: [['pick', 'ruleAf0', `${truncTitle} (customer-impacting)`], ['do', withAction({fix: 'b', mode: 'observe'})],
            ['pick', 'ruleAd0', 'Run: changes by itself'], ['do', withAction({fix: 'b', mode: 'run'}, true)], ['move', 'ruleApprovalNote'],
            ['type', 'ruleTicket', 'CHG-2026-1110'], ['tip', 'ruleTicket', `Recorded with ${esc(GH.me())} as the approver`], ['wait', 1400], ['untip'],
            ['click', 'ruleSave'], ['hide', 'ruleDialog'],
            ['do', s => { $('[data-g="grule"]', s).innerHTML = M.row(Alerts.ruleRow(approvedRule, checks)).innerHTML; }],
            ['tip', '@[data-g="grule"] td:nth-child(5)', 'Approved by you, ticket CHG-2026-1110']]},
        {title: 'It acts, measures, then stops', text: `One item at a time (one live migration, or the whole fix once), the measuring check after each. It stops when the `
          + 'problem of the target is gone, at the maximum, at the first item that fails, or when paused or frozen meanwhile. One automatic action per target at a '
          + `time; at most ${cfg.limits.auto_per_hour} an hour per rule; the same fix on the same target again only after ${cfg.limits.auto_again_hours} hours.`,
          do: [['untip'], ['move', '@[data-g="gdone"] td:nth-child(6)'], ['tip', '@[data-g="gdone"] td:nth-child(6)', 'Action #12: the problem is gone'], ['wait', 1200],
            ['untip'], ['move', '@[data-g="gdone"] td:nth-child(7)'], ['tip', '@[data-g="gdone"] td:nth-child(7)', 'What it did and why it stopped']]},
        {title: 'Pause them, or keep a site out', text: 'One untick pauses every automatic action (the checks still run). <b>Sites where automatic changes never run</b> '
          + 'is empty unless you tick one (e.g. a site under an incident): its checks still run, nothing changes there by itself.',
          do: [['untip'], ['move', 'alAutoFix'], ['tip', 'alAutoFix', 'Off: every alert waits for an operator'], ['wait', 1200], ['untip'],
            ['check', '@[data-g="alFrozen"] input'], ['tip', '@[data-g="alFrozen"] label', 'Its checks run, nothing changes there by itself']]},
      ];
      return {html: head.outerHTML + main.outerHTML, overlay: [sd, setup, rd], scenes};
    },
  },
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
      const acct = {id: 0, name: 'xcc-readonly', username: 'runbook-ro', bmcs: 1, updated: GH.now(), updated_by: GH.me()};
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

'use strict';
/* Status (portal module /status/): the read-only checks of Runbook Automation for every product of every site, run by
   themselves every few hours; one card per product with what is safe, what each check found, its recommendations and
   the checks to run next. Same look and helpers as Nessus and Runbook Automation (PatternFly v5 like AWX,
   docs/UI-SPEC.md); sign-in, users and credentials belong to the portal. */

const BASE = '/status';
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
const icon = name => `<svg class="pf-icon" aria-hidden="true"><use href="#i-${name}"></use></svg>`;
const plural = (n, word, many = `${word}s`) => `${n} ${n === 1 ? word : many}`;
const tabStore = {
  get(key) { try { return sessionStorage.getItem(key); } catch (e) { return null; } },
  set(key, value) { try { sessionStorage.setItem(key, value); } catch (e) { /* storage not available */ } },
};
const BASE_TITLE = document.title;
const UI_VERSION = document.querySelector('meta[name="ui-version"]')?.content || '';
const SITE_COLORS = ['#2b9af3', '#3e8635', '#8476d1', '#ec7a08', '#c9190b', '#009596'];

function shortTime(iso) {
  if (!iso) return '-';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString('en-GB', {day: 'numeric', month: 'short', hour: '2-digit',
    minute: '2-digit', hourCycle: 'h23'}).replace('Sept', 'Sep');
}
function alertBox(kind, title, body = '') {
  const name = {success: 'check-circle', danger: 'x-circle', warning: 'alert', info: 'info'}[kind];
  return `<div class="pf-alert pf-m-${kind}"${kind === 'danger' ? ' role="alert"' : ''}>${icon(name)}<div class="pf-alert__title">${title}</div>`
    + (body ? `<div class="pf-alert__body">${body}</div>` : '') + '</div>';
}
const label = (text, color = '', ic = '', title = '') => `<span class="pf-label${color ? ` pf-m-${color}` : ''}"${title ? ` title="${esc(title)}"` : ''}>`
  + `${ic ? icon(ic) : ''}${esc(text)}</span>`;

// A product from its checks; a check from its run (Runbook Automation words)
const PRODUCT = {ok: ['Safe', 'green', 'check-circle'], warn: ['Needs attention', 'gold', 'alert'], problem: ['Not safe', 'red', 'x-circle'],
  unknown: ['Could not check', '', 'minus-circle'], running: ['Checking', 'blue', 'in-progress'], 'not-configured': ['Not configured', '', 'minus-circle'],
  never: ['Not checked yet', '', 'circle']};
const CHECK = {ok: ['OK', 'green', 'check-circle'], warn: ['Warning', 'gold', 'alert'], fail: ['Problem found', 'red', 'x-circle'],
  error: ['Could not run', '', 'x'], unknown: ['Unknown', '', 'minus-circle'], skip: ['Not checked', '', 'minus-circle'],
  stopped: ['Stopped', '', 'minus-circle'], running: ['Running', 'blue', 'in-progress'], waiting: ['Waiting', '', 'circle'],
  'not-configured': ['Not configured', '', 'minus-circle'], never: ['Not checked yet', '', 'circle']};
const lab = (map, status, title = '') => { const [t, c, i] = map[status] || [status, '', 'circle']; return label(t, c, i, title); };

async function api(url, body, method) {
  const init = {method: method || (body === undefined ? 'GET' : 'POST')};
  if (body !== undefined) {
    init.headers = {'Content-Type': 'application/json'};
    init.body = JSON.stringify(body);
  }
  const res = await fetch(BASE + url, init);
  let data;
  try { data = await res.json(); } catch (e) { throw new Error(`Portal server error (HTTP ${res.status})`); }
  if (res.status === 401) window.PortalLauncher?.signIn();
  if (res.status === 403) Session.refresh();
  if (!data.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}
function toast(message, kind = 'danger') {
  const box = document.createElement('div');
  box.innerHTML = alertBox(kind, esc(message));
  const el = box.firstElementChild;
  const close = document.createElement('button');
  close.type = 'button';
  close.className = 'pf-btn pf-m-plain pf-m-small';
  close.setAttribute('aria-label', 'Close');
  close.innerHTML = icon('x');
  close.addEventListener('click', () => el.remove());
  el.insertBefore(close, el.children[2] || null);
  $('#toasts').appendChild(el);
  setTimeout(() => el.remove(), kind === 'danger' ? 10000 : 5000);
}
async function run(button, fn) {
  if (button) { button.disabled = true; button.classList.add('is-loading'); }
  try { return await fn(); } catch (e) { toast(e.message); } finally {
    if (button) { button.disabled = false; button.classList.remove('is-loading'); }
  }
}

/* =========================================================================
   Site, session, user menu
   ========================================================================= */
const ROLE_LABELS = {admin: 'Administrator', operator: 'Operator'};
function signedInWith(user) {
  const account = user.source === 'local' ? 'a local account' : 'Active Directory';
  return {sso: 'Signed in with Duo SSO', duo: `Signed in with ${account} and Duo`, none: `Signed in with ${account}`,
    bypassed: `Signed in with ${account} (Duo was unreachable and bypassed)`}[user.mfa] || '';
}
const Site = {
  current: '',
  list: [],
  titles: {},
  set(status) {
    this.list = (status.sites || []).map((x, i) => ({...x, color: SITE_COLORS[i % SITE_COLORS.length]}));
    this.titles = Object.fromEntries((status.products || []).map(p => [p.id, p.title]));
  },
  render() {
    $('#siteSwitch').innerHTML = this.list.map(x => `<label title="Site ${esc(x.name)}"><input type="radio" name="site" value="${esc(x.name)}"`
      + `${x.name === this.current ? ' checked' : ''}><span><span class="site-dot" style="--site-color:${x.color}"></span>${esc(x.name)}</span></label>`).join('');
    $('#navSites').innerHTML = this.list.map(x => `<div><span class="site-dot" style="--site-color:${x.color}"></span>${esc(x.name)}`
      + `<span class="pf-text-sm">${x.products.length ? x.products.map(p => esc(this.titles[p] || p)).join(' · ') : 'nothing configured'}</span></div>`).join('');
  },
  activate(name) {
    this.current = name;
    if (name) tabStore.set('health_site', name);
    document.title = name ? `[${name}] ${BASE_TITLE}` : BASE_TITLE;
    $$('.site-name-current').forEach(el => { el.textContent = name || '-'; });
    $$('#siteSwitch input').forEach(x => { x.checked = x.value === name; });
  },
};
const Session = {
  user: null,
  outdated: false,
  apply(status) {
    if (!this.outdated && status.ui_version && UI_VERSION && status.ui_version !== UI_VERSION) {
      this.outdated = true;
      toast('A new version of Status is available. Reload the page.', 'info');
    }
    if (!status.user) return window.PortalLauncher?.signIn();
    this.user = status.user;
    this.allowed = !!status.allowed;
    this.admin = !!status.is_admin;
    this.interval = status.interval_hours;
    UserMenu.render(this.user, status.client);
    $$('.admin-only').forEach(el => { el.hidden = !this.admin; });
    $('#appView').hidden = false;
    Site.set(status);
    const names = Site.list.map(x => x.name);
    Site.render();
    Site.activate([Site.current, tabStore.get('health_site')].find(n => n && names.includes(n)) || names[0] || '');
  },
  async refresh() {
    try {
      const status = await (await fetch(`${BASE}/api/session`)).json();
      this.apply(status);
      return status;
    } catch (e) { return null; }
  },
  async logout() {
    UserMenu.close();
    try { await fetch('/api/logout', {method: 'POST'}); } catch (e) { /* the session still ends when it expires */ }
    location.assign('/');
  },
};
const UserMenu = {
  init() {
    $('#userToggle').addEventListener('click', () => (this.isOpen() ? this.close() : this.open()));
    $('#logoutBtn').addEventListener('click', () => Session.logout());
    document.addEventListener('click', e => { if (this.isOpen() && !e.target.closest('#userMenuWrap')) this.close(); });
    $('#userMenuWrap').addEventListener('keydown', e => { if (e.key === 'Escape' && this.isOpen()) { this.close(); $('#userToggle').focus(); } });
    $('#userMenuWrap').addEventListener('focusout', e => { if (!e.currentTarget.contains(e.relatedTarget)) this.close(); });
  },
  isOpen() { return !$('#userMenu').hidden; },
  open() { $('#userMenu').hidden = false; $('#userToggle').setAttribute('aria-expanded', 'true'); $('#logoutBtn').focus(); },
  close() { $('#userMenu').hidden = true; $('#userToggle').setAttribute('aria-expanded', 'false'); },
  render(user, client = '') {
    const name = user.display_name || user.username;
    const words = name.split(/[\s._-]+/).filter(Boolean);
    $('#userAvatar').textContent = words.length > 1 ? words[0][0] + words[1][0] : name.slice(0, 2);
    $('#userName').textContent = name;
    $('#userRole').textContent = ROLE_LABELS[user.role] || user.role;
    $('#userRole').className = `pf-label pf-m-compact${user.role === 'admin' ? ' pf-m-blue' : ''}`;
    $('#userMenuName').textContent = name;
    $('#userMenuLogin').textContent = name !== user.username ? user.username : '';
    $('#userMenuMfa').textContent = signedInWith(user);
    $('#userMenuClient').textContent = client ? `From ${client}` : '';
  },
};
const Router = {
  page: '',
  init() {
    window.addEventListener('hashchange', () => this.go());
    $('#siteSwitch').addEventListener('change', e => {
      if (e.target.name !== 'site') return;
      Site.activate(e.target.value);
      this.go();
    });
    $('#navToggle').setAttribute('aria-expanded', String(!matchMedia('(max-width: 1000px)').matches));
    $('#navToggle').addEventListener('click', () => {
      const page = $('#appView');
      const narrow = matchMedia('(max-width: 1000px)').matches;
      page.classList.toggle(narrow ? 'is-nav-open' : 'is-nav-collapsed');
      $('#navToggle').setAttribute('aria-expanded', String(narrow ? page.classList.contains('is-nav-open') : !page.classList.contains('is-nav-collapsed')));
    });
  },
  go() {
    if ($('#appView').hidden) return;
    UserMenu.close();
    const page = Session.allowed ? 'overview' : 'noaccess';
    $$('[data-page]').forEach(el => { el.hidden = el.dataset.page !== page; });
    this.page = page;
    Overview.stop();
    if (page === 'overview') run(null, () => Overview.load());
    window.scrollTo(0, 0);
  },
};

/* =========================================================================
   Overview: one card per product of the site
   ========================================================================= */
const Overview = {
  data: null,
  timer: 0,
  selected: tabStore.get('health_product') || '',   // the product whose checks that are not healthy are shown
  open: new Set(),                                   // the checks opened in it
  BAD: ['fail', 'warn', 'error', 'unknown', 'stopped', 'skip'],
  ORDER: {fail: 0, warn: 1, error: 2, unknown: 2, stopped: 2, skip: 2},
  init() {
    $('#hcProducts').addEventListener('click', e => { const c = e.target.closest('[data-product]'); if (c) this.select(c.dataset.product); });
    $('#hcProducts').addEventListener('keydown', e => {
      if ((e.key === 'Enter' || e.key === ' ') && e.target.matches('[data-product]')) { e.preventDefault(); this.select(e.target.dataset.product); }
    });
    $('#hcDetail').addEventListener('click', e => {
      if (e.target.closest('[data-close-detail]')) return this.select('');
      if (e.target.closest('[data-expand-all]')) {
        const p = this.data.products.find(x => x.id === this.selected);
        const bad = p.checks.filter(c => this.BAD.includes(c.status)).map(c => c.key);
        const all = bad.every(id => this.open.has(id));
        bad.forEach(id => (all ? this.open.delete(id) : this.open.add(id)));
        return this.renderDetail();
      }
      if (e.target.closest('a')) return;
      const row = e.target.closest('tr.hc-row');
      if (!row) return;
      const id = row.dataset.check;
      if (this.open.has(id)) this.open.delete(id); else this.open.add(id);
      this.renderDetail();
    });
    $('#hcRun').addEventListener('click', () => run(null, async () => {   // stays off while the round runs (render)
      const b = $('#hcRun');
      b.disabled = true;
      try { await this.runNow(); } finally { if (!this.data?.running) b.disabled = false; }
    }));
    $('#hcRefresh').addEventListener('click', e => run(e.currentTarget, () => this.load()));
  },
  stop() { clearTimeout(this.timer); this.timer = 0; },
  select(id) {
    this.selected = this.selected === id ? '' : id;   // the same card again closes it
    tabStore.set('health_product', this.selected);
    this.open.clear();
    this.render();
    if (this.selected) $('#hcDetail').scrollIntoView({behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start'});
    window.PortalGuide?.changed();
  },
  async load() {
    this.stop();
    const site = Site.current;
    if (!site) return;
    const data = await api(`/api/overview?site=${encodeURIComponent(site)}`);
    if (Router.page !== 'overview' || site !== Site.current) return;
    this.data = data;
    this.render();
    if (data.running) this.timer = setTimeout(() => run(null, () => this.load()), 15000);   // the results come in as each check ends
    window.PortalGuide?.changed();
  },
  async runNow() {
    const site = Site.current;
    await api('/api/rounds', {site});
    toast(`Status round of ${site} started: every check runs one after the other (read only).`, 'success');
    await this.load();
  },
  when(d) {
    const r = d.round;
    const parts = [];
    if (d.running) parts.push(`Round #${r.id} running (${r.trigger === 'auto' ? 'by itself' : `Run now by ${r.username}`})`);
    else if (r) parts.push(`Last round ${shortTime(r.started)} (${r.trigger === 'auto' ? 'by itself' : `Run now by ${r.username}`})`);
    else parts.push('No round yet');
    if (d.next && !d.running) parts.push(`next ${shortTime(d.next)}`);
    return parts.join(' · ');
  },
  render() {
    const d = this.data;
    $('#hcInterval').textContent = d.interval_hours || '-';
    $('#hcWhen').textContent = this.when(d);
    $('#hcRun').disabled = d.running;
    const none = d.products.every(p => p.status === 'not-configured');
    $('#hcNotice').innerHTML = none ? alertBox('info', `No product is configured on ${esc(d.site)}`,
      'The checks need OpenStack (mgmt, director), ONTAP or the read-only accounts of VMware Cloud of this site (sites.yml, Administration → Credentials).') : '';
    if (this.selected && !d.products.some(p => p.id === this.selected && p.status !== 'not-configured')) this.selected = '';
    $('#hcProducts').innerHTML = d.products.map(p => this.card(p)).join('');
    this.renderDetail();
  },
  // A product of the site in short: its status and how many checks are in each state; a click shows what is not healthy
  card(p) {
    const n = s => p.counts[s] || 0;
    const configured = p.status !== 'not-configured';
    const sel = configured && this.selected === p.id;
    const notOk = p.checks.filter(c => this.BAD.includes(c.status)).length;
    const pending = n('running') + n('waiting');
    const tile = (value, text, cls) => `<div class="kpi is-static ${value ? cls : 'is-zero'}"><span class="kpi-value">${value}</span>`
      + `<span class="kpi-label">${text}</span></div>`;
    const tiles = configured && p.status !== 'never' ? `<div class="kpis">${tile(n('fail'), 'Problem', 'is-critical')}${tile(n('warn'), 'Warning', 'is-high')}`
      + `${tile(n('error') + n('unknown') + n('stopped') + n('skip'), 'Could not run', '')}${tile(n('ok'), 'OK', 'is-ok')}</div>` : '';
    const foot = !configured ? `<span class="pf-text-secondary">Not configured on this site.</span>`
      : p.status === 'never' ? '<span class="pf-text-secondary">Not checked yet: the first round fills it in.</span>'
      : (pending ? `<span class="pf-text-secondary">${icon('in-progress')}${pending} check${pending === 1 ? '' : 's'} still running</span> ` : '')
        + (notOk ? `<span class="hc-link">${sel ? 'Hide' : 'Show'} what is not healthy (${notOk})${icon('angle-right')}</span>`
          : pending ? '' : `<span class="hc-ok">${icon('check-circle')}Every check is OK</span>`);
    const attrs = configured && p.status !== 'never' ? ` data-product="${esc(p.id)}" role="button" tabindex="0" aria-expanded="${sel}" aria-controls="hcDetail"` : '';
    return `<article class="pf-card hc-card is-${esc(p.status)}${sel ? ' is-selected' : ''}${attrs ? ' is-clickable' : ''}"${attrs}>`
      + `<div class="pf-card__header">${icon(p.icon)}<h2 class="pf-card__title">${esc(p.title)}`
      + `${p.read_only ? ' <span class="pf-text-secondary pf-text-sm">(read only)</span>' : ''}</h2>`
      + `<span class="pf-card__actions">${lab(PRODUCT, p.status)}</span></div>`
      + `<div class="pf-card__body">${tiles}<div class="hc-card-foot">${foot}</div></div></article>`;
  },
  // The product clicked: its checks that are not OK (worst first), each opening on what it found and what to do
  renderDetail() {
    const box = $('#hcDetail');
    const p = this.data?.products.find(x => x.id === this.selected);
    if (!p) { box.hidden = true; box.innerHTML = ''; return; }
    const bad = p.checks.filter(c => this.BAD.includes(c.status)).sort((a, b) => (this.ORDER[a.status] ?? 9) - (this.ORDER[b.status] ?? 9));
    const names = list => list.map(c => esc(c.title)).join(', ');
    const ok = p.checks.filter(c => c.status === 'ok');
    const pending = p.checks.filter(c => ['running', 'waiting', 'never'].includes(c.status));
    const off = p.checks.filter(c => c.status === 'not-configured');
    const rest = [ok.length ? `${lab(CHECK, 'ok')} ${names(ok)}` : '', pending.length ? `${lab(CHECK, 'running')} ${names(pending)}` : '',
      off.length ? `${lab(CHECK, 'not-configured')} ${names(off)}` : ''].filter(Boolean).map(x => `<p class="hc-rest-line">${x}</p>`).join('');
    const allOpen = bad.length && bad.every(c => this.open.has(c.key));
    box.hidden = false;
    box.innerHTML = `<div class="pf-card"><div class="pf-card__header">${icon(p.icon)}<h2 class="pf-card__title">${esc(p.title)}: `
      + `${bad.length ? `${plural(bad.length, 'check')} not healthy` : 'every check is OK'}</h2><span class="pf-card__actions">`
      + `<button type="button" class="pf-btn pf-m-plain" data-close-detail aria-label="Close" title="Close">${icon('x')}</button></span></div>`
      + (bad.length ? '<div class="pf-table-wrap"><table class="pf-table hc-table"><thead><tr>'
        + `<th class="hc-toggle-col"><button type="button" class="pf-table__toggle" data-expand-all aria-expanded="${allOpen}" aria-label="${allOpen ? 'Collapse' : 'Expand'} every check">${icon('angle-right')}</button></th>`
        + '<th class="hc-col-status">Status</th><th class="hc-col-check">Check</th><th class="hc-col-when">Checked</th></tr></thead>'
        + bad.map(c => this.row(c)).join('') + '</table></div>' : '')
      + (rest ? `<div class="pf-card__body hc-rest">${rest}</div>` : '') + '</div>';
  },
  row(c) {
    const id = esc(c.key.replace(/[^A-Za-z0-9_-]/g, '_'));
    const open = this.open.has(c.key);
    const run = c.run_id ? `<a class="mono" href="/runbook/#/runs/${c.run_id}">Run #${c.run_id}</a>` : '';
    return `<tbody><tr class="hc-row${open ? ' is-expanded' : ''}" data-check="${esc(c.key)}">`
      + `<td class="hc-toggle-col"><button type="button" class="pf-table__toggle" data-toggle aria-expanded="${open}" aria-controls="hcd-${id}" `
      + `aria-label="Details of ${esc(c.title)}">${icon('angle-right')}</button></td>`
      + `<td class="hc-col-status">${lab(CHECK, c.status)}</td>`
      + `<td class="hc-col-check"><b>${esc(c.title)}</b>${c.summary || c.note ? `<span class="pf-table__sub">${esc(c.summary || c.note)}</span>` : ''}</td>`
      + `<td class="hc-col-when">${esc(shortTime(c.finished))}${run ? `<span class="pf-table__sub">${run}</span>` : ''}</td></tr>`
      + `<tr class="hc-detail" id="hcd-${id}"${open ? '' : ' hidden'}><td class="hc-toggle-col"></td><td class="hc-detail-cell" colspan="3">${this.detailHtml(c)}</td></tr></tbody>`;
  },
  detailHtml(c) {
    const findings = c.findings.map(f => `<li>${lab(CHECK, f.status)} <b>${esc(f.title)}</b>${f.detail ? `<span class="hc-sub">${esc(f.detail)}</span>` : ''}</li>`).join('');
    const recs = c.recommendations.map(r => `<li>${r.fix ? `<span class="pf-label pf-m-compact pf-m-blue" title="Ask for it on the run (Run this fix): pre-check, then an engineer's review">${icon('tool')}Fix</span> ` : ''}${esc(r.title)}</li>`).join('');
    const next = c.next.map(x => `<li><a href="/runbook/#/checks/${encodeURIComponent(x.id)}">${esc(x.title)}</a></li>`).join('');
    const block = (title, body) => body ? `<section class="hc-block"><h3 class="hc-h">${title}</h3><ul class="hc-list">${body}</ul></section>` : '';
    const blocks = block('What it found', findings) + block('Recommendations', recs) + block('Check next', next);
    return (blocks ? `<div class="hc-blocks">${blocks}</div>` : `<p class="pf-text-secondary">${esc(c.note || 'No detail: open its run.')}</p>`)
      + (c.run_id ? `<p class="hc-open-run"><a class="pf-btn pf-m-secondary pf-m-small" href="/runbook/#/runs/${c.run_id}">${icon('external')}Open run #${c.run_id}</a></p>` : '');
  },
};

document.addEventListener('DOMContentLoaded', async () => {
  UserMenu.init();
  Overview.init();
  Router.init();
  if (!location.hash) history.replaceState(null, '', '#/overview');
  const status = await Session.refresh();
  if (!status) return toast('Cannot reach the portal server.');
  if (status.user) Router.go();
  let active = false;   // keep the portal session alive while this page is used
  ['click', 'keydown'].forEach(ev => document.addEventListener(ev, () => { active = true; }, {passive: true}));
  setInterval(async () => {
    if (!active) return;
    active = false;
    try {
      const data = await (await fetch('/api/keepalive', {method: 'POST'})).json();
      if (!data.user) window.PortalLauncher?.signIn();
    } catch (e) { /* server not reachable for a moment */ }
  }, 120000);
});

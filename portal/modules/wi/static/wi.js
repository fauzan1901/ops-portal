'use strict';
/* Operation Automation (portal module /wi/): catalog of checks from the Knowledge Base work instructions, launch form, runs, and
   the result of a run per WI step with the live Ansible output. Same look and helpers as ONTAP Restore Web UI
   (PatternFly v5 like AWX, docs/UI-SPEC.md); sign-in, users and credentials belong to the portal. */

/* =========================================================================
   Utilities (same as ONTAP Restore Web UI)
   ========================================================================= */
const BASE = '/wi';
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
const qs = params => Object.entries(params).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v ?? '')}`).join('&');
const icon = name => `<svg class="pf-icon" aria-hidden="true"><use href="#i-${name}"></use></svg>`;
// One of the items of a fix: "instances" -> "instance", "FDB entries" -> "FDB entry".
const singular = noun => String(noun || '').replace(/ies$/, 'y').replace(/s$/, '');
// A work instruction: a link to its Knowledge Base page, or its title only when it is not in the Knowledge Base yet.
const wiRef = (w, cls = '') => w.url
  ? `<a${cls ? ` class="${cls}"` : ''} href="${esc(w.url)}" target="_blank" rel="noopener">${esc(w.title)}${icon('external')}</a>`
  : `<span${cls ? ` class="${cls}"` : ''}>${esc(w.title)}</span>`;
const sleep = ms => new Promise(r => setTimeout(r, ms));

function storage(area) {
  return {
    get(key) { try { return window[area].getItem(key); } catch (e) { return null; } },
    set(key, value) { try { window[area].setItem(key, value); } catch (e) { /* storage not available */ } },
  };
}
const tabStore = storage('sessionStorage');

const BASE_TITLE = document.title;
const UI_VERSION = document.querySelector('meta[name="ui-version"]')?.content || '';
const SITE_COLORS = ['#2b9af3', '#3e8635', '#8476d1', '#ec7a08', '#c9190b', '#009596'];

function fmtTime(iso) {
  if (!iso) return '-';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString('en-GB', {day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23'}).replace('Sept', 'Sep');
}
function shortTime(iso) {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? (iso || '-') : d.toLocaleString('en-GB', {day: 'numeric', month: 'short', hour: '2-digit',
    minute: '2-digit', hourCycle: 'h23'}).replace('Sept', 'Sep');
}
function bytes(n) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = Number(n) || 0, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  return `${i ? v.toFixed(v < 10 ? 1 : 0) : v} ${units[i]}`;
}
function duration(seconds) {
  const s = Math.max(0, Math.round(seconds));
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, '0')}s`;
}
function dl(rows) {
  return `<dl class="pf-dl pf-m-horizontal">${rows.filter(Boolean).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join('')}</dl>`;
}
// The first sentence of a recommendation is its title (not split inside "e.g.", "i.e.", "vs." or a number like 1.5).
function splitTitle(text) {
  const t = String(text || '').trim();
  const m = /(?<!\b(?:e\.g|i\.e|etc|vs|approx))(?<!\d)\.\s+(?=[A-Z0-9("])/.exec(t);
  return m ? [t.slice(0, m.index + 1), t.slice(m.index + m[0].length)] : [t, ''];
}
function alertBox(kind, title, body = '') {
  const name = {success: 'check-circle', danger: 'x-circle', warning: 'alert', info: 'info'}[kind];
  return `<div class="pf-alert pf-m-${kind}"${kind === 'danger' ? ' role="alert"' : ''}>${icon(name)}<div class="pf-alert__title">${title}</div>`
    + (body ? `<div class="pf-alert__body">${body}</div>` : '') + '</div>';
}
document.addEventListener('click', e => {
  const btn = e.target.closest('[data-copy]');
  if (!btn) return;
  navigator.clipboard?.writeText(btn.dataset.copy).then(() => toast('Copied to clipboard', 'success'), () => toast('Copy failed'));
});

// Result of a check (and of every step): the check's own rating, or that it could not run.
const RESULT = {
  ok: ['OK', 'green', 'check-circle'], warn: ['Warning', 'gold', 'alert'], fail: ['Problem found', 'red', 'x-circle'],
  skip: ['Not checked', '', 'minus-circle'], info: ['Info', 'blue', 'info'], running: ['Running', 'blue', 'in-progress'],
  error: ['Could not run', 'red', 'x-circle'], unknown: ['Unknown', 'gold', 'alert'],
};
const resultLabel = s => { const [text, color, ic] = RESULT[s] || [s, '', 'info']; return `<span class="pf-label${color ? ` pf-m-${color}` : ''}">${icon(ic)}${esc(text)}</span>`; };
const CHECK_STATUS = {ready: ['Ready', 'green', 'check-circle'], planned: ['Planned', 'gold', 'in-progress'],
  manual: ['Manual (WI)', '', 'info'], module: ['Portal module', 'blue', 'angle-right']};
const checkStatusLabel = c => {
  const [text, color, ic] = CHECK_STATUS[c.status] || [c.status, '', 'info'];
  return `<span class="pf-label${color ? ` pf-m-${color}` : ''}">${icon(ic)}${esc(text)}</span>`
    + (c.validation === 'lab' ? ' <span class="pf-label pf-m-gold" title="Commands to be validated on a lab device first">Lab validation</span>' : '');
};
const READS = {openstack: 'OpenStack', undercloud: 'Undercloud (ironic)', ontap: 'ONTAP', 'ro-vcenter': 'vCenter (read-only)',
  'ro-nsxt': 'NSX-T (read-only)', 'ro-vcd': 'vCloud Director (read-only)', 'hosts:bmc': 'BMC (Redfish)'};
const readsLabel = need => READS[need] || (need.startsWith('hosts:') ? `SSH ${need.slice(6).split('|').join(', ')}` : need);

/* =========================================================================
   Requests and notifications
   ========================================================================= */
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

async function downloadFile(url, fallbackName) {
  const res = await fetch(BASE + url);
  if (!res.ok) {
    let data = {};
    try { data = await res.json(); } catch (e) { /* not JSON */ }
    if (res.status === 401) window.PortalLauncher?.signIn();
    throw new Error(data.error || `HTTP ${res.status}`);
  }
  const name = (res.headers.get('Content-Disposition') || '').match(/filename="?([^";]+)"?/)?.[1] || fallbackName;
  const link = document.createElement('a');
  link.href = URL.createObjectURL(await res.blob());
  link.download = name;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 5000);
  toast(`${name} downloaded.`, 'success');
}

function toast(message, kind = 'danger', action = null) {
  const box = document.createElement('div');
  box.innerHTML = alertBox(kind, esc(message));
  const el = box.firstElementChild;
  if (action) {
    const link = document.createElement('button');
    link.type = 'button';
    link.className = 'pf-btn pf-m-link pf-m-inline pf-alert__action';
    link.textContent = action.label;
    link.addEventListener('click', action.fn);
    const body = document.createElement('div');
    body.className = 'pf-alert__body';
    body.appendChild(link);
    el.appendChild(body);
  }
  const close = document.createElement('button');
  close.type = 'button';
  close.className = 'pf-btn pf-m-plain pf-m-small';
  close.setAttribute('aria-label', 'Close');
  close.innerHTML = icon('x');
  close.addEventListener('click', () => el.remove());
  el.insertBefore(close, el.children[2] || null);
  $('#toasts').appendChild(el);
  if (!action) setTimeout(() => el.remove(), kind === 'danger' ? 10000 : 5000);
}

async function run(button, fn) {
  if (button) {
    button.disabled = true;
    button.classList.add('is-loading');
  }
  try {
    return await fn();
  } catch (e) {
    toast(e.message);
  } finally {
    if (button) {
      button.disabled = false;
      button.classList.remove('is-loading');
    }
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
  set(status) { this.list = (status.sites || []).map((x, i) => ({...x, color: SITE_COLORS[i % SITE_COLORS.length]})); },
  info(name) { return this.list.find(x => x.name === name) || {name, color: SITE_COLORS[0], groups: []}; },
  render() {
    $('#siteSwitch').innerHTML = this.list.map(x => `<label title="Site ${esc(x.name)}"><input type="radio" name="site" value="${esc(x.name)}"`
      + `${x.name === this.current ? ' checked' : ''}><span><span class="site-dot" style="--site-color:${x.color}"></span>${esc(x.name)}</span></label>`).join('');
    $('#navSites').innerHTML = this.list.map(x => `<div><span class="site-dot" style="--site-color:${x.color}"></span>${esc(x.name)}`
      + `<span class="pf-text-sm">${x.openstack ? 'OpenStack' : ''}${x.groups.length ? `${x.openstack ? ' · ' : ''}${esc(x.groups.join(', '))}` : ''}</span></div>`).join('');
  },
  activate(name) {
    this.current = name;
    if (name) tabStore.set('wi_site', name);
    document.title = name ? `[${name}] ${BASE_TITLE}` : BASE_TITLE;
    $$('.site-name-current').forEach(el => { el.textContent = name || '-'; });
  },
};

const Session = {
  user: null,
  outdated: false,
  isAdmin() { return this.user?.role === 'admin'; },
  checkVersion(status) {
    if (this.outdated || !status.ui_version || !UI_VERSION || status.ui_version === UI_VERSION) return;
    this.outdated = true;
    toast('A new version of Operation Automation is available. Reload the page.', 'info', {label: 'Reload', fn: () => location.reload()});
  },
  apply(status) {
    this.checkVersion(status);
    if (!status.user) return window.PortalLauncher?.signIn();
    this.user = status.user;
    this.allowed = status.allowed;
    this.canFix = !!status.can_fix;
    this.admin = !!status.is_admin;
    UserMenu.render(this.user, status.client);
    $$('.admin-only').forEach(el => { el.hidden = !this.isAdmin(); });
    $('#appView').hidden = false;
    Site.set(status);
    const names = Site.list.map(x => x.name);
    Site.activate([Site.current, tabStore.get('wi_site')].find(n => n && names.includes(n)) || names[0] || '');
    Site.render();
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
    $('#userMenuWrap').addEventListener('keydown', e => {
      if (e.key === 'Escape' && this.isOpen()) {
        this.close();
        $('#userToggle').focus();
      }
    });
    $('#userMenuWrap').addEventListener('focusout', e => { if (!e.currentTarget.contains(e.relatedTarget)) this.close(); });
  },
  isOpen() { return !$('#userMenu').hidden; },
  open() {
    $('#userMenu').hidden = false;
    $('#userToggle').setAttribute('aria-expanded', 'true');
    $('#logoutBtn').focus();
  },
  close() {
    $('#userMenu').hidden = true;
    $('#userToggle').setAttribute('aria-expanded', 'false');
  },
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

/* =========================================================================
   Navigation (hash): #/checks (all products), #/products/<product>, #/checks/<id>, #/runs, #/runs/<id>
   ========================================================================= */
const Router = {
  init() {
    window.addEventListener('hashchange', () => this.go());
    $('#siteSwitch').addEventListener('change', e => {
      if (e.target.name !== 'site') return;
      Site.activate(e.target.value);
      Catalog.loaded = '';
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
    const [, section = 'checks', id] = (location.hash.match(/^#\/([a-z]+)(?:\/([a-z0-9-]+))?/) || []);
    let page = section === 'runs' ? (id ? 'run' : 'runs') : ['products', 'activities'].includes(section) ? 'product'
      : section === 'templates' ? 'template' : section === 'hosts' ? 'hosts' : section === 'bmc' ? 'bmc' : id ? 'launch' : 'checks';
    if (!Session.allowed) page = 'noaccess';
    $$('[data-page]').forEach(el => { el.hidden = el.dataset.page !== page; });
    this.page = page;
    Nav.current = {checks: 'checks', runs: 'runs', run: 'runs', product: `${section === 'activities' ? 'activity' : 'product'}:${id}`,
      launch: `check:${id}`, hosts: 'hosts', bmc: 'bmc'}[page] || '';
    $$('.pf-nav__link[data-route]').forEach(a => a.classList.toggle('is-current', a.dataset.route === Nav.current));
    Nav.sync();
    if (page !== 'run') {
      RunPage.stop();
      document.title = Site.current ? `[${Site.current}] ${BASE_TITLE}` : BASE_TITLE;
    }
    if (page === 'checks') run(null, () => Catalog.showOverview());
    if (page === 'product') run(null, () => Catalog.showList(section === 'activities' ? 'activity' : 'product', id));
    if (page === 'launch') run(null, () => Launch.open(id));
    if (page === 'template') run(null, () => TemplateForm.open(id || 'new'));
    if (page === 'runs') run(null, () => Runs.load());
    if (page === 'hosts') run(null, () => Hosts.load());
    if (page === 'bmc') run(null, () => Bmcs.load());
    if (page === 'run') RunPage.open(Number(id));
    window.scrollTo(0, 0);
  },
};

/* =========================================================================
   Left menu: one expandable group per product (PatternFly Nav, expandable), its problems under it
   ========================================================================= */
const Nav = {
  current: '',
  init() {},
  // What the operator wants to do (activities), then the products: one link each with its number of checks. The checks
  // themselves are on the page of each (a short menu that fits on one screen).
  render() {
    const data = Catalog.data;
    if (!data) return;
    // the short name on one line, the full one as its tooltip ("Network" for "Network (VyOS, NSX-T, Huawei, ACI)")
    const link = (route, href, ic, title, n, short) => `<li><a class="pf-nav__link" href="${href}" data-route="${route}" title="${esc(title)}">${icon(ic)}`
      + `<span class="pf-nav__text">${esc(short || title)}</span><span class="pf-nav__count">${n}</span></a></li>`;
    $('#navActivities').innerHTML = (data.activities || []).map(a => {
      const n = data.checks.filter(c => c.activity === a.id).length;
      return n ? link(`activity:${a.id}`, `#/activities/${a.id}`, a.icon, a.title, n, a.short) : '';
    }).join('');
    $('#navProducts').innerHTML = data.categories.map(cat => {
      const n = data.checks.filter(c => c.category === cat.id).length;
      return n ? link(`product:${cat.id}`, `#/products/${cat.id}`, cat.icon || 'checklist', cat.title, n, cat.short) : '';
    }).join('');
    this.sync();
  },
  // The current page in the menu; a check also marks its activity and its product.
  sync() {
    const check = this.current.startsWith('check:') ? (Catalog.data?.checks || []).find(c => c.id === this.current.slice(6)) : null;
    $$('.pf-nav__link[data-route]').forEach(a => {
      const r = a.dataset.route;
      a.classList.toggle('is-current', r === this.current || (!!check && (r === `product:${check.category}` || r === `activity:${check.activity}`)));
    });
  },
};

/* =========================================================================
   Products: an overview card per product, one page per product with its problems (like the Templates list of AWX)
   ========================================================================= */
const Catalog = {
  data: null,
  loaded: '',
  mode: 'product',   // the list page shows one product, or one activity
  id: '',
  store: storage('localStorage'),
  open: new Set(),   // rows opened (details shown)
  sort: {key: '', dir: 'asc'},
  init() {
    const openRun = e => {
      const tr = e.target.closest('tr[data-run]');
      if (tr && (e.type === 'click' || e.key === 'Enter') && !e.target.closest('a')) location.hash = `#/runs/${tr.dataset.run}`;
    };
    $('#ovRecentList').addEventListener('click', openRun);
    $('#ovRecentList').addEventListener('keydown', openRun);
    $('#ckQ').addEventListener('input', () => this.renderList());
    $('#ckFilter').addEventListener('change', () => this.renderList());
    $('#ckRunnable').checked = this.store.get('wi_runnable') === '1';
    $('#ckRunnable').addEventListener('change', e => { this.store.set('wi_runnable', e.target.checked ? '1' : ''); this.renderList(); });
    $('#ovQ').addEventListener('input', () => this.renderSearch());
    ['#ckList', '#ovList'].forEach(sel => $(sel).addEventListener('click', e => {
      if (e.target.closest('[data-clear]')) { this.clear(); return; }
      const sort = e.target.closest('[data-sort]');
      if (sort) {
        const key = sort.dataset.sort;
        this.sort = this.sort.key === key ? {key, dir: this.sort.dir === 'asc' ? 'desc' : 'asc'} : {key, dir: key === 'last' ? 'desc' : 'asc'};
        this.redraw();
        return;
      }
      if (e.target.closest('[data-expand-all]')) {
        const rows = $$('tr.ck-row', $(sel));
        const open = rows.some(r => !this.open.has(r.dataset.check));
        rows.forEach(r => this.expand(r, open));
        return;
      }
      // the toggle, or a click anywhere on a row (not on its links and buttons), opens or closes its details
      const row = e.target.closest('tr.ck-row');
      if (row && (e.target.closest('[data-toggle]') || !e.target.closest('a,button'))) this.expand(row, !this.open.has(row.dataset.check));
    }));
    // "/" goes to the search of the page, Esc empties it
    document.addEventListener('keydown', e => {
      const typing = e.target.closest('textarea,select,[contenteditable]')
        || (e.target.matches('input') && !['radio', 'checkbox', 'button', 'submit'].includes(e.target.type));
      if (e.key === '/' && !typing && !e.ctrlKey && !e.metaKey && !e.altKey) {
        const box = $$('[data-search]').find(x => x.offsetParent !== null);
        if (box) { e.preventDefault(); box.focus(); box.select(); }
      }
      if (e.key === 'Escape' && e.target.matches('[data-search]') && e.target.value) {
        e.target.value = '';
        e.target.dispatchEvent(new Event('input'));
      }
    });
  },
  async load(force = false) {
    if (!force && this.data && this.loaded === Site.current) return this.data;
    this.data = await api(`/api/catalog?${qs({site: Site.current})}`);
    this.loaded = Site.current;
    Nav.render();
    return this.data;
  },
  category(id) { return (this.data?.categories || []).find(c => c.id === id); },
  activity(id) { return (this.data?.activities || []).find(a => a.id === id); },
  // Both pages draw at once from the catalog already loaded, then again with the fresh one (access per site changes).
  async showOverview() {
    $$('[data-create-template]').forEach(b => { b.hidden = !Session.admin; });
    if (this.data && this.loaded === Site.current) { this.renderOverview(); this.renderSearch(); }
    this.renderRecent();
    await this.load(true);
    this.renderOverview();
    this.renderSearch();
  },
  async showList(mode, id) {
    $$('[data-create-template]').forEach(b => { b.hidden = !Session.admin; });
    if (this.data && this.loaded === Site.current) this.drawList(mode, id, true);
    await this.load(true);
    this.drawList(mode, id, false);
  },
  drawList(mode, id, first) {
    const meta = mode === 'activity' ? this.activity(id) : this.category(id);
    const changed = this.mode !== mode || this.id !== id;
    this.mode = mode;
    this.id = id;
    $('#pdCrumb').textContent = meta ? meta.title : id;
    $('#pdTitle').textContent = meta ? meta.title : (mode === 'activity' ? 'Unknown activity' : 'Unknown product');
    $('#pdIcon').innerHTML = icon(meta?.icon || 'checklist');
    $('#pdSummary').textContent = meta?.summary || '';
    if (first || changed) {
      $('#ckQ').value = '';
      $('#ckFilter').innerHTML = this.filterHtml();
    }
    this.renderList();
  },
  // The second filter: the activities of a product (toggle group), or the products of an activity (select).
  filterHtml() {
    const all = this.inScope();
    if (this.mode === 'activity') {
      const cats = this.data.categories.map(c => [c, all.filter(x => x.category === c.id).length]).filter(([, n]) => n);
      return `<select class="pf-form-control ck-product" id="ckProduct" aria-label="Product"><option value="">All products (${all.length})</option>`
        + cats.map(([c, n]) => `<option value="${esc(c.id)}">${esc(c.title)} (${n})</option>`).join('') + '</select>';
    }
    const acts = (this.data.activities || []).map(a => [a, all.filter(x => x.activity === a.id).length]).filter(([, n]) => n);
    if (acts.length < 2) return '';
    return `<div class="pf-toggle-group pf-m-compact" role="radiogroup" aria-label="Activity">`
      + `<label><input type="radio" name="ckAct" value="" checked><span>All ${all.length}</span></label>`
      + acts.map(([a, n]) => `<label><input type="radio" name="ckAct" value="${esc(a.id)}"><span>${esc(a.short)} ${n}</span></label>`).join('')
      + '</div>';
  },
  inScope() {
    return this.data.checks.filter(c => this.mode === 'activity' ? c.activity === this.id : c.category === this.id);
  },
  clear() {
    const page = Router.page === 'checks' ? '#ovQ' : '#ckQ';
    $(page).value = '';
    if (Router.page !== 'checks') {
      const all = $('#ckFilter input[value=""]');
      if (all) all.checked = true;
      if ($('#ckProduct')) $('#ckProduct').value = '';
      $('#ckRunnable').checked = false;
      this.store.set('wi_runnable', '');
      this.renderList();
    } else this.renderSearch();
    $(page).focus();
  },
  counts(checks) {
    const ready = checks.filter(c => c.status === 'ready');
    return {total: checks.length, ready: ready.length, runnable: ready.filter(c => c.access.runnable).length};
  },
  // Home: the problems an operator sees, each with the checks for it
  renderOverview() {
    const byId = Object.fromEntries(this.data.checks.map(c => [c.id, c]));
    $('#ovSymptoms').innerHTML = (this.data.symptoms || []).map(s => `<div class="pf-card ov-symptom"><div class="ov-symptom__title">`
      + `${icon(s.icon)}<h3>${esc(s.title)}</h3></div><ul class="ov-symptom__checks">`
      + s.checks.filter(id => byId[id]).map(id => `<li><a href="#/checks/${esc(id)}" title="${esc(byId[id].does || '')}">`
        + `${icon('angle-right')}${esc(byId[id].title)}</a></li>`).join('') + '</ul></div>').join('');
  },
  // The last runs of this site that found a problem (as the Recent Jobs of the AWX dashboard): one click back to them.
  // Activities and products are in the menu.
  async renderRecent() {
    const site = Site.current;
    let items = [];
    try {
      items = (await api(`/api/runs?limit=40&site=${encodeURIComponent(site)}`)).items || [];
    } catch (e) {
      items = [];
    }
    if (site !== Site.current) return;
    const bad = items.filter(r => r.status === 'fail' || r.status === 'warn').slice(0, 6);
    $('#ovRecent').hidden = !bad.length;
    $('#ovRecentList').innerHTML = bad.map(r => `<tr class="is-clickable" tabindex="0" data-run="${r.id}">`
      + `<td><a href="#/runs/${r.id}">${esc(r.check_title)}</a><span class="pf-table__sub">${esc(r.summary || '')}</span></td>`
      + `<td class="pf-nowrap">${resultLabel(r.status)}</td><td class="pf-nowrap" title="${esc(fmtTime(r.ts))}">${esc(shortTime(r.ts))}</td>`
      + `<td class="mono pf-nowrap">${esc(r.username)}</td></tr>`).join('');
  },
  matches(c, q) {
    if (!q) return true;
    const symptoms = (this.data?.symptoms || []).filter(s => s.checks.includes(c.id)).map(s => s.title);
    return [c.title, c.does, c.summary, c.id, ...c.wi.map(w => w.title), ...symptoms].some(t => String(t || '').toLowerCase().includes(q));
  },
  // Search across every check: grouped by activity; the cards stay below.
  renderSearch() {
    const q = $('#ovQ').value.trim().toLowerCase();
    $('#ovResults').hidden = !q;
    if (!q || !this.data) return;
    const shown = this.data.checks.filter(c => this.matches(c, q));
    $('#ovShown').textContent = `${shown.length} check${shown.length === 1 ? '' : 's'}`;
    $('#ovList').innerHTML = this.listHtml(shown, ['product', 'type', 'last'], 'Search results');
  },
  renderList() {
    if (!this.data) return;
    const q = $('#ckQ').value.trim().toLowerCase();
    const act = $('#ckFilter input:checked')?.value || '';
    const prod = $('#ckProduct')?.value || '';
    const runnable = $('#ckRunnable').checked;
    const all = this.inScope();
    const shown = all.filter(c => this.matches(c, q) && (!act || c.activity === act) && (!prod || c.category === prod)
      && (!runnable || (c.status === 'ready' && c.access.runnable)));
    const n = this.counts(all);
    $('#ckShown').textContent = `${shown.length} of ${all.length} · ${n.runnable} runnable on ${Site.current}`;
    const title = (this.mode === 'activity' ? this.activity(this.id) : this.category(this.id))?.title || '';
    $('#ckList').innerHTML = this.listHtml(shown, this.mode === 'activity' ? ['product', 'type', 'last'] : ['type', 'last'], `Checks of ${title}`);
  },
  redraw() { if (Router.page === 'checks') this.renderSearch(); else this.renderList(); },
  expand(row, open) {
    const id = row.dataset.check;
    if (open) this.open.add(id); else this.open.delete(id);
    row.classList.toggle('is-expanded', open);
    $('[data-toggle]', row).setAttribute('aria-expanded', String(open));
    row.nextElementSibling.hidden = !open;
    const table = row.closest('table');
    const all = $$('tr.ck-row', table).every(r => this.open.has(r.dataset.check));
    const btn = $('[data-expand-all]', table);
    btn.setAttribute('aria-expanded', String(all));
    btn.setAttribute('aria-label', all ? 'Collapse all rows' : 'Expand all rows');
  },
  // Order of the rows: the catalog order within each activity (or product), or the column the operator sorted on
  ordered(checks, groupBy) {
    const idx = (list, id) => { const i = list.findIndex(x => x.id === id); return i < 0 ? 999 : i; };
    const group = c => groupBy === 'category' ? idx(this.data.categories, c.category) : idx(this.data.activities || [], c.activity);
    const base = this.data.checks;
    const keys = {
      name: c => c.title.toLowerCase(),
      activity: c => idx(this.data.activities || [], c.activity),
      product: c => idx(this.data.categories, c.category),
      last: c => (c.runs || [])[0]?.id || 0,
    };
    const key = keys[this.sort.key];
    return [...checks].sort((a, b) => {
      if (key) {
        const [x, y] = [key(a), key(b)];
        if (x !== y) return (x < y ? -1 : 1) * (this.sort.dir === 'asc' ? 1 : -1);
      }
      return group(a) - group(b) || base.indexOf(a) - base.indexOf(b);
    });
  },
  // The checks as a table like the Templates list of AWX (ansible-ui): expandable rows (description, activity of the last
  // runs, WI, what it reads), sortable columns, the last run on this site and a Run action.
  listHtml(checks, cols, label) {
    if (!checks.length) {
      return `<div class="pf-empty-state">${icon('search')}<h2 class="pf-title">No check matches</h2>`
        + '<span>Try another word, or clear the filters.</span><button type="button" class="pf-btn pf-m-link" data-clear>Clear filters</button></div>';
    }
    const rows = this.ordered(checks, this.mode === 'activity' && Router.page === 'product' ? 'category' : 'activity');
    const allOpen = rows.every(c => this.open.has(c.id));
    const head = {name: 'Name', activity: 'Activity', product: 'Product', type: 'What it can do', last: 'Last ran'};
    const th = key => {
      const cls = key === 'name' ? '' : ` class="ck-col-${key}${key === 'last' ? '' : ' ck-opt'}"`;
      if (key === 'type') return `<th scope="col"${cls}>${head[key]}</th>`;
      const sorted = this.sort.key === key;
      return `<th scope="col"${cls}${sorted ? ` aria-sort="${this.sort.dir === 'asc' ? 'ascending' : 'descending'}"` : ''}>`
        + `<button type="button" class="ck-sort" data-sort="${key}">${head[key]}${icon('caret-down')}</button></th>`;
    };
    const keys = ['name', ...cols];
    return `<div class="pf-table-wrap"><table class="pf-table ck-table" aria-label="${esc(label)}"><thead><tr>`
      + `<td class="ck-toggle-col"><button type="button" class="pf-table__toggle" data-expand-all aria-expanded="${allOpen}" `
      + `aria-label="${allOpen ? 'Collapse' : 'Expand'} all rows">${icon('angle-right')}</button></td>`
      + keys.map(th).join('') + '<td class="ck-col-action"></td></tr></thead>'
      + rows.map(c => this.row(c, keys)).join('') + '</table></div>';
  },
  // What a check can do, in words (instead of its activity and kind): check only, check + fix, a change, collects files
  typeHtml(c) {
    const badge = (color, ic, text, title) => `<span class="pf-label ck-can${color ? ` pf-m-${color}` : ''}" title="${esc(title)}">${icon(ic)}${esc(text)}</span>`;
    let out;
    if (c.status === 'module') out = badge('', 'external', 'Portal module', 'Done by another module of the portal');
    else if (c.status === 'manual') out = badge('', 'info', 'Manual (WI)', 'Nothing to read automatically: follow the work instruction');
    else if (c.status === 'planned') out = badge('gold', 'in-progress', 'Planned', c.reason || 'Not runnable yet');
    else if (c.collect) out = badge('cyan', 'download', 'Collects files', 'Collects logs or events into files to download');
    else if (c.fix && c.activity === 'operations') out = badge('orange', 'refresh', 'Makes a change', 'Checks first; the change runs only after you confirm it');
    else if (c.fix) out = badge('blue', 'tool', 'Check + fix', 'Reads only; a fix runs only when you start it from the result');
    else out = badge('green', 'search', 'Check only', 'Reads only; it changes nothing');
    if (c.template) out += ' <span class="pf-label">Template</span>';
    if (c.status === 'ready' && !c.access.runnable) {
      out += ` <span class="pf-label pf-m-gold" title="${esc(c.access.missing.join('; '))}">Not on ${esc(Site.current)}</span>`;
    }
    return out;
  },
  runTitle(r) {
    return `Run #${r.id} · ${(RESULT[r.status] || [r.status])[0]} · ${fmtTime(r.ts)} · ${r.username}`;
  },
  lastHtml(c) {
    const r = (c.runs || [])[0];
    if (!r) return `<span class="ck-muted">${c.status === 'ready' ? 'Never' : '-'}</span>`;
    const ic = (RESULT[r.status] || ['', '', 'info'])[2];
    return `<a class="ck-last" href="#/runs/${r.id}" title="${esc(this.runTitle(r))}">`
      + `<span class="ck-st is-${esc(r.status)}">${icon(ic)}</span>${esc(shortTime(r.ts))}</a>`;
  },
  actionHtml(c) {
    const a = (href, ic, text, ext = false) => `<a class="pf-btn pf-m-plain" href="${esc(href)}" title="${esc(text)}" `
      + `aria-label="${esc(`${text}: ${c.title}`)}"${ext ? ' target="_blank" rel="noopener"' : ''}>${icon(ic)}</a>`;
    if (c.status === 'ready') {
      const edit = c.basis === 'template' && Session.admin ? a(`#/templates/${c.id}`, 'pencil', 'Edit template') : '';
      return (c.access.runnable ? a(`#/checks/${c.id}`, 'play', `Run on ${Site.current}`) : a(`#/checks/${c.id}`, 'info', `Why not on ${Site.current}`)) + edit;
    }
    if (c.status === 'module') return a(c.link, 'angle-right', 'Open module');
    const wi = c.wi.find(w => w.url);
    return wi ? a(wi.url, 'external', 'Open the work instruction', true) : a(`#/checks/${c.id}`, 'info', 'Details');
  },
  // The last runs on this site as bars, oldest left (the Activity sparkline of AWX); each bar opens its run
  sparkline(c) {
    const items = [...(c.runs || [])].reverse();
    if (!items.length) return `<span class="ck-muted">No run on ${esc(Site.current)} yet</span>`;
    return `<span class="ck-spark">${items.map(r => `<a class="is-${esc(r.status)}" href="#/runs/${r.id}" title="${esc(this.runTitle(r))}">`
      + `<span class="sr-only">${esc(this.runTitle(r))}</span></a>`).join('')}</span>`;
  },
  detailHtml(c) {
    const last = (c.runs || [])[0];
    const why = c.status === 'ready' ? (c.access.runnable ? '' : c.access.missing.map(esc).join('<br>')) : esc(c.reason || '');
    const reads = [...(c.needs || []), ...(c.uses || [])];
    const t = c.template;
    return dl([
      ['Description', esc(c.summary)],
      t && ['Template', `Made on the portal by ${esc(t.created_by || '-')}; changed ${esc(shortTime(t.updated))} by ${esc(t.updated_by || '-')}`],
      t && ['Steps', `<ol class="ck-tsteps">${t.steps.map(st => `<li>${esc(st.title)} <span class="pf-label${st.mode === 'change' ? ' pf-m-gold' : ''}">`
        + `${st.mode === 'change' ? 'Changes, after confirmation' : 'Reads'}</span><code class="mono">${esc(st.command)}</code></li>`).join('')}</ol>`],
      c.status === 'ready' && ['Activity', this.sparkline(c)],
      last && last.summary && ['Last result', `${resultLabel(last.status)} ${esc(last.summary)}`],
      c.wi.length && ['Work instructions', c.wi.map(w => wiRef(w, 'wi-link')).join('')],
      reads.length && ['Reads', reads.map(n => `<span class="pf-label">${esc(readsLabel(n))}${(c.uses || []).includes(n) ? ' (optional)' : ''}</span>`).join(' ')],
      why && [c.status === 'ready' ? `Not on ${Site.current}` : 'Why not automated', why],
    ]);
  },
  row(c, keys) {
    const open = this.open.has(c.id);
    const cell = {
      name: () => `<td class="ck-name"><a href="#/checks/${esc(c.id)}">${esc(c.title)}</a>`
        + `<span class="ck-does">${esc(c.does || '')}</span></td>`,
      activity: () => {
        const a = this.activity(c.activity);
        return `<td class="ck-col-activity ck-opt">${a ? `<span class="pf-label">${icon(a.icon)}${esc(a.short)}</span>` : ''}</td>`;
      },
      product: () => `<td class="ck-col-product ck-opt">${esc(this.category(c.category)?.title || c.category)}</td>`,
      type: () => `<td class="ck-col-type ck-opt">${this.typeHtml(c)}</td>`,
      last: () => `<td class="ck-col-last">${this.lastHtml(c)}</td>`,
    };
    return `<tbody><tr class="ck-row${open ? ' is-expanded' : ''}" data-check="${esc(c.id)}">`
      + `<td class="ck-toggle-col"><button type="button" class="pf-table__toggle" data-toggle aria-expanded="${open}" `
      + `aria-controls="ckd-${esc(c.id)}" aria-label="Details of ${esc(c.title)}">${icon('angle-right')}</button></td>`
      + keys.map(k => cell[k]()).join('') + `<td class="ck-col-action">${this.actionHtml(c)}</td></tr>`
      + `<tr class="ck-detail" id="ckd-${esc(c.id)}"${open ? '' : ' hidden'}><td></td>`
      + `<td colspan="${keys.length + 1}">${this.detailHtml(c)}</td></tr></tbody>`;
  },
};

/* =========================================================================
   Templates (administrators): a check of your own in steps, without writing Ansible (like Create job template of AWX,
   with a form instead of a playbook). Each step: one command and the rules that rate its output; the portal says which
   steps only read (they run with the check) and which change the host (a fix, after the host name is typed).
   ========================================================================= */
const TemplateForm = {
  meta: null,
  id: '',          // '' = a new template
  prefill: null,   // {category, activity} of the list the Create button was pressed on
  timer: 0,
  seq: 0,
  init() {
    $('#tpForm').addEventListener('submit', e => { e.preventDefault(); this.save(); });
    $('#tpAdd').addEventListener('click', () => { this.addStep({}); this.classify(); $('#tpSteps li:last-child [data-f="title"]').focus(); });
    $('#tpDelete').addEventListener('click', () => this.remove());
    $('#tpGroup').addEventListener('change', () => this.classify());
    $('#tpSteps').addEventListener('input', e => { if (e.target.dataset.f === 'command') this.classifySoon(); });
    $('#tpSteps').addEventListener('click', e => {
      const btn = e.target.closest('[data-step-tool]');
      if (!btn) return;
      const li = btn.closest('li');
      const tool = btn.dataset.stepTool;
      if (tool === 'remove' && $$('#tpSteps > li').length > 1) li.remove();
      if (tool === 'up' && li.previousElementSibling) li.parentNode.insertBefore(li, li.previousElementSibling);
      if (tool === 'down' && li.nextElementSibling) li.parentNode.insertBefore(li.nextElementSibling, li);
      this.number();
      this.classify();
      (tool === 'remove' ? $('#tpAdd') : btn).focus();
    });
    document.addEventListener('click', e => {
      if (!e.target.closest('[data-create-template]')) return;
      this.prefill = Router.page === 'product' ? {[Catalog.mode === 'activity' ? 'activity' : 'category']: Catalog.id} : null;
      location.hash = '#/templates/new';
    });
  },
  async open(id) {
    $('#tpNotice').innerHTML = '';
    $('#tpError').hidden = true;
    if (!Session.admin) {
      $('#tpForm').hidden = true;
      $('#tpNotice').innerHTML = alertBox('warning', 'Administrators only', 'Only administrators create and change templates. Every user can run them from the check lists.');
      return;
    }
    $('#tpForm').hidden = false;
    this.meta = this.meta || await api('/api/templates/meta');
    const data = await Catalog.load();
    this.id = id === 'new' ? '' : id;
    const t = this.id ? (await api(`/api/templates/${encodeURIComponent(this.id)}`)).template
      : {name: '', summary: '', activity: this.prefill?.activity || 'troubleshoot', category: this.prefill?.category || '',
         group: '', steps: [{fail_on_error: true}]};
    this.prefill = null;
    const opts = (items, current, empty) => (empty ? `<option value="">${empty}</option>` : '')
      + items.map(([value, label]) => `<option value="${esc(value)}"${value === current ? ' selected' : ''}>${esc(label)}</option>`).join('');
    $('#tpGroup').innerHTML = opts(this.meta.groups.map(g => [g.id, g.label + (g.read_only ? ' (read-only)' : '')]), t.group, 'Choose a host group');
    $('#tpActivity').innerHTML = opts((data.activities || []).map(a => [a.id, a.title]), t.activity);
    $('#tpCategory').innerHTML = opts(data.categories.map(c => [c.id, c.title]), t.category, 'Choose a product');
    $('#tpName').value = t.name;
    $('#tpSummary').value = t.summary || '';
    const title = this.id ? `Edit template: ${t.name}` : 'Create template';
    $('#tpTitle').textContent = title;
    $('#tpCrumb').textContent = this.id ? t.name : 'Create template';
    document.title = `${title} - ${BASE_TITLE}`;
    $('#tpCancel').href = this.id ? `#/checks/${this.id}` : '#/checks';
    $('#tpDelete').hidden = !this.id;
    $('#tpSteps').innerHTML = '';
    (t.steps.length ? t.steps : [{fail_on_error: true}]).forEach(s => this.addStep(s));
    this.classify();
    $('#tpName').focus();
  },
  addStep(s) {
    const li = document.createElement('li');
    li.className = 'tp-step';
    li.innerHTML = this.stepHtml(s, ++this.seq);
    $('#tpSteps').appendChild(li);
    this.number();
  },
  // One step of the form (also drawn by the guide of this page)
  stepHtml(s, n) {
    const id = f => `tp${n}_${f}`;
    const wait = Math.max(0, parseInt(s.wait, 10) || 0);
    return `<div class="tp-step__head"><h3 class="tp-step__n"></h3><span class="tp-mode" data-mode></span>`
      + `<span class="tp-step__tools">`
      + `<button type="button" class="pf-btn pf-m-plain" data-step-tool="up" title="Move up" aria-label="Move this step up">${icon('arrow-up')}</button>`
      + `<button type="button" class="pf-btn pf-m-plain" data-step-tool="down" title="Move down" aria-label="Move this step down">${icon('arrow-down')}</button>`
      + `<button type="button" class="pf-btn pf-m-plain" data-step-tool="remove" title="Remove step" aria-label="Remove this step">${icon('trash')}</button></span></div>`
      + `<div class="tp-grid">`
      + `<div class="pf-form-group"><label class="pf-form-label" for="${id('title')}">Title <span class="pf-required" aria-hidden="true">*</span></label>`
      + `<input class="pf-form-control" id="${id('title')}" data-f="title" maxlength="80" placeholder="e.g. Disk usage of /" value="${esc(s.title || '')}"></div>`
      + `<div class="pf-form-group tp-command"><label class="pf-form-label" for="${id('command')}">Command <span class="pf-required" aria-hidden="true">*</span></label>`
      + `<input class="pf-form-control mono" id="${id('command')}" data-f="command" maxlength="1000" spellcheck="false" autocapitalize="off" `
      + `placeholder="e.g. df -h /" aria-describedby="${id('why')}" value="${esc(s.command || '')}">`
      + `<span class="pf-helper-text" id="${id('why')}" data-why aria-live="polite"></span></div></div>`
      + `<fieldset class="tp-rules" data-rules><legend>When is the result a problem?</legend><div class="tp-grid tp-grid--3">`
      + `<div class="pf-form-group"><label class="pf-form-label" for="${id('problem_if')}">Problem if the output contains</label>`
      + `<input class="pf-form-control mono" id="${id('problem_if')}" data-f="problem_if" maxlength="200" spellcheck="false" placeholder="e.g. 9[0-9]%" value="${esc(s.problem_if || '')}"></div>`
      + `<div class="pf-form-group"><label class="pf-form-label" for="${id('warning_if')}">Warning if the output contains</label>`
      + `<input class="pf-form-control mono" id="${id('warning_if')}" data-f="warning_if" maxlength="200" spellcheck="false" placeholder="e.g. 8[0-9]%" value="${esc(s.warning_if || '')}"></div>`
      + `<div class="pf-form-group"><label class="pf-form-label" for="${id('expect')}">Problem if the output does not contain</label>`
      + `<input class="pf-form-control mono" id="${id('expect')}" data-f="expect" maxlength="200" spellcheck="false" placeholder="e.g. ^active" value="${esc(s.expect || '')}"></div></div>`
      + `<label class="pf-check"><input type="checkbox" data-f="fail_on_error"${s.fail_on_error === false ? '' : ' checked'}>`
      + `<span>Problem when the command fails (exit code not 0)</span></label>`
      + `<span class="pf-helper-text">A text or a regular expression, not case-sensitive: <span class="mono">failed|error</span> matches either word. Empty = not used.</span></fieldset>`
      + `<div class="tp-change" data-change hidden>${alertBox('info', 'This step changes the host',
        'It does not run with the check. The result offers the change steps as a fix: they run in order, once the operator types '
        + 'the host name, for accounts that may run fixes, on hosts whose SSH credential allows fixes (Hosts &amp; SSH).')}</div>`
      + `<div class="pf-form-group tp-wait" data-wait><label class="pf-form-label" for="${id('wait')}">Wait before the next step</label>`
      + `<div class="pf-input-group"><input class="pf-form-control" type="number" id="${id('wait')}" data-f="wait" min="0" max="1800" step="1" `
      + `inputmode="numeric" value="${wait % 60 === 0 && wait >= 60 ? wait / 60 : wait}" aria-describedby="${id('wait_help')}">`
      + `<select class="pf-form-control" data-f="wait_unit" aria-label="Unit of the wait">`
      + `<option value="1"${wait % 60 === 0 && wait >= 60 ? '' : ' selected'}>seconds</option>`
      + `<option value="60"${wait % 60 === 0 && wait >= 60 ? ' selected' : ''}>minutes</option></select></div>`
      + `<span class="pf-helper-text" id="${id('wait_help')}" data-wait-help></span></div>`;
  },
  modeHtml(group, mode) {
    return !group ? '<span class="pf-label">Choose “Runs on” first</span>'
      : !mode ? '' : mode === 'read' ? `<span class="pf-label pf-m-green">${icon('eye')}Reads</span>`
        : `<span class="pf-label pf-m-gold">${icon('alert')}Changes the host · after confirmation</span>`;
  },
  whyText(mode, why) { return mode === 'change' ? `Changes the host: ${why}.` : mode === 'read' ? 'Only reads: runs with the check.' : ''; },
  waitHelp(mode) {
    return mode === 'change'
      ? 'Inside the fix, before the next change step; after the last one, before the check runs again. Up to 30 minutes.'
      : 'Inside the check, before the next read step. 0 = go on at once; up to 30 minutes.';
  },
  number() {
    $$('#tpSteps > li').forEach((li, i, all) => {
      $('.tp-step__n', li).textContent = `Step ${i + 1}`;
      $('[data-step-tool="up"]', li).disabled = i === 0;
      $('[data-step-tool="down"]', li).disabled = i === all.length - 1;
      $('[data-step-tool="remove"]', li).disabled = all.length === 1;
    });
    $('#tpAdd').disabled = $$('#tpSteps > li').length >= (this.meta?.max_steps || 20);
  },
  classifySoon() {
    clearTimeout(this.timer);
    this.timer = setTimeout(() => this.classify(), 350);
  },
  // What each step does, as the portal will rate it when the template runs (the server decides, never the form)
  async classify() {
    const rows = $$('#tpSteps > li');
    const group = $('#tpGroup').value;
    const commands = rows.map(li => $('[data-f="command"]', li).value);
    let items = [];
    try { items = group ? (await api('/api/templates/classify', {group, commands})).items : []; } catch (e) { items = []; }
    if ($('#tpGroup').value !== group) return;   // changed meanwhile: a newer call follows
    rows.forEach((li, i) => {
      const it = commands[i].trim() && items[i];
      const mode = it ? it.mode : '';
      $('[data-mode]', li).innerHTML = this.modeHtml(group, mode);
      $('[data-why]', li).textContent = this.whyText(mode, it && it.why);
      $('[data-rules]', li).hidden = mode === 'change';
      $('[data-change]', li).hidden = mode !== 'change';
      const readOnly = (this.meta?.groups || []).some(g => g.id === group && g.read_only);
      $('[data-wait]', li).hidden = readOnly;
      $('[data-wait-help]', li).textContent = this.waitHelp(mode);
    });
  },
  collect() {
    return {
      name: $('#tpName').value, summary: $('#tpSummary').value, activity: $('#tpActivity').value,
      category: $('#tpCategory').value, group: $('#tpGroup').value,
      steps: $$('#tpSteps > li').map(li => ({
        title: $('[data-f="title"]', li).value, command: $('[data-f="command"]', li).value,
        problem_if: $('[data-f="problem_if"]', li).value, warning_if: $('[data-f="warning_if"]', li).value,
        expect: $('[data-f="expect"]', li).value, fail_on_error: $('[data-f="fail_on_error"]', li).checked,
        wait: $('[data-wait]', li).hidden ? 0
          : Math.round((parseFloat($('[data-f="wait"]', li).value) || 0) * Number($('[data-f="wait_unit"]', li).value)),
      })),
    };
  },
  async save() {
    const btn = $('#tpSave');
    btn.disabled = true;
    $('#tpError').hidden = true;
    try {
      const body = this.collect();
      const res = this.id ? await api(`/api/templates/${encodeURIComponent(this.id)}`, body, 'PUT') : await api('/api/templates', body);
      Catalog.loaded = '';   // the lists show the template at once
      toast(this.id ? 'Template saved' : 'Template created: choose a host and run it', 'success');
      location.hash = `#/checks/${res.id}`;
    } catch (e) {
      $('#tpError').innerHTML = `<div class="pf-alert__title">${esc(e.message)}</div>`;
      $('#tpError').hidden = false;
      $('#tpError').focus();
    } finally {
      btn.disabled = false;
    }
  },
  async remove() {
    const name = $('#tpName').value;
    if (!await Confirm.ask('Delete this template?', `${name} is deleted for everyone. Its past runs stay in Runs.`, 'Delete')) return;
    try {
      await api(`/api/templates/${encodeURIComponent(this.id)}`, undefined, 'DELETE');
      Catalog.loaded = '';
      toast('Template deleted', 'success');
      location.hash = '#/checks';
    } catch (e) {
      toast(e.message);
    }
  },
};

/* =========================================================================
   Launch: parameters of one check on the selected site
   ========================================================================= */
const Launch = {
  check: null,
  init() {
    $('#lnForm').addEventListener('submit', e => { e.preventDefault(); this.submit(); });
    // A list of IDs (uuid_list): one row per ID, Add / remove buttons; several IDs pasted at once become one row each.
    const params = $('#lnParams');
    params.addEventListener('click', e => {
      const add = e.target.closest('[data-add]');
      const remove = e.target.closest('[data-remove]');
      if (add) {
        const list = $(`.wi-idlist[data-list="${add.dataset.add}"]`, params);
        const p = (this.check?.params || []).find(x => x.name === add.dataset.add);
        if (list && p && $$('[data-item]', list).length < (p.max || 16)) {
          list.insertAdjacentHTML('beforeend', this.idRow(p));
          $$('[data-item]', list).at(-1).focus();
        } else if (p) toast(`At most ${p.max || 16} IDs per run`);
        this.idCount(add.dataset.add);
      } else if (remove) {
        const list = remove.closest('.wi-idlist');
        const rows = $$('.wi-idlist__row', list);
        if (rows.length > 1) remove.closest('.wi-idlist__row').remove();
        else $('[data-item]', rows[0]).value = '';
        this.idCount(list.dataset.list);
      }
    });
    params.addEventListener('paste', e => {
      const input = e.target.closest('[data-item]');
      if (!input) return;
      const ids = (e.clipboardData?.getData('text') || '').split(/[\s,;]+/).filter(Boolean);
      if (ids.length < 2) return;
      e.preventDefault();
      const list = input.closest('.wi-idlist');
      const p = (this.check?.params || []).find(x => x.name === list.dataset.list);
      input.value = ids.shift();
      for (const id of ids) {
        if ($$('[data-item]', list).length >= (p?.max || 16)) { toast(`At most ${p?.max || 16} IDs per run`); break; }
        list.insertAdjacentHTML('beforeend', this.idRow(p, id));
      }
      this.idCount(list.dataset.list);
    });
    params.addEventListener('input', e => { if (e.target.closest('[data-item]')) this.idCount(e.target.closest('.wi-idlist').dataset.list); });
  },
  idRow(p, value = '') {
    const noFill = 'autocomplete="off" data-lpignore="true" data-1p-ignore="true" data-bwignore="true" data-form-type="other"';
    return `<div class="wi-idlist__row"><input type="text" class="pf-form-control mono" data-item ${noFill} spellcheck="false" maxlength="64"`
      + ` aria-label="${esc(p.label)}" placeholder="e.g. a80a1a07-06b8-489b-a984-b046981f68b9" value="${esc(value)}">`
      + `<button type="button" class="pf-btn pf-m-plain" data-remove aria-label="Remove this row" title="Remove">${icon('minus-circle')}</button></div>`;
  },
  idCount(name) {
    const list = $(`.wi-idlist[data-list="${name}"]`);
    const n = list ? $$('[data-item]', list).filter(i => i.value.trim()).length : 0;
    const out = $(`[data-count="${name}"]`);
    if (out) out.textContent = n ? `${n} ID${n > 1 ? 's' : ''}` : '';
  },
  async open(id) {
    const data = await Catalog.load();
    const c = data.checks.find(x => x.id === id);
    if (!c) {
      $('#lnTitle').textContent = id;
      $('#lnNotice').innerHTML = alertBox('danger', 'Unknown check');
      return;
    }
    this.check = c;
    const cat = Catalog.category(c.category);
    $('#lnProduct').textContent = cat ? cat.title : c.category;
    $('#lnProduct').href = $('#lnCancel').href = `#/products/${c.category}`;
    $('#lnCrumb').textContent = c.title;
    $('#lnTitle').textContent = c.title;
    $('#lnStatus').innerHTML = checkStatusLabel(c) + (c.template ? ' <span class="pf-label pf-m-blue">Template</span>' : '');
    $('#lnActions').innerHTML = c.template && Session.admin
      ? `<a class="pf-btn pf-m-secondary" href="#/templates/${esc(c.id)}">${icon('pencil')}Edit template</a>` : '';
    $('#lnSummary').textContent = c.does || c.summary;
    const site = Site.info(Site.current);
    $('#lnSite').style.setProperty('--opt', site.color);
    $('#lnSite').innerHTML = `<span class="site-banner-name">${esc(site.name)}</span><span class="site-banner-detail"><b>Site ${esc(site.name)}</b>`
      + `<br><span class="pf-text-secondary">Change the site in the masthead.</span></span>`;
    const notices = [];
    if (c.status === 'planned') notices.push(alertBox('warning', 'Planned, not runnable yet', esc(c.reason || '')));
    if (c.status === 'manual') notices.push(alertBox('info', 'Manual work instruction', 'Nothing can be read automatically for this WI: follow the WI page.'));
    if (c.status === 'module') notices.push(alertBox('info', 'Done by another portal module', `<a href="${esc(c.link)}">Open the module</a>`));
    if (c.status === 'ready' && !c.access.runnable) {
      notices.push(alertBox('warning', `Cannot run on site ${esc(Site.current)}`, `<ul>${c.access.missing.map(m => `<li>${esc(m)}</li>`).join('')}</ul>`));
    }
    if (c.access.optional.length && c.status === 'ready') {
      notices.push(alertBox('info', 'Some steps will be skipped', `<ul>${c.access.optional.map(m => `<li>${esc(m)}</li>`).join('')}</ul>`));
    }
    $('#lnNotice').innerHTML = notices.join('');
    $('#lnParams').innerHTML = c.params.length ? c.params.map(p => this.field(p, c)).join('')
      : '<p class="pf-text-secondary pf-mb-md">This check has no parameters.</p>';
    const runnable = c.status === 'ready' && c.access.runnable;
    $('#lnRun').disabled = !runnable;
    $('#lnForm').hidden = c.status !== 'ready';
    if (c.template) {
      const t = c.template;
      $('#lnAbout').innerHTML = `<div class="wi-about"><p>${esc(c.summary)}</p><h3>Template</h3><p class="pf-text-secondary">Made on the portal by ${esc(t.created_by || '-')}, `
        + `changed ${esc(fmtTime(t.updated))} by ${esc(t.updated_by || '-')}.</p><h3>Steps</h3><ol class="ck-tsteps">`
        + t.steps.map(st => `<li>${esc(st.title)} <span class="pf-label${st.mode === 'change' ? ' pf-m-gold' : ''}">`
          + `${st.mode === 'change' ? 'Changes, after confirmation' : 'Reads'}</span><code class="mono">${esc(st.command)}</code></li>`).join('') + '</ol>'
        + '<p class="pf-text-secondary pf-mt-md">The read steps run with the SSH credential of the host. The change steps never run with the check: '
        + 'the result offers them as a fix, which runs once the operator types the host name, for accounts that may run fixes, on hosts '
        + 'whose SSH credential allows fixes.</p></div>';
    } else {
      $('#lnAbout').innerHTML = `<div class="wi-about"><p>${esc(c.summary)}</p><h3>${c.wi.length ? 'Work instruction' : 'Platform health'}</h3>`
        + (c.wi.map(w => wiRef(w, 'wi-link')).join('')
           || '<p class="pf-text-secondary">Not from a Knowledge Base page: a health check of the platform. Each finding links to the vendor documentation.</p>')
        + (c.steps.length ? `<h3>Steps checked</h3><ol>${c.steps.map(s => `<li>${esc(s)}</li>`).join('')}</ol>` : '')
        + `<h3>Reads</h3>${[...c.needs, ...c.uses].map(n => `<span class="pf-label">${esc(readsLabel(n))}${c.uses.includes(n) ? ' (optional)' : ''}</span>`).join(' ') || '-'}`
        + '<p class="pf-text-secondary pf-mt-md">Read-only accounts only. OpenStack commands are limited to list and show; host commands are fixed read commands.</p></div>';
    }
    const topo = Topology.html(c.topology);
    $('#lnTopoCard').hidden = !topo;
    $('#lnTopo').innerHTML = topo;
    const first = $('#lnParams input, #lnParams select');
    if (first && runnable) first.focus();
  },
  // Parameter fields carry data-param instead of a name and opt out of autofill: a browser or password manager must
  // never put a saved sign-in (the portal password) into a field that ends up in the run history and the activity log.
  field(p, c) {
    const id = `p_${p.name}`;
    const noFill = 'autocomplete="off" data-lpignore="true" data-1p-ignore="true" data-bwignore="true" data-form-type="other"';
    const label = `<label class="pf-form-label" for="${id}">${esc(p.label)}${p.required ? ' <span class="pf-required" aria-hidden="true">*</span>' : ''}</label>`;
    const help = p.help ? `<span class="pf-helper-text">${esc(p.help)}</span>` : '';
    let control;
    if (p.type === 'host') {
      const hosts = c.hosts[p.name] || [];
      const last = tabStore.get(`wi_host_${c.id}`) || '';
      control = `<select class="pf-form-control" id="${id}" data-param="${esc(p.name)}" ${noFill}${p.required ? ' required' : ''}>`
        + `<option value="">${(p.groups || []).includes('bmc') ? (hosts.length ? 'Choose a server (BMC)' : 'No BMC on this site (add it on the page BMC)')
          : hosts.length ? 'Choose a host' : 'No host of this kind on this site'}</option>`
        + hosts.map(h => `<option value="${esc(h.name)}"${h.name === last ? ' selected' : ''}>${esc(h.name)} — ${esc(h.address)} (${esc(h.group)})</option>`).join('')
        + '</select>';
    } else if (p.type === 'uuid_list') {
      return `<div class="pf-form-group"><label class="pf-form-label" for="${id}_0">${esc(p.label)}${p.required ? ' <span class="pf-required" aria-hidden="true">*</span>' : ''}`
        + ` <span class="pf-text-secondary wi-idlist__count" data-count="${esc(p.name)}"></span></label>`
        + `<div class="wi-idlist" data-list="${esc(p.name)}">${this.idRow(p).replace('<input ', `<input id="${id}_0" `)}</div>`
        + `<button type="button" class="pf-btn pf-m-link pf-m-inline wi-idlist__add" data-add="${esc(p.name)}">${icon('plus')} Add instance</button>`
        + `${help}</div>`;
    } else if (p.type === 'select') {
      control = `<select class="pf-form-control" id="${id}" data-param="${esc(p.name)}" ${noFill}>${(p.options || []).map(o => `<option${String(o) === String(p.default ?? '') ? ' selected' : ''}>${esc(o)}</option>`).join('')}</select>`;
    } else {
      const numeric = ['int', 'port'].includes(p.type);
      const mono = ['uuid', 'ip', 'ip_list', 'cidr', 'ip_port', 'project'].includes(p.type) ? ' mono' : '';
      control = `<input type="text" class="pf-form-control${mono}" id="${id}" data-param="${esc(p.name)}" ${numeric ? 'inputmode="numeric"' : ''}`
        + ` ${noFill} spellcheck="false" maxlength="256" value="${esc(p.default ?? '')}"`
        + `${p.type === 'uuid' ? ' placeholder="e.g. a80a1a07-06b8-489b-a984-b046981f68b9"' : ''}${p.type === 'ip' ? ' placeholder="e.g. 11.7.101.238"' : ''}`
        + `${p.type === 'ip_list' ? ' placeholder="e.g. 10.249.11.50, 10.249.11.51"' : ''}>`;
    }
    return `<div class="pf-form-group">${label}${control}${help}</div>`;
  },
  async submit() {
    const c = this.check;
    if (!c) return;
    const params = {};
    $$('#lnParams [data-param]').forEach(el => {
      el.classList.remove('is-invalid');
      if (el.value.trim() !== '') params[el.dataset.param] = el.value.trim();
    });
    const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    for (const list of $$('#lnParams .wi-idlist')) {   // the rows of a list of IDs, comma separated
      const items = $$('[data-item]', list);
      items.forEach(i => i.classList.remove('is-invalid'));
      const bad = items.filter(i => i.value.trim() && !uuid.test(i.value.trim()));
      if (bad.length) {
        bad.forEach(i => i.classList.add('is-invalid'));
        bad[0].focus();
        return toast(`${bad.length} row(s) are not OpenStack IDs`);
      }
      const ids = items.map(i => i.value.trim().toLowerCase()).filter(Boolean);
      if (ids.length) params[list.dataset.list] = [...new Set(ids)].join(',');
    }
    const missing = c.params.filter(p => p.required && !params[p.name]);
    if (missing.length) {
      missing.forEach(p => ($(`#p_${p.name}`) || $(`#p_${p.name}_0`))?.classList.add('is-invalid'));
      ($(`#p_${missing[0].name}`) || $(`#p_${missing[0].name}_0`))?.focus();
      return toast(`${missing.map(p => p.label).join(', ')}: required`);
    }
    const host = c.params.find(p => p.type === 'host');
    if (host && params[host.name]) tabStore.set(`wi_host_${c.id}`, params[host.name]);
    await run($('#lnRun'), async () => {
      const data = await api('/api/runs', {site: Site.current, check: c.id, params});
      location.hash = `#/runs/${data.run_id}`;
    });
  },
};

/* =========================================================================
   Fixes running now: a fix runs on the portal server, also when its page is closed or another page is open. Shown on
   every page with its progress and a link to the run it was started from; refreshed every 5 s while one runs.
   ========================================================================= */
const RunningFixes = {
  items: [],
  timer: null,
  init() {
    document.addEventListener('visibilitychange', () => { if (!document.hidden) this.load(); });
  },
  progressText(a) {
    const p = a.progress;
    if (!p) return `running for ${duration((Date.now() - new Date(a.ts)) / 1000)}`;
    const done = (p.done || []).length;
    const counts = ['ok', 'skipped', 'failed', 'attention'].map(k => [k, (p.done || []).filter(d => d.status === k).length]).filter(x => x[1]);
    return `${done} of ${p.of} done` + (counts.length ? ` (${counts.map(([k, n]) => `${n} ${k}`).join(', ')})` : '')
      + (p.current ? ` · now ${p.current.n}/${p.of}: ${p.current.label}` : '');
  },
  async load() {
    clearTimeout(this.timer);
    if (!Session.allowed) return;
    const before = new Set(this.items.map(a => a.id));
    try {
      this.items = (await api('/api/fixes/running')).items || [];
    } catch (e) { /* the next refresh tries again */ }
    const ended = [...before].some(id => !this.of(id));
    this.render();
    // a fix that ended: the list shows its result (and the check that ran again after it)
    if (Router.page === 'runs') { if (ended) Runs.load().catch(() => {}); else Runs.render(); }
    if (Router.page === 'run' && RunPage.record) RunPage.renderElsewhere(RunPage.record);
    this.timer = setTimeout(() => this.load(), this.items.length ? 5000 : 30000);
  },
  of(id) { return this.items.find(a => a.id === id); },
  title(a) { return splitTitle(String(a.title || '').split(' (')[0])[0]; },   // "Live-migrate selected: 3 instances" 
  render() {
    const box = $('#wiRunning');
    box.hidden = !this.items.length;
    if (!this.items.length) { box.innerHTML = ''; return; }
    const rows = this.items.map(a => `<li><span class="pf-spinner pf-m-sm" aria-hidden="true"></span><span><b>Fix #${a.id}</b> `
      + `${esc(this.title(a))} <span class="pf-text-secondary">· ${esc(a.site || '')} · ${esc(a.target || a.host || '')} · `
      + `${esc(this.progressText(a))} · by ${esc(a.username)}, started ${esc(shortTime(a.ts))}</span> `
      + `<a class="wi-link" href="#/runs/${a.run_id}">Open run #${a.run_id}</a></span></li>`).join('');
    box.innerHTML = alertBox('info', `${this.items.length} fix${this.items.length > 1 ? 'es' : ''} running on the portal server`,
      `<ul class="wi-running__list">${rows}</ul><span class="pf-text-secondary pf-text-sm">It keeps running when this page is closed; `
      + 'open its run to follow every item.</span>');
  },
};

/* =========================================================================
   Runs (like the Jobs list of AWX / ONTAP Restore)
   ========================================================================= */
const Runs = {
  items: [],
  total: 0,
  init() {
    let timer = null;
    $('#rnQ').addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(() => run(null, () => this.load()), 300); });
    ['#rnUser', '#rnSite', '#rnStatus'].forEach(sel => $(sel).addEventListener('change', () => run(null, () => this.load())));
    $('#rnMoreBtn').addEventListener('click', e => run(e.currentTarget, () => this.load(true)));
    $('#rnExportBtn').addEventListener('click', e => run(e.currentTarget, () => downloadFile(`/export/runs.csv?${qs(this.filters())}`, 'runs.csv')));
    $('#rnList').addEventListener('click', e => {
      const row = e.target.closest('tr[data-id]');
      if (row) location.hash = `#/runs/${row.dataset.id}`;
    });
    $('#rnList').addEventListener('keydown', e => {
      const row = e.target.closest('tr[data-id]');
      if (row && e.key === 'Enter') location.hash = `#/runs/${row.dataset.id}`;
    });
  },
  filters() { return {q: $('#rnQ').value.trim(), user: $('#rnUser').value, site: $('#rnSite').value, status: $('#rnStatus').value}; },
  async load(more = false) {
    const data = await api(`/api/runs?${qs({...this.filters(), limit: 50, offset: more ? this.items.length : 0})}`);
    this.items = more ? [...this.items, ...data.items] : data.items;
    this.total = data.total;
    const user = $('#rnUser').value, site = $('#rnSite').value;
    $('#rnUser').innerHTML = '<option value="">All users</option>' + data.users.map(u => `<option${u === user ? ' selected' : ''}>${esc(u)}</option>`).join('');
    $('#rnSite').innerHTML = '<option value="">All sites</option>' + Site.list.map(s => `<option${s.name === site ? ' selected' : ''}>${esc(s.name)}</option>`).join('');
    this.render();
  },
  target(r) {
    const p = r.params || {};
    const text = r.host || p.instance || (p.ip ? `${p.ip}${p.port ? `:${p.port}` : ''}` : '') || p.project || p.pool || p.tier1 || '';
    return text ? `<span class="mono">${esc(text)}</span>` : '<span class="pf-text-secondary">-</span>';
  },
  render() {
    $('#rnShown').textContent = this.total ? `${this.items.length} of ${this.total}` : '';
    $('#rnMore').hidden = this.items.length >= this.total;
    $('#rnList').innerHTML = this.items.map(r => `<tr class="is-clickable" tabindex="0" data-id="${r.id}">`
      + `<td class="mono">#${r.id}</td><td>${esc(r.check_title)}<span class="pf-table__sub">${esc(r.summary || r.error || '')}</span></td>`
      + `<td class="pf-nowrap">${resultLabel(r.status)}</td><td>${this.fixes(r)}</td><td>${esc(r.site)}</td><td>${this.target(r)}</td>`
      + `<td class="mono pf-nowrap">${esc(r.username)}</td><td class="pf-nowrap" title="${esc(fmtTime(r.ts))}">${esc(shortTime(r.ts))}</td>`
      + `<td class="pf-nowrap">${r.finished ? duration((new Date(r.finished) - new Date(r.ts)) / 1000) : '-'}</td></tr>`).join('')
      || `<tr><td colspan="9"><div class="pf-empty-state">${icon('list')}<h2 class="pf-title">No runs yet</h2><span>Run a check from the Checks page.</span></div></td></tr>`;
  },
  // The fixes started from a run: the last ones, running with their progress
  fixes(r) {
    const list = (r.fixes || []).slice(-2);
    if (!list.length) return '<span class="pf-text-secondary">-</span>';
    const look = {running: ['blue', 'in-progress', 'Running'], ok: ['green', 'check-circle', 'Done'], failed: ['red', 'x-circle', 'Failed']};
    return list.map(f => {
      const [color, ic, text] = look[f.status] || ['', 'info', f.status];
      const live = f.status === 'running' && RunningFixes.of(f.id);
      return `<span class="pf-label pf-m-${color || 'compact'}" title="${esc(f.title || '')}">${icon(ic)}Fix #${f.id} ${esc(text)}</span>`
        + (live ? `<span class="pf-table__sub">${esc(RunningFixes.progressText(live))}</span>` : '');
    }).join(' ');
  },
};

/* =========================================================================
   One run: result per WI step, how to fix it, details, live Ansible output (like an AWX job)
   ========================================================================= */
const LogView = {
  kind(line) {
    if (/^PLAY( RECAP)? \[?/.test(line)) return 'is-play';
    if (/^TASK \[/.test(line)) return 'is-task';
    if (/^(ok|included):/.test(line)) return 'is-ok';
    if (/^changed:/.test(line)) return 'is-changed';
    if (/^(fatal|failed):|FAILED!/.test(line)) return 'is-failed';
    if (/^skipping:/.test(line)) return 'is-skip';
    return '';
  },
  html(lines, start = 0) {
    return lines.map((line, i) => `<div class="pf-log__line"><span class="pf-log__num">${start + i + 1}</span>`
      + `<span class="pf-log__text ${this.kind(line)}">${esc(line) || '&nbsp;'}</span></div>`).join('');
  },
};

/* =========================================================================
   Progress of a running check or fix: how far (an animated bar), what runs now, how long, the last tasks
   (progress.py on the portal reads it from the live Ansible output)
   ========================================================================= */
const Progress = {
  html(bar, elapsed, what) {
    return `<div class="wi-progress" role="group" aria-label="${esc(what)}"><div class="wi-progress__head">`
      + '<span class="wi-progress__now"><span class="pf-spinner pf-m-sm" aria-hidden="true"></span><span data-now></span></span>'
      + '<span class="wi-progress__pct" data-pct></span></div>'
      + `<div class="wi-progress__track" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-label="${esc(what)}">`
      + '<span class="wi-progress__fill" data-fill></span></div><div class="wi-progress__meta" data-meta aria-live="polite"></div>'
      + '<ol class="wi-progress__steps" data-steps></ol></div>';
  },
  // Update in place (the bar slides from where it was); draw it first when the box is still empty.
  show(box, bar, elapsed, what) {
    if (!box) return;
    if (!$('.wi-progress', box)) box.innerHTML = this.html(bar, elapsed, what);
    const pct = Math.max(0, Math.min(100, Math.round(bar?.percent ?? 0)));
    $('[data-pct]', box).textContent = `${pct}%`;
    $('[data-fill]', box).style.width = `${Math.max(pct, 2)}%`;
    $('.wi-progress__track', box).setAttribute('aria-valuenow', String(pct));
    $('[data-now]', box).textContent = bar?.current || 'Starting…';
    $('[data-meta]', box).textContent = elapsed != null ? `Running for ${duration(elapsed)}` : '';
    const ic = {ok: ['check-circle', 'is-ok'], failed: ['x-circle', 'is-fail'], running: ['in-progress', 'is-running']};
    $('[data-steps]', box).innerHTML = (bar?.steps || []).map(st => {
      const [i, cls] = ic[st.status] || ['circle', ''];
      return `<li class="${cls}">${icon(i)}<span>${esc(st.name)}</span></li>`;
    }).join('');
  },
};

const RunPage = {
  token: 0,
  record: null,
  sel: {},
  selRun: null,
  lineCount: 0,
  task: '',
  init() {
    $('#runAgainBtn').addEventListener('click', () => this.again());
    $('#runNoteBtn').addEventListener('click', () => this.copyNote());
    // Export of the result: CSV (every table of the steps and the fixes) and a printable report (Save as PDF).
    $('#runCsvBtn').addEventListener('click', e => run(e.currentTarget, () => downloadFile(`/export/runs/${this.record.id}.csv`, `run-${this.record.id}.csv`)));
    $('#runPdfBtn').addEventListener('click', () => window.open(`${BASE}/runs/${this.record.id}/report?print=1`, '_blank', 'noopener'));
    // Permission "collect logs": every command and its full output, and the log bundle of Collect logs / sos report
    // (the bundle is a plain link: it can be gigabytes, the browser downloads it itself).
    $('#runRawBtn').addEventListener('click', e => run(e.currentTarget, () => downloadFile(`/export/runs/${this.record.id}/raw.zip`, `run-${this.record.id}-raw.zip`)));
    // The exports in one menu (as the user menu of the masthead): open / close, outside click, Escape
    const menu = $('#runExportMenu'), toggle = $('#runExportToggle');
    const setOpen = open => { menu.hidden = !open; toggle.setAttribute('aria-expanded', String(open)); };
    toggle.addEventListener('click', () => { setOpen(menu.hidden); if (!menu.hidden) $('.pf-menu__item:not([hidden])', menu)?.focus(); });
    menu.addEventListener('click', e => { if (e.target.closest('.pf-menu__item')) setOpen(false); });
    document.addEventListener('click', e => { if (!menu.hidden && !e.target.closest('#runExportWrap')) setOpen(false); });
    $('#runExportWrap').addEventListener('keydown', e => { if (e.key === 'Escape' && !menu.hidden) { setOpen(false); toggle.focus(); } });
    // The findings of the result jump to their step (or to the fixes); the hash stays the route of the page
    $('#runOutcome').addEventListener('click', e => {
      const b = e.target.closest('[data-goto]');
      if (!b) return;
      const el = $(b.dataset.goto);
      if (!el) return;
      $('details.wi-step__more', el)?.setAttribute('open', '');
      el.scrollIntoView({behavior: 'smooth', block: 'start'});
    });
    $('#runRecs').addEventListener('click', e => {
      const b = e.target.closest('[data-fix]');
      if (b && !b.disabled) FixDialog.open(this.record, Number(b.dataset.fix), [...(this.sel[Number(b.dataset.fix)] || [])]);
    });
    // Fixes with selectable items: tick the instances / volumes / images to change (the server runs only their commands).
    $('#runRecs').addEventListener('change', e => {
      const box = e.target.closest('input[data-sel]');
      if (!box) return;
      const rec = Number(box.dataset.sel);
      const fx = (this.record?.fixes || [])[rec];
      if (!fx?.selectable) return;
      const set = this.sel[rec] || (this.sel[rec] = new Set());
      const ok = fx.items.map((it, j) => j).filter(j => !fx.items[j].disabled);
      if (box.dataset.all !== undefined) {
        ok.forEach(j => (box.checked ? set.add(j) : set.delete(j)));
      } else {
        const j = Number(box.value);
        if (box.checked) set.add(j); else set.delete(j);
      }
      this.syncSelection(rec);
    });
  },
  // Selection of the fix of recommendation rec: rows, the select-all box and the button follow the ticked items.
  syncSelection(rec) {
    const fx = (this.record?.fixes || [])[rec];
    const root = $(`.wi-rec[data-rec="${rec}"]`);
    if (!fx || !root) return;
    const set = this.sel[rec] || new Set();
    $$('input[data-sel]:not([data-all])', root).forEach(b => {
      b.checked = set.has(Number(b.value));
      b.closest('tr')?.classList.toggle('is-selected', b.checked);
    });
    const ok = fx.items.filter(it => !it.disabled).length;
    const all = $('input[data-all]', root);
    if (all) { all.checked = ok > 0 && set.size === ok; all.indeterminate = set.size > 0 && set.size < ok; }
    const btn = $(`[data-fix="${rec}"]`, root);
    const running = (this.record.actions || []).some(a => a.rec_index === rec && a.status === 'running');
    if (btn) {
      btn.disabled = !fx.available || running || !set.size;
      $('.wi-fix__count', btn).textContent = ` (${set.size})`;
    }
    const high = [...set].some(j => fx.items[j]?.delete);
    const risk = $('.wi-fix__risk', root);
    if (risk) {
      risk.className = `pf-label wi-fix__risk ${high ? 'pf-m-red' : 'pf-m-blue'}`;
      risk.innerHTML = high ? `${icon('alert')}High risk: type the number of ticked ${esc(fx.noun)} to confirm` : 'Standard fix';
      btn?.classList.toggle('pf-m-danger', high);
      btn?.classList.toggle('pf-m-primary', !high);
    }
  },
  stop() { this.token += 1; this.tracking = null; },   // a fix followed before is followed again when its run is reopened
  // A fix of this check on the same target that runs from another run (e.g. this is a newer run of the check): where to
  // follow it; the same fix cannot start twice (one migration / clean-up / upgrade per target at a time).
  renderElsewhere(r) {
    const box = $('#runElsewhere');
    if (!box) return;
    const targets = new Set((r.fixes || []).filter(Boolean).map(fx => fx.target));
    const other = RunningFixes.items.filter(a => a.run_id !== r.id && a.check_id === r.check_id && a.site === r.site
      && (targets.has(a.target) || (a.host && a.host === r.host)));
    box.innerHTML = other.map(a => alertBox('info', `Fix #${a.id} is running for this target from run #${a.run_id}`,
      `${esc(RunningFixes.title(a))} — ${esc(RunningFixes.progressText(a))}, by ${esc(a.username)} since ${esc(shortTime(a.ts))}. `
      + `<a class="wi-link" href="#/runs/${a.run_id}">Open run #${a.run_id}</a> to follow it; a second one waits until it ends.`)).join('');
  },
  async open(id) {
    this.stop();
    const token = this.token;
    this.lineCount = 0;
    this.bar = null;
    this.elapsed = null;
    this.task = '';
    ['#runLog', '#runOutcome', '#runSteps', '#runDetail', '#runStatus', '#runRecs', '#runTopo', '#runScreens'].forEach(sel => { $(sel).innerHTML = ''; });
    $('#runTopoCard').hidden = $('#runScreensCard').hidden = $('#runProduct').hidden = $('#runProductSep').hidden = true;
    ['#runElapsed', '#runLines', '#runTitle'].forEach(sel => { $(sel).textContent = ''; });
    $('#runRecsCard').hidden = true;
    $('#runAgainBtn').hidden = $('#runNoteBtn').hidden = $('#runCsvBtn').hidden = $('#runPdfBtn').hidden = true;
    $('#runRawBtn').hidden = $('#runBundleBtn').hidden = $('#runExportWrap').hidden = $('#runExportMenu').hidden = true;
    $('#runTopoSummary').textContent = '';
    $('#runCrumb').textContent = `Run #${id}`;
    let record;
    try {
      record = (await api(`/api/runs/${id}`)).item;
    } catch (e) {
      $('#runTitle').textContent = `Run #${id}`;
      $('#runOutcome').innerHTML = alertBox('danger', 'Run not found', esc(e.message));
      return;
    }
    if (token !== this.token) return;
    this.record = record;
    this.renderHeader(record);
    this.renderDetail(record);
    if (record.status === 'running' && record.job_id) {
      this.renderPending(record);
      await this.follow(record, token);
    } else {
      this.consume((record.log || '').split('\n').filter((l, i, all) => l || i < all.length - 1));
      if (!record.log) $('#runLog').innerHTML = '<div class="pf-log-empty">No output.</div>';
      this.renderResult(record);
    }
  },
  async follow(record, token) {
    const started = Date.now();
    for (;;) {
      let data;
      try {
        data = await api(`/api/jobs/${encodeURIComponent(record.job_id)}?since=${this.lineCount}`);
      } catch (e) {
        $('#runOutcome').innerHTML = alertBox('warning', 'Cannot follow the progress', esc(e.message));
        return;
      }
      if (token !== this.token) return;
      this.consume(data.lines);
      this.task = data.task || this.task;
      this.bar = data.progress || this.bar;
      this.elapsed = data.elapsed ?? (Date.now() - started) / 1000;
      $('#runElapsed').textContent = duration(this.elapsed);
      this.renderPending(record);
      if (data.status !== 'running') {
        // The job has ended; the portal then stores the result (and a log bundle, which can take a while): wait for it.
        let final = (await api(`/api/runs/${record.id}`)).item;
        for (let i = 0; final.status === 'running' && i < 900 && token === this.token; i++) {
          $('#runElapsed').textContent = 'saving the result…';
          await sleep(1000);
          final = (await api(`/api/runs/${record.id}`)).item;
        }
        if (token !== this.token) return;
        this.record = final;
        this.renderHeader(final);
        this.renderDetail(final);
        this.renderResult(final);
        return;
      }
      await sleep(1000);
    }
  },
  consume(lines) {
    if (!lines.length) return;
    const log = $('#runLog');
    const atBottom = log.scrollTop + log.clientHeight >= log.scrollHeight - 30;
    log.insertAdjacentHTML('beforeend', LogView.html(lines, this.lineCount));
    this.lineCount += lines.length;
    if (atBottom) log.scrollTop = log.scrollHeight;
    $('#runLines').textContent = `${this.lineCount} lines`;
  },
  renderHeader(r) {
    $('#runTitle').textContent = r.check_title;
    $('#runStatus').innerHTML = resultLabel(r.status);
    if (r.finished) $('#runElapsed').textContent = duration((new Date(r.finished) - new Date(r.ts)) / 1000);
    const done = r.status !== 'running';
    $('#runAgainBtn').hidden = !done;
    $('#runNoteBtn').hidden = $('#runCsvBtn').hidden = $('#runPdfBtn').hidden = !done || !r.result?.steps?.length;
    const f = r.files || {};
    $('#runRawBtn').hidden = !done || !f.can;
    $('#runExportWrap').hidden = $('#runCsvBtn').hidden && $('#runPdfBtn').hidden && $('#runRawBtn').hidden;
    const b = $('#runBundleBtn');
    b.hidden = !done || !f.can || !f.bundle;
    // one primary action: the log bundle when there is one, else running the check again
    $('#runAgainBtn').classList.toggle('pf-m-primary', b.hidden);
    $('#runAgainBtn').classList.toggle('pf-m-secondary', !b.hidden);
    if (f.bundle) {
      b.href = `${BASE}/export/runs/${r.id}/bundle`;
      $('span', b).textContent = `Download log bundle (${bytes(f.bundle.size)})`;
      b.title = `${f.bundle.name} · kept until ${fmtTime(f.bundle.expires)} (bundles are deleted after ${f.keep_days} days)`;
    }
    document.title = `[${r.site}] Run #${r.id} · ${BASE_TITLE}`;
  },
  renderDetail(r) {
    if (r.category) {   // the product by its name: a run opened directly (a link) loads the catalog first
      const name = () => { const cat = Catalog.category(r.category); $('#runProduct').textContent = cat ? (cat.short || cat.title) : r.category; };
      name();
      if (!Catalog.category(r.category)) Catalog.load().then(name).catch(() => {});
      $('#runProduct').href = `#/products/${r.category}`;
      $('#runProduct').hidden = $('#runProductSep').hidden = false;
    }
    const topo = Topology.html(r.topology, r.status === 'running');
    $('#runTopoCard').hidden = !topo;
    $('#runTopo').innerHTML = topo;
    $('#runTopoSummary').textContent = Topology.summary(r.topology);
    const params = Object.entries(r.params || {}).filter(([k]) => k !== 'host');
    // under the title, as a description list (PatternFly): the steps of the result get the whole width
    const group = (k, v) => `<div class="pf-dl__group"><dt>${esc(k)}</dt><dd>${v}</dd></div>`;
    $('#runDetail').innerHTML = '<dl class="pf-dl">' + [
      group('Site', esc(r.site)),
      r.host && group('Host', `<span class="mono">${esc(r.host)}</span>`),
      group('Launched by', `${esc(r.username)} <span class="pf-text-secondary">from ${esc(r.client_ip || '-')}</span>`),
      group('Started', esc(fmtTime(r.ts)) + (r.finished ? ` <span class="pf-text-secondary">· took ${esc(duration((new Date(r.finished) - new Date(r.ts)) / 1000))}</span>` : '')),
      params.length && group('Parameters', params.map(([k, v]) => `${esc(k)} = <span class="mono">${esc(v)}</span>`).join(', ')),
      (r.wi || []).length && group('Work instruction', r.wi.map(w => wiRef(w, 'wi-link')).join('')),
    ].filter(Boolean).join('') + '</dl>';
  },
  // While the playbook runs: the steps of the check, the current Ansible task under them.
  renderPending(r) {
    const steps = r.steps_plan || [];
    $('#runSteps').innerHTML = steps.map((s, i) => `<li class="wi-step ${i === 0 ? 'is-current' : 'is-pending'}"><span class="wi-step__icon">${icon(i === 0 ? 'in-progress' : 'circle')}</span>`
      + `<span class="wi-step__title">${esc(s)}</span>${i === 0 && this.task ? `<span class="wi-step__detail">${esc(this.task)}</span>` : ''}</li>`).join('')
      || `<li class="wi-step is-current"><span class="wi-step__icon">${icon('in-progress')}</span><span class="wi-step__title">${esc(this.task || 'Reading…')}</span></li>`;
    // the progress bar (updated in place), and the result per step once every read is finished
    if (!$('#runOutcome .wi-progress')) $('#runOutcome').innerHTML = '';
    Progress.show($('#runOutcome'), this.bar, this.elapsed, 'Progress of the check');
  },
  renderResult(r) {
    const res = r.result || {};
    const steps = res.steps || [];
    if (r.status === 'error' || r.status === 'unknown') {
      $('#runOutcome').innerHTML = alertBox(r.status === 'error' ? 'danger' : 'warning', r.status === 'error' ? 'The check could not run' : 'Unknown result',
        esc(r.error || res.error || '') + (res.step ? `<br><span class="pf-text-secondary">At step: ${esc(res.step)}</span>` : ''));
    } else {
      const kind = {ok: 'success', warn: 'warning', fail: 'danger', skip: 'info'}[r.status] || 'info';
      const title = {ok: 'No problem found', warn: 'Warnings found', fail: 'Problem found', skip: 'Nothing could be checked'}[r.status] || r.status;
      // the findings as links to their step, and to the fixes: what is wrong first, the data under it, then how to fix it
      const found = steps.map((s, i) => [s, i]).filter(([s]) => s.status === 'fail' || s.status === 'warn');
      const recCount = (res.recommendations || []).length;
      const jumps = found.map(([s, i]) => `<button type="button" class="pf-label ${s.status === 'fail' ? 'pf-m-red' : 'pf-m-gold'} wi-jump" data-goto="#step-${i}">`
        + `${icon(s.status === 'fail' ? 'x-circle' : 'alert')}${esc(s.title)}</button>`).join('')
        + (recCount ? `<button type="button" class="pf-btn pf-m-link pf-m-inline wi-jump-fix" data-goto="#runRecsCard">${icon('tool')}`
          + `How to fix it (${recCount})</button>` : '');
      $('#runOutcome').innerHTML = alertBox(kind, title, found.length
        ? `<span class="wi-findings__count">${found.length} finding${found.length === 1 ? '' : 's'}:</span><span class="wi-findings">${jumps}</span>`
        : esc(r.summary || ''));
    }
    $('#runSteps').innerHTML = steps.map((s, i) => this.step(s, i)).join('')
      || `<li class="wi-step"><span class="wi-step__icon">${icon('minus-circle')}</span><span class="wi-step__title">No step result</span></li>`;
    const recs = res.recommendations || [];
    if (this.selRun !== r.id) {   // a new result: the default selection of each fix with selectable items
      this.selRun = r.id;
      this.sel = {};
      (r.fixes || []).forEach((fx, i) => {
        if (fx?.selectable) this.sel[i] = new Set(fx.items.map((it, j) => (it.default && !it.disabled ? j : -1)).filter(j => j >= 0));
      });
    }
    $('#runRecsCard').hidden = !recs.length;
    $('#runRecs').innerHTML = recs.map((x, i) => this.recHtml(x, i, r)).join('');
    this.renderElsewhere(r);
    (r.fixes || []).forEach((fx, i) => { if (fx?.selectable) this.syncSelection(i); });
    Screens.render(res.screens, r);
    const running = (r.actions || []).find(a => a.status === 'running');
    if (running) this.trackFix(running.id, r.id);
  },
  // One recommendation of "How to fix it": title (its first sentence) and details, the items it is about (table), where
  // to run it, the commands, the warning, and the fix button.
  recHtml(x, i, r) {
    const [title, body] = splitTitle(x.text);
    const fx = (r.fixes || [])[i];
    // one row per item to tick (rows and items in the same order); a table cut short still ticks the rows shown
    const pick = fx?.selectable && (x.items?.rows || []).length <= fx.items.length ? fx : null;
    const box = (j, it) => `<td class="wi-pick"><input type="checkbox" data-sel="${i}" value="${j}"${it.disabled ? ' disabled' : ''}`
      + ` aria-label="Tick ${esc(it.label)}"${it.disabled ? ` title="${esc(it.disabled)}"` : ''}></td>`;
    const items = x.items?.rows?.length
      ? `<div class="wi-rec__items pf-table-wrap"><table class="pf-table pf-m-compact${pick ? ' wi-pick-table' : ''}" aria-label="Items of fix ${i + 1}"><thead><tr>`
        + (pick ? `<th class="wi-pick"><input type="checkbox" data-sel="${i}" data-all aria-label="Tick every ${esc(pick.noun)} that can run"></th>` : '')
        + `${x.items.columns.map(c => `<th>${esc(c)}</th>`).join('')}</tr></thead>`
        + `<tbody>${x.items.rows.map((row, j) => `<tr${pick && pick.items[j].disabled ? ' class="is-disabled"' : ''}>${pick ? box(j, pick.items[j]) : ''}`
          + row.map((v, k) => `<td>${esc(v)}${pick && k === 0 && pick.items[j].disabled ? `<span class="pf-table__sub">${esc(pick.items[j].disabled)}</span>` : ''}</td>`).join('') + '</tr>').join('')}</tbody></table>`
        + (x.items.more ? `<span class="pf-helper-text">${x.items.more} more not shown.</span>` : '') + '</div>'
      : '';
    const commands = x.commands?.length
      ? `<div class="wi-cmd"><pre class="pf-code-block">${esc(x.commands.join('\n'))}</pre>`
        + `<button type="button" class="pf-btn pf-m-plain pf-m-small" data-copy="${esc(x.commands.join('\n'))}" aria-label="Copy the commands">${icon('copy')}</button></div>`
      : '';
    return `<div class="wi-rec" data-rec="${i}"><div class="wi-rec__head"><span class="wi-rec__num">${i + 1}</span>`
      + `<div><p class="wi-rec__title">${esc(title)}</p>${body ? `<p class="wi-rec__body">${esc(body)}</p>` : ''}</div></div>`
      + items
      + (x.where ? `<div class="wi-rec__where"><span class="pf-label pf-m-blue">${icon('terminal')} Run on: ${esc(x.where)}</span></div>` : '')
      + commands
      + (x.warning ? `<div class="wi-rec__warning">${icon('alert')} ${esc(x.warning)}</div>` : '')
      + (x.references?.length ? `<div class="wi-rec__refs"><span class="pf-text-secondary">Vendor reference</span>`
        + x.references.map(f => `<a class="wi-link" href="${esc(f.url)}" target="_blank" rel="noopener"><b>${esc(f.vendor)}</b> ${esc(f.title)}${icon('external')}</a>`).join('')
        + '</div>' : '')
      + this.fixHtml((r.fixes || [])[i], (r.actions || []).filter(a => a.rec_index === i), i) + '</div>';
  },
  // The fix of one recommendation: the button (or why it cannot run) and the fixes already run from this result.
  fixHtml(fx, actions, i) {
    if (!fx && !actions.length) return '';
    let html = '<div class="wi-fix">';
    if (fx?.selectable) {   // the button runs the ticked items; syncSelection keeps count, risk and colour current
      html += `<div class="wi-fix__bar"><button type="button" class="pf-btn pf-m-primary pf-m-small" data-fix="${i}" disabled>`
        + `${icon('play')}${esc(fx.label || 'Run this fix')}<span class="wi-fix__count"></span></button>`
        + '<span class="pf-label pf-m-blue wi-fix__risk">Standard fix</span>'
        + `<span class="pf-text-secondary pf-text-sm">on <b>${esc(fx.target)}</b>: one ${esc(singular(fx.noun))} after the other, `
        + `${fx.stop_on_failure ? 'stops at the first one that is not done' : 'skips one that is not done, stops when one needs a person'}</span></div>`
        + (fx.available ? '' : `<span class="pf-helper-text wi-fix__why">${icon('lock')} ${esc(fx.reason)}</span>`);
    } else if (fx) {
      const risk = fx.risk === 'high' ? `<span class="pf-label pf-m-red">${icon('alert')}High risk: type ${fx.kind === 'openstack' ? 'the ID or name' : 'the host name'}</span>`
        : '<span class="pf-label pf-m-blue">Standard fix</span>';
      html += `<div class="wi-fix__bar"><button type="button" class="pf-btn ${fx.risk === 'high' ? 'pf-m-danger' : 'pf-m-primary'} pf-m-small" data-fix="${i}"`
        + `${fx.available && !actions.some(a => a.status === 'running') ? '' : ' disabled'}>${icon('play')}${esc(fx.label || 'Run this fix')}</button>`
        + `${risk}<span class="pf-text-secondary pf-text-sm">on <b>${esc(fx.target)}</b></span></div>`
        + (fx.available ? '' : `<span class="pf-helper-text wi-fix__why">${icon('lock')} ${esc(fx.reason)}</span>`);
    }
    for (const a of actions) {
      const label = {running: ['Running', 'blue', 'in-progress'], ok: ['Fix done', 'green', 'check-circle'],
        failed: ['Fix failed', 'red', 'x-circle'], unknown: ['Unknown', 'gold', 'alert']}[a.status] || [a.status, '', 'info'];
      const steps = (a.output || []).map(st => `<li class="${st.rc === 0 || st.rc === '0' ? 'is-ok' : 'is-fail'}">${icon(st.rc === 0 || st.rc === '0' ? 'check' : 'x')}`
        + `<span class="mono">${esc(String(st.command).split('\n')[0])}</span>${st.out ? `<pre class="pf-code-block">${esc(st.out)}</pre>` : ''}</li>`).join('');
      html += `<div class="wi-fix__run"><span class="pf-label pf-m-${label[1] || 'grey'}">${icon(label[2])}${esc(label[0])}</span>`
        + `<span class="pf-text-sm">Fix #${a.id} by ${esc(a.username)}, ${esc(shortTime(a.ts))}${a.risk === 'high' ? ', high risk confirmed' : ''}</span>`
        + (a.verify_run_id ? `<a class="pf-text-sm" href="#/runs/${a.verify_run_id}">Checked again: run #${a.verify_run_id} ${icon('angle-right')}</a>` : '')
        + (a.error ? `<span class="wi-fix__error">${esc(a.error)}</span>` : '')
        + (a.status === 'running' ? `<div class="wi-fix__live" data-live="${a.id}"><div data-bar></div>`
          + `<details class="wi-live" open hidden><summary>Live output</summary><pre class="pf-code-block" data-out></pre></details></div>`
          + `<ol class="wi-fix__progress" data-progress="${a.id}" aria-live="polite"></ol>` : '')
        + (steps ? `<details class="wi-step__more"${fx?.selectable ? ' open' : ''}><summary>${(a.output || []).length} ${fx?.selectable ? 'item(s)' : 'command(s)'}</summary><ol class="wi-fix__steps">${steps}</ol></details>` : '')
        + '</div>';
    }
    return html + '</div>';
  },
  // Follow a fix until it ends, then show its result and the check that runs again.
  async trackFix(actionId, runId) {
    if (this.tracking === actionId) return;
    this.tracking = actionId;
    const token = this.token;
    let since = 0;
    const progress = {done: [], current: null};
    for (;;) {
      await sleep(1500);
      if (token !== this.token) return;
      let data;
      try { data = await api(`/api/fixes/${actionId}?since=${since}`); } catch (e) { break; }
      since = data.next ?? since;
      if (data.progress) {   // the progress file of the fix: every item done so far, also after the page was reopened
        progress.done = (data.progress.done || []).map(d => ({n: String(d.n), status: d.status, label: d.label, summary: d.summary || ''}));
        progress.current = data.progress.current ? {n: String(data.progress.current.n), of: String(data.progress.of), label: data.progress.current.label} : null;
        progress.fromFile = true;
      }
      this.progress(actionId, progress.fromFile ? [] : data.lines || [], progress);
      this.live(actionId, data);
      if (data.item.status !== 'running') {
        const record = (await api(`/api/runs/${runId}`)).item;
        if (token !== this.token) return;
        this.record = record;
        this.tracking = null;
        this.renderResult(record);
        const done = data.item.status === 'ok';
        toast(done ? `Fix #${actionId} done. The check runs again${data.item.verify_run_id ? ` (run #${data.item.verify_run_id})` : ''}.`
          : `Fix #${actionId} failed: ${data.item.error || ''}`, done ? 'success' : 'danger',
          data.item.verify_run_id ? {label: 'Open', fn: () => { location.hash = `#/runs/${data.item.verify_run_id}`; }} : null);
        return;
      }
    }
    this.tracking = null;
  },
  // The progress bar of a running fix, and the output of the item running now (OpenStack fixes, every few seconds)
  live(actionId, data) {
    const box = $(`[data-live="${actionId}"]`);
    if (!box) return;
    Progress.show($('[data-bar]', box), data.bar, data.elapsed, `Progress of fix #${actionId}`);
    const lines = data.live || [];
    const det = $('.wi-live', box);
    det.hidden = !lines.length;
    if (!lines.length) return;
    const pre = $('[data-out]', box);
    const atBottom = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 30;
    pre.textContent = lines.join('\n');
    if (atBottom) pre.scrollTop = pre.scrollHeight;
  },
  // Live progress of a fix with selected items, from its Ansible output: the item running now and each item done.
  progress(actionId, lines, state) {
    for (const line of lines) {
      const task = /^TASK \[Item (\d+)\/(\d+): (.*?)\]/.exec(line);
      if (task && !/ done$/.test(task[3])) state.current = {n: task[1], of: task[2], label: task[3]};
      const done = /@@WI@@item (\d+) (ok|failed|skipped|attention) (.*?) :: (.*?)"?,?$/.exec(line);
      if (done) {
        state.done.push({n: done[1], status: done[2], label: done[3], summary: done[4].replace(/\\"/g, '"')});
        if (state.current && state.current.n === done[1]) state.current = null;
      }
    }
    const box = $(`[data-progress="${actionId}"]`);
    if (!box) return;
    const ic = {ok: ['check-circle', 'is-ok'], failed: ['alert', 'is-warn'], skipped: ['minus-circle', 'is-skip'], attention: ['x-circle', 'is-fail']};
    box.innerHTML = state.done.map(d => `<li class="${ic[d.status][1]}">${icon(ic[d.status][0])}<span><b>${esc(d.n)}. ${esc(d.label)}</b>`
      + ` <span class="pf-text-secondary">${esc(d.summary)}</span></span></li>`).join('')
      + (state.current ? `<li class="is-running"><span class="pf-spinner pf-m-sm" aria-hidden="true"></span><span><b>${esc(state.current.n)}/${esc(state.current.of)}. `
        + `${esc(state.current.label)}</b> <span class="pf-text-secondary">running…</span></span></li>` : '');
  },
  step(s, i) {
    const ic = {ok: 'check-circle', warn: 'alert', fail: 'x-circle', skip: 'minus-circle', info: 'info'}[s.status] || 'circle';
    let more = '';
    if (s.table?.rows?.length) {
      more += `<div class="pf-table-wrap"><table class="pf-table" aria-label="${esc(s.title)}"><thead><tr>${s.table.columns.map(c => `<th>${esc(c)}</th>`).join('')}</tr></thead>`
        + `<tbody>${s.table.rows.map(row => `<tr>${row.map(v => `<td>${esc(v)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`
        + (s.table.more ? `<span class="pf-helper-text">${s.table.more} more rows not shown.</span>` : '');
    }
    if (s.evidence) more += `<pre class="pf-code-block">${esc(s.evidence)}</pre>`;
    const open = s.open || s.status === 'fail' || s.status === 'warn' ? ' open' : '';   // open: a summary shown at once
    return `<li class="wi-step is-${esc(s.status)}" id="step-${i}"><span class="wi-step__icon" title="${esc((RESULT[s.status] || [s.status])[0])}">${icon(ic)}</span>`
      + `<span class="wi-step__title">${esc(s.title)}</span>${s.detail ? `<span class="wi-step__detail">${esc(s.detail)}</span>` : ''}`
      + (more ? `<details class="wi-step__more"${open}><summary>${s.table?.rows?.length ? `${s.table.rows.length + (s.table.more || 0)} row(s)` : 'Evidence'}</summary>${more}</details>` : '')
      + '</li>';
  },
  // Plain text for the operational ticket: what was checked, the result per step, and the fixes.
  copyNote() {
    const r = this.record;
    const res = r.result || {};
    const mark = {ok: '[OK]', warn: '[WARN]', fail: '[PROBLEM]', skip: '[SKIPPED]', info: '[INFO]'};
    const text = [`Operation Automation run #${r.id}: ${r.check_title}`, `Site ${r.site}${r.host ? `, host ${r.host}` : ''}; ${Object.entries(r.params || {}).map(([k, v]) => `${k}=${v}`).join(', ')}`,
      `By ${r.username}, ${fmtTime(r.ts)}`, `Result: ${(RESULT[r.status] || [r.status])[0]} - ${r.summary || r.error || ''}`, '',
      ...(res.steps || []).map(s => `${mark[s.status] || ''} ${s.title}: ${s.detail}`),
      ...((res.recommendations || []).length ? ['', 'How to fix it:', ...res.recommendations.flatMap((x, i) => [`${i + 1}. ${x.text}`,
        ...(x.where ? [`Run on: ${x.where}`] : []), ...(x.commands || []), ...(x.warning ? [`Note: ${x.warning}`] : []), ''])] : []),
      ...((r.wi || []).length ? ['', `WI: ${r.wi.map(w => w.url || w.title).join(' ; ')}`] : [])].join('\n');
    navigator.clipboard?.writeText(text).then(() => toast('Ticket note copied', 'success'), () => toast('Copy failed'));
  },
  async again() {
    const r = this.record;
    if (!r) return;
    if (Site.current !== r.site && Site.list.some(s => s.name === r.site)) {
      Site.activate(r.site);
      Site.render();
    }
    await run($('#runAgainBtn'), async () => {
      const data = await api('/api/runs', {site: r.site, check: r.check_id, params: r.params});
      location.hash = `#/runs/${data.run_id}`;
    });
  },
};

/* =========================================================================
   Run a fix: what will run where, typed confirmation for a high-risk fix (PatternFly modal)
   ========================================================================= */
const FixDialog = {
  record: null,
  index: -1,
  init() {
    $('#fixForm').addEventListener('submit', e => { e.preventDefault(); this.submit(); });
    $('#fixConfirm').addEventListener('input', () => this.sync());
  },
  // What the dialog shows for fix `index` of a run (and the ticked items of a fix with items)
  content(record, index, selected = []) {
    const fx = (record.fixes || [])[index];
    const rec = ((record.result || {}).recommendations || [])[index];
    if (!fx || !rec) return null;
    const picked = fx.selectable ? [...selected].sort((a, b) => a - b) : null;
    const items = picked ? picked.map(j => fx.items[j]).filter(Boolean) : [];
    const high = picked ? items.some(it => it.delete) : fx.risk === 'high';
    const commands = picked ? items.flatMap((it, k) => [`# ${k + 1}. ${it.label}`, ...it.commands]) : (fx.commands || []);
    return {
      fx, picked, high, commands, text: rec.text,
      expected: picked ? `${items.length} ${fx.noun}` : fx.target,
      title: high ? 'Run a high-risk fix' : 'Run this fix',
      risk: high ? alertBox('danger', 'High risk', fx.kind === 'openstack'
        ? 'It deletes on OpenStack, which cannot be undone. Make sure the customer / PIC approved it and it is recorded in the ticket.'
        : 'It deletes, stops, restarts, kills, reboots, formats or commits a change on a network device. '
          + 'Make sure the customer and the change process allow it now.') : '',
      where: dl([['Site', esc(record.site)], ['Runs on', fx.kind === 'openstack'
          ? `<b>OpenStack ${esc(record.site)}</b> <span class="pf-text-secondary">(director, as admin with overcloudrc)</span> · ${esc(fx.target)}`
          : fx.kind === 'ontap' ? `<b>${esc(fx.target)}</b> <span class="pf-text-secondary">(ONTAP REST of ${esc(record.site)}, account ontap:${esc(record.site)})</span>`
          : `<b>${esc(fx.target)}</b>${rec.where && !rec.where.startsWith(fx.target) ? ` <span class="pf-text-secondary">(${esc(rec.where)})</span>` : ''}`],
        ['From', `run #${record.id}, ${esc(fmtTime(record.finished || record.ts))}`]]),
      stopNote: picked
        ? `One ${singular(fx.noun)} after the other: each starts when the one before has ended; ${fx.stop_on_failure
          ? 'the run stops at the first one that is not done' : 'one that is not done is skipped, the run stops when one needs a person'}. `
          + 'Each item is checked again first, followed until it ends, and what can be fixed safely is fixed on the way. '
        : 'They stop at the first command that fails. ',
      stopHidden: !picked && (fx.commands || []).length < 2,
      checkHidden: !commands.some(c => /^(require|wait) /.test(c)),
    };
  },
  open(record, index, selected = []) {
    const d = this.content(record, index, selected);
    if (!d) return;
    this.record = record;
    this.index = index;
    this.selected = d.picked;
    this.expected = d.expected;
    $('#fixTitle').textContent = d.title;
    $('#fixRisk').innerHTML = d.risk;
    $('#fixText').textContent = d.text;
    $('#fixWhere').innerHTML = d.where;
    $('#fixCommands').textContent = d.commands.join('\n');
    $('#fixStopNote').textContent = d.stopNote;
    $('#fixStopNote').hidden = d.stopHidden;
    $('#fixCheckNote').hidden = d.checkHidden;
    $('#fixConfirmGroup').hidden = !d.high;
    $('#fixConfirmName').textContent = this.expected;
    $('#fixConfirm').value = '';
    $('#fixError').hidden = true;
    $('#fixRun').className = `pf-btn ${d.high ? 'pf-m-danger' : 'pf-m-primary'}`;
    this.sync();
    const high = d.high;
    $('#fixDialog').showModal();
    (high ? $('#fixConfirm') : $('#fixRun')).focus();
  },
  sync() {
    const fx = (this.record?.fixes || [])[this.index];
    const high = this.selected ? this.selected.some(j => fx?.items[j]?.delete) : fx?.risk === 'high';
    $('#fixRun').disabled = !fx || (high && $('#fixConfirm').value.trim() !== this.expected);
  },
  async submit() {
    const r = this.record;
    await run($('#fixRun'), async () => {
      try {
        const data = await api(`/api/runs/${r.id}/fixes/${this.index}`, {confirm: $('#fixConfirm').value.trim(),
          ...(this.selected ? {selected: this.selected} : {})});
        $('#fixDialog').close();
        toast(`Fix #${data.action_id} started on ${(r.fixes[this.index] || {}).target}.`, 'info');
        const record = (await api(`/api/runs/${r.id}`)).item;
        RunPage.record = record;
        RunPage.renderResult(record);
      } catch (e) {
        $('#fixError').textContent = e.message;
        $('#fixError').hidden = false;
      }
    });
  },
};

// Confirmation for destructive actions (PatternFly modal), as in the portal shell.
const Confirm = {
  ask(title, body, action = 'Remove') {
    const dialog = $('#confirmDialog');
    $('#confirmTitle').textContent = title;
    $('#confirmBody').textContent = body;
    $('#confirmOk').textContent = action;
    dialog.returnValue = '';
    dialog.showModal();
    $('#confirmCancel').focus();
    return new Promise(resolve => dialog.addEventListener('close', () => resolve(dialog.returnValue === 'ok'), {once: true}));
  },
};

/* =========================================================================
   Hosts & SSH (administrators): SSH credentials, the hosts of each site and product group
   ========================================================================= */
const Hosts = {
  data: null,
  editing: null,
  init() {
    $('#hsCredAdd').addEventListener('click', () => this.openCred(null));
    $('#hsHostAdd').addEventListener('click', () => this.openHost(null, false));
    $('#hsBulk').addEventListener('click', () => this.openHost(null, true));
    ['#hsSite', '#hsGroup'].forEach(sel => $(sel).addEventListener('change', () => this.render()));
    $('#hsQ').addEventListener('input', () => this.render());
    $('#hsCreds').addEventListener('click', e => this.action(e, 'cred'));
    $('#hsHosts').addEventListener('click', e => this.action(e, 'host'));
    $('#sshForm').addEventListener('submit', e => { e.preventDefault(); this.saveCred(); });
    $('#hostForm').addEventListener('submit', e => { e.preventDefault(); this.saveHost(); });
    $('#hostSite').addEventListener('change', () => this.jumpOptions());
    $('#sshAuth').addEventListener('change', () => this.authChanged());
  },
  async load() {
    if (!Session.admin) {
      $('#hsCreds').innerHTML = $('#hsHosts').innerHTML = `<tr><td colspan="8">${alertBox('warning', 'Administrators only')}</td></tr>`;
      return;
    }
    this.data = await api('/api/hosts');
    const opt = (map, current, all) => `<option value="">${all}</option>` + Object.entries(map).map(([k, v]) => `<option value="${esc(k)}"${k === current ? ' selected' : ''}>${esc(v)}</option>`).join('');
    $('#hsSite').innerHTML = opt(Object.fromEntries(this.data.sites.map(x => [x, x])), $('#hsSite').value, 'All sites');
    $('#hsGroup').innerHTML = opt(this.data.groups, $('#hsGroup').value, 'All groups');
    this.render();
  },
  render() {
    const d = this.data;
    if (!d) return;
    $('#hsCreds').innerHTML = d.credentials.map(c => this.credRow(c)).join('')
      || `<tr><td colspan="8"><div class="pf-empty-state">${icon('key')}<h2 class="pf-title">No SSH credential yet</h2><span>Add one, then the hosts that use it.</span></div></td></tr>`;
    const site = $('#hsSite').value, grp = $('#hsGroup').value, q = $('#hsQ').value.trim().toLowerCase();
    const rows = d.hosts.filter(h => (!site || h.site === site) && (!grp || h.grp === grp)
      && (!q || `${h.name} ${h.address} ${h.note || ''}`.toLowerCase().includes(q)));
    $('#hsShown').textContent = `${rows.length} of ${d.hosts.length} host${d.hosts.length === 1 ? '' : 's'}`;
    $('#hsHosts').innerHTML = rows.map(h => this.hostRow(h)).join('')
      || `<tr><td colspan="8"><div class="pf-empty-state">${icon('server')}<h2 class="pf-title">No host</h2><span>Add a host, or many at once.</span></div></td></tr>`;
  },
  // One row of each table, and the choices of the dialogs (also drawn by the guide of this page)
  credRow(c) {
    const d = this.data;
    return `<tr><td><b>${esc(c.name)}</b></td><td class="mono">${esc(c.username)}</td>`
      + `<td>${esc(d.auths[c.auth] || c.auth)}${c.auth === 'key' && c.fingerprint ? `<span class="pf-table__sub mono">${esc(c.fingerprint)}</span>` : ''}</td><td>${esc(d.privileges[c.privilege] || c.privilege)}</td>`
      + `<td>${c.fixes ? `<span class="pf-label pf-m-gold">${icon('play')}May run fixes</span>` : '<span class="pf-label">Read only</span>'}</td>`
      + `<td>${c.hosts}</td><td class="pf-text-sm">${esc(shortTime(c.updated))} ${esc(c.updated_by || '')}</td>`
      + `<td class="pf-table__actions"><button type="button" class="pf-btn pf-m-link pf-m-inline" data-act="edit" data-id="${c.id}">Edit</button>`
      + `<button type="button" class="pf-btn pf-m-link pf-m-inline pf-m-danger" data-act="delete" data-id="${c.id}">Remove</button></td></tr>`;
  },
  hostRow(h) {
    const d = this.data;
    return `<tr><td>${esc(h.site)}</td><td>${esc(d.groups[h.grp] || h.grp)}</td><td><b>${esc(h.name)}</b></td>`
      + `<td class="mono">${esc(h.address)}${h.port !== 22 ? `:${h.port}` : ''}${h.jump ? `<span class="pf-table__sub">through ${esc(h.jump)}</span>` : h.jumped ? `<span class="pf-table__sub">jump host of ${h.jumped}${h.proxy ? ', through the web proxy' : ''}</span>` : h.proxy ? '<span class="pf-table__sub">through the web proxy</span>' : ''}</td><td>${h.credential ? esc(h.credential) : '<span class="pf-label pf-m-gold">None</span>'}</td>`
      + `<td>${h.fixes ? `<span class="pf-label pf-m-gold">${icon('play')}Yes</span>` : '<span class="pf-text-secondary pf-text-sm">Read only</span>'}</td>`
      + `<td class="pf-text-sm">${esc(h.note || '')}</td>`
      + `<td class="pf-table__actions">${!h.jump_id && h.credential_id ? `<button type="button" class="pf-btn pf-m-link pf-m-inline" data-act="behind" data-id="${h.id}">Add hosts behind</button>` : ''}`
      + `<button type="button" class="pf-btn pf-m-link pf-m-inline" data-act="test" data-id="${h.id}">Test</button>`
      + `<button type="button" class="pf-btn pf-m-link pf-m-inline" data-act="edit" data-id="${h.id}">Edit</button>`
      + `<button type="button" class="pf-btn pf-m-link pf-m-inline pf-m-danger" data-act="delete" data-id="${h.id}">Remove</button></td></tr>`;
  },
  privilegeOptions(current) {
    return Object.entries(this.data.privileges).map(([k, v]) => `<option value="${esc(k)}"${k === current ? ' selected' : ''}>${esc(v)}</option>`).join('');
  },
  siteOptions(site) { return this.data.sites.map(x => `<option${x === site ? ' selected' : ''}>${esc(x)}</option>`).join(''); },
  groupOptions(grp) {
    return Object.entries(this.data.groups).map(([k, v]) => `<option value="${esc(k)}"${k === grp ? ' selected' : ''}>${esc(v)}</option>`).join('');
  },
  credOptions(cred) {
    return '<option value="">No credential (cannot be read yet)</option>'
      + this.data.credentials.map(c => `<option value="${c.id}"${cred === c.id ? ' selected' : ''}>${esc(c.name)} (${esc(c.username)}${c.fixes ? ', may run fixes' : ', read only'})</option>`).join('');
  },
  async action(e, kind) {
    const b = e.target.closest('[data-act]');
    if (!b) return;
    const id = Number(b.dataset.id);
    const item = (kind === 'cred' ? this.data.credentials : this.data.hosts).find(x => x.id === id);
    if (b.dataset.act === 'edit') return kind === 'cred' ? this.openCred(item) : this.openHost(item, false);
    if (b.dataset.act === 'test') return this.test(item, b);
    if (b.dataset.act === 'behind') return this.openHost(null, true, item);
    const what = kind === 'cred' ? `the SSH credential ${item.name}` : `${item.name} (${item.site})`;
    if (!await Confirm.ask(`Remove ${kind === 'cred' ? 'credential' : 'host'}?`, `Remove ${what}? ${kind === 'cred' ? 'Hosts must use another credential first.' : 'Checks can no longer choose it.'}`)) return;
    await run(b, async () => {
      await api(kind === 'cred' ? `/api/credentials/${id}` : `/api/hosts/${id}`, undefined, 'DELETE');
      toast('Removed.', 'success');
      await this.load();
    });
  },
  // The result of a connection test stays above the hosts table (with what to do when it failed) until the next test.
  async test(h, button) {
    const where = `${h.name} (${h.address}${h.port !== 22 ? `:${h.port}` : ''}${h.jump ? `, through ${h.jump}` : h.proxy ? ', through the web proxy' : ''})`;
    $('#hsNotice').innerHTML = '';
    await run(button, async () => {
      const {job_id} = await api(`/api/hosts/${h.id}/test`, {});
      for (let i = 0; i < 120; i++) {
        await sleep(1000);
        const job = await api(`/api/jobs/${job_id}`);
        if (job.status === 'running') continue;
        const res = job.result || {};
        const out = (res.steps || []).map(s => String(s.out || '').trim()).filter(Boolean);
        if (res.ok) {
          $('#hsNotice').innerHTML = alertBox('success', `Connection test of ${esc(where)}: connected as ${esc(out[1] || '?')} on ${esc(out[0] || '?')}.`);
        } else {
          const error = String(res.error || job.error || 'the connection failed');
          const hint = res.hint || '';
          $('#hsNotice').innerHTML = alertBox('danger', `Connection test of ${esc(where)} failed`,
            hint ? `<p><b>${esc(hint)}</b></p><p class="pf-text-sm mono">${esc(error.replace(` — ${hint}`, ''))}</p>` : esc(error));
        }
        return;
      }
      $('#hsNotice').innerHTML = alertBox('info', `Connection test of ${esc(where)}: no answer yet; look in Runs later.`);
    });
  },
  openCred(c) {
    this.editing = c;
    $('#sshTitle').textContent = c ? `Edit ${c.name}` : 'Add SSH credential';
    $('#sshName').value = c ? c.name : '';
    $('#sshUser').value = c ? c.username : '';
    $$('#sshAuth input').forEach(i => { i.checked = i.value === (c ? c.auth : 'key'); });
    $('#sshKey').value = $('#sshPass').value = '';
    $('#sshKey').placeholder = c && c.auth === 'key' && c.fingerprint
      ? `Stored key: ${c.fingerprint}. Paste a new private key only to replace it.`
      : '-----BEGIN OPENSSH PRIVATE KEY-----\n…\n-----END OPENSSH PRIVATE KEY-----';
    $('#sshPrivilege').innerHTML = this.privilegeOptions(c ? c.privilege : 'sudo');
    $('#sshFixes').checked = !!(c && c.fixes);
    $('#sshError').hidden = true;
    this.authChanged();
    $('#sshDialog').showModal();
    $('#sshName').focus();
  },
  authChanged() {
    const key = ($('#sshAuth input:checked') || {}).value !== 'password';
    $('#sshKeyGroup').hidden = !key;
    $('#sshPassGroup').hidden = key;
    $('#sshKeyReq').hidden = $('#sshPassReq').hidden = !!this.editing;
    const fp = this.editing && this.editing.auth === 'key' && this.editing.fingerprint;
    $('#sshKeyHelp').textContent = fp ? `A key is stored (${fp}). Leave empty to keep it.`
      : this.editing ? 'Leave empty to keep the stored key.' : 'Without a passphrase. Stored encrypted, never shown again.';
    $('#sshPassHelp').textContent = this.editing ? 'Leave empty to keep the stored password.' : 'Stored encrypted, never shown again.';
  },
  async saveCred() {
    const auth = ($('#sshAuth input:checked') || {}).value || 'key';
    const body = {name: $('#sshName').value.trim(), username: $('#sshUser').value.trim(), auth, privilege: $('#sshPrivilege').value,
      fixes: $('#sshFixes').checked, secret: auth === 'key' ? $('#sshKey').value : $('#sshPass').value};
    await run($('#sshSave'), async () => {
      try {
        if (this.editing) await api(`/api/credentials/${this.editing.id}`, body, 'PUT');
        else await api('/api/credentials', body);
        $('#sshKey').value = $('#sshPass').value = '';
        $('#sshDialog').close();
        toast('SSH credential saved.', 'success');
        await this.load();
      } catch (e) {
        $('#sshError').textContent = e.message;
        $('#sshError').hidden = false;
      }
    });
  },
  // via: a host the portal reaches; the new hosts are behind it (it is their jump host), on its site and group.
  openHost(h, many, via = null) {
    this.editing = h;
    this.many = many;
    const d = this.data;
    const site = h ? h.site : via ? via.site : $('#hsSite').value || Site.current;
    const grp = h ? h.grp : via ? via.grp : $('#hsGroup').value;
    const cred = h ? h.credential_id : via ? via.credential_id : null;
    $('#hostTitle').textContent = h ? `Edit ${h.name}` : via ? `Add hosts behind ${via.name}` : many ? 'Add many hosts' : 'Add host';
    $('#hostSite').innerHTML = this.siteOptions(site);
    $('#hostGroup').innerHTML = this.groupOptions(grp);
    $('#hostCred').innerHTML = this.credOptions(cred);
    $('#hostLines').placeholder = via ? `addresses as ${via.name} reaches them, e.g.\nnode-01 10.249.1.11\nnode-02 10.249.1.12 2222   (SSH port 2222)`
      : 'dca-cdn-lb-03 172.31.10.69\ndca-cdn-lb-04 172.31.10.70 2222';
    $('#hostSingle').hidden = many;
    $('#hostMany').hidden = !many;
    $('#hostName').value = h ? h.name : '';
    $('#hostAddress').value = h ? h.address : '';
    $('#hostPort').value = h ? h.port : 22;
    $('#hostNote').value = h ? h.note || '' : '';
    $('#hostLines').value = '';
    this.jumpOptions(h ? h.jump_id : via ? via.id : null);
    $('#hostError').hidden = true;
    $('#hostDialog').showModal();
    (many ? $('#hostLines') : $('#hostName')).focus();
  },
  // Jump hosts: hosts of the chosen site the portal reaches directly (not through a jump host themselves), with a credential.
  jumpOptions(current) {
    const site = $('#hostSite').value, self = this.editing ? this.editing.id : null;
    const keep = current === undefined ? Number($('#hostJump').value) || null : current;
    const usable = this.data.hosts.filter(x => x.site === site && x.id !== self && !x.jump_id && x.credential_id);
    $('#hostJump').innerHTML = '<option value="">Direct (the portal reaches the address)</option>'
      + usable.map(x => `<option value="${x.id}"${x.id === keep ? ' selected' : ''}>Jump host ${esc(x.name)} (${esc(x.address)}, ${esc(this.data.groups[x.grp] || x.grp)})</option>`).join('');
    $('#hostJump').disabled = !!(this.editing && this.editing.jumped);
    $('#hostJumpHelp').textContent = this.editing && this.editing.jumped
      ? `${this.editing.jumped} host(s) connect through ${this.editing.name}, so it is reached directly.`
      : 'For hosts the portal cannot reach directly (no reachable IP): the portal logs in to the jump host with its own credential, and from there opens SSH to this host with the credential above.';
  },
  async saveHost() {
    const body = {site: $('#hostSite').value, group: $('#hostGroup').value, credential_id: $('#hostCred').value || null,
      jump_id: $('#hostJump').value || null};
    await run($('#hostSave'), async () => {
      try {
        if (this.many) {
          const data = await api('/api/hosts/bulk', {...body, lines: $('#hostLines').value});
          toast(`${data.added} host(s) added.`, 'success');
        } else {
          Object.assign(body, {name: $('#hostName').value.trim(), address: $('#hostAddress').value.trim(), port: $('#hostPort').value.trim(),
            note: $('#hostNote').value.trim()});
          if (this.editing) await api(`/api/hosts/${this.editing.id}`, body, 'PUT');
          else await api('/api/hosts', body);
          toast('Host saved.', 'success');
        }
        $('#hostDialog').close();
        Catalog.loaded = '';
        await this.load();
      } catch (e) {
        $('#hostError').textContent = e.message;
        $('#hostError').hidden = false;
      }
    });
  },
};

/* =========================================================================
   BMC (administrators): the BMC web accounts and the management IP of each server, read with Redfish over HTTPS
   ========================================================================= */
const Bmcs = {
  data: null,
  editing: null,
  many: false,
  init() {
    $('#bmCredAdd').addEventListener('click', () => this.openCred(null));
    $('#bmAdd').addEventListener('click', () => this.open(null, false));
    $('#bmBulk').addEventListener('click', () => this.open(null, true));
    $('#bmSite').addEventListener('change', () => this.render());
    $('#bmQ').addEventListener('input', () => this.render());
    $('#bmCreds').addEventListener('click', e => this.action(e, 'cred'));
    $('#bmList').addEventListener('click', e => this.action(e, 'bmc'));
    $('#bmCredForm').addEventListener('submit', e => { e.preventDefault(); this.saveCred(); });
    $('#bmForm').addEventListener('submit', e => { e.preventDefault(); this.save(); });
  },
  async load() {
    if (!Session.admin) {
      $('#bmCreds').innerHTML = $('#bmList').innerHTML = `<tr><td colspan="7">${alertBox('warning', 'Administrators only')}</td></tr>`;
      return;
    }
    this.data = await api('/api/bmc');
    const current = $('#bmSite').value;
    $('#bmSite').innerHTML = '<option value="">All sites</option>'
      + this.data.sites.map(x => `<option${x === current ? ' selected' : ''}>${esc(x)}</option>`).join('');
    this.render();
  },
  render() {
    const d = this.data;
    if (!d) return;
    $('#bmCreds').innerHTML = d.credentials.map(c => this.credRow(c)).join('')
      || `<tr><td colspan="5"><div class="pf-empty-state">${icon('key')}<h2 class="pf-title">No BMC account yet</h2><span>Add the web login of the BMCs (read-only role is enough), then the BMCs.</span></div></td></tr>`;
    const site = $('#bmSite').value, q = $('#bmQ').value.trim().toLowerCase();
    const rows = d.bmcs.filter(b => (!site || b.site === site) && (!q || `${b.name} ${b.address} ${b.note || ''}`.toLowerCase().includes(q)));
    $('#bmShown').textContent = `${rows.length} of ${d.bmcs.length} BMC${d.bmcs.length === 1 ? '' : 's'}`;
    $('#bmList').innerHTML = rows.map(b => this.row(b)).join('')
      || `<tr><td colspan="7"><div class="pf-empty-state">${icon('cubes')}<h2 class="pf-title">No BMC</h2><span>Add a BMC, or many at once.</span></div></td></tr>`;
  },
  // One row of each table, and the choices of the dialogs (also drawn by the guide of this page)
  credRow(c) {
    return `<tr><td><b>${esc(c.name)}</b></td><td class="mono">${esc(c.username)}</td><td>${c.bmcs}</td>`
      + `<td class="pf-text-sm">${esc(shortTime(c.updated))} ${esc(c.updated_by || '')}</td>`
      + `<td class="pf-table__actions"><button type="button" class="pf-btn pf-m-link pf-m-inline" data-act="edit" data-id="${c.id}">Edit</button>`
      + `<button type="button" class="pf-btn pf-m-link pf-m-inline pf-m-danger" data-act="delete" data-id="${c.id}">Remove</button></td></tr>`;
  },
  row(b) {
    const d = this.data;
    return `<tr><td>${esc(b.site)}</td><td><b>${esc(b.name)}</b></td>`
      + `<td class="mono"><a href="https://${esc(b.address)}${b.port !== 443 ? `:${b.port}` : ''}/" target="_blank" rel="noopener">${esc(b.address)}${b.port !== 443 ? `:${b.port}` : ''}${icon('external')}</a></td>`
      + `<td>${esc(d.vendors[b.vendor] || b.vendor || '')}</td>`
      + `<td>${b.credential ? esc(b.credential) : '<span class="pf-label pf-m-gold">None</span>'}</td><td class="pf-text-sm">${esc(b.note || '')}</td>`
      + `<td class="pf-table__actions">${b.credential_id ? `<button type="button" class="pf-btn pf-m-link pf-m-inline" data-act="check" data-id="${b.id}">Check</button>` : ''}`
      + `<button type="button" class="pf-btn pf-m-link pf-m-inline" data-act="edit" data-id="${b.id}">Edit</button>`
      + `<button type="button" class="pf-btn pf-m-link pf-m-inline pf-m-danger" data-act="delete" data-id="${b.id}">Remove</button></td></tr>`;
  },
  siteOptions(site) { return this.data.sites.map(x => `<option${x === site ? ' selected' : ''}>${esc(x)}</option>`).join(''); },
  vendorOptions(vendor) {
    return Object.entries(this.data.vendors).map(([k, v]) => `<option value="${esc(k)}"${k === vendor ? ' selected' : ''}>${esc(v)}</option>`).join('');
  },
  credOptions(id) {
    return '<option value="">No account (cannot be read yet)</option>'
      + this.data.credentials.map(c => `<option value="${c.id}"${id === c.id ? ' selected' : ''}>${esc(c.name)} (${esc(c.username)})</option>`).join('');
  },
  async action(e, kind) {
    const b = e.target.closest('[data-act]');
    if (!b) return;
    const id = Number(b.dataset.id);
    const item = (kind === 'cred' ? this.data.credentials : this.data.bmcs).find(x => x.id === id);
    if (b.dataset.act === 'edit') return kind === 'cred' ? this.openCred(item) : this.open(item, false);
    if (b.dataset.act === 'check') {
      return run(b, async () => {
        const data = await api('/api/runs', {site: item.site, check: 'bmc-health', params: {bmc: item.name}});
        location.hash = `#/runs/${data.run_id}`;
      });
    }
    const what = kind === 'cred' ? `the BMC account ${item.name}` : `${item.name} (${item.site})`;
    if (!await Confirm.ask(`Remove ${kind === 'cred' ? 'account' : 'BMC'}?`, `Remove ${what}? ${kind === 'cred' ? 'BMCs must use another account first.' : 'Checks can no longer choose it.'}`)) return;
    await run(b, async () => {
      await api(kind === 'cred' ? `/api/bmc/credentials/${id}` : `/api/bmc/${id}`, undefined, 'DELETE');
      toast('Removed.', 'success');
      Catalog.loaded = '';
      await this.load();
    });
  },
  openCred(c) {
    this.editing = c;
    $('#bmCredTitle').textContent = c ? `Edit ${c.name}` : 'Add BMC account';
    $('#bmCredName').value = c ? c.name : '';
    $('#bmCredUser').value = c ? c.username : '';
    $('#bmCredPass').value = '';
    $('#bmCredPassReq').hidden = !!c;
    $('#bmCredPassHelp').textContent = c ? 'Leave empty to keep the stored password.' : 'The BMC web login. Stored encrypted, never shown again.';
    $('#bmCredError').hidden = true;
    $('#bmCredDialog').showModal();
    $('#bmCredName').focus();
  },
  async saveCred() {
    const body = {name: $('#bmCredName').value.trim(), username: $('#bmCredUser').value.trim(), secret: $('#bmCredPass').value};
    await run($('#bmCredSave'), async () => {
      try {
        if (this.editing) await api(`/api/bmc/credentials/${this.editing.id}`, body, 'PUT');
        else await api('/api/bmc/credentials', body);
        $('#bmCredPass').value = '';
        $('#bmCredDialog').close();
        toast('BMC account saved.', 'success');
        await this.load();
      } catch (e) {
        $('#bmCredError').textContent = e.message;
        $('#bmCredError').hidden = false;
      }
    });
  },
  open(b, many) {
    this.editing = b;
    this.many = many;
    const d = this.data;
    const site = b ? b.site : $('#bmSite').value || Site.current;
    $('#bmTitle').textContent = b ? `Edit ${b.name}` : many ? 'Add many BMCs' : 'Add BMC';
    $('#bmSiteSel').innerHTML = this.siteOptions(site);
    $('#bmVendor').innerHTML = this.vendorOptions(b ? b.vendor : '');
    $('#bmCred').innerHTML = this.credOptions(b ? b.credential_id : null);
    $('#bmSingle').hidden = many;
    $('#bmMany').hidden = !many;
    $('#bmName').value = b ? b.name : '';
    $('#bmAddress').value = b ? b.address : '';
    $('#bmPort').value = b ? b.port : 443;
    $('#bmNote').value = b ? b.note || '' : '';
    $('#bmLines').value = '';
    $('#bmError').hidden = true;
    $('#bmDialog').showModal();
    (many ? $('#bmLines') : $('#bmName')).focus();
  },
  async save() {
    const body = {site: $('#bmSiteSel').value, vendor: $('#bmVendor').value, credential_id: $('#bmCred').value || null};
    await run($('#bmSave'), async () => {
      try {
        if (this.many) {
          const data = await api('/api/bmc/bulk', {...body, lines: $('#bmLines').value});
          toast(`${data.added} BMC(s) added.`, 'success');
        } else {
          Object.assign(body, {name: $('#bmName').value.trim(), address: $('#bmAddress').value.trim(), port: $('#bmPort').value.trim(),
            note: $('#bmNote').value.trim()});
          if (this.editing) await api(`/api/bmc/${this.editing.id}`, body, 'PUT');
          else await api('/api/bmc', body);
          toast('BMC saved.', 'success');
        }
        $('#bmDialog').close();
        Catalog.loaded = '';
        await this.load();
      } catch (e) {
        $('#bmError').textContent = e.message;
        $('#bmError').hidden = false;
      }
    });
  },
};

/* =========================================================================
   Where a check reads: topology diagram (PatternFly Topology / OpenShift Topology view: nodes, edges, status decorators)
   ========================================================================= */
const Topology = {
  STATUS: {ok: ['check-circle', 'OK'], warn: ['alert', 'Warning'], fail: ['x-circle', 'Problem found'], error: ['x-circle', 'Could not run'],
    skip: ['minus-circle', 'Not checked'], info: ['info', 'Info'], reached: ['check', 'Reached']},
  short(text, n = 26) { text = String(text || ''); return text.length > n ? `${text.slice(0, n - 1)}…` : text; },
  node(n, x, y, running) {
    const [ic, word] = this.STATUS[n.status] || ['', ''];
    const steps = (n.steps || []).map(st => `\n${(this.STATUS[st.status] || ['', st.status])[1]}: ${st.title}`).join('');
    const tip = `${n.label}${n.sub ? ` — ${n.sub}` : ''}${word ? `\n${word}` : running ? '\nReading…' : ''}${steps}`;
    return `<g class="topo-node${n.status ? ` is-${esc(n.status)}` : ''}${running && !n.status ? ' is-running' : ''}" transform="translate(${x},${y})" tabindex="0" role="img" aria-label="${esc(tip.replace(/\n/g, '. '))}">`
      + `<title>${esc(tip)}</title><circle class="topo-node__bg" r="28"></circle>`
      + `<use href="#i-${esc(n.kind || 'circle')}" x="-12" y="-12" width="24" height="24" class="topo-node__icon"></use>`
      + (ic ? `<g class="topo-node__decorator" transform="translate(20,-20)"><circle r="10"></circle><use href="#i-${ic}" x="-7" y="-7" width="14" height="14"></use></g>` : '')
      + `<text class="topo-node__label" y="48">${esc(this.short(n.label))}</text>`
      + (n.sub ? `<text class="topo-node__sub" y="64">${esc(this.short(n.sub, 30))}</text>` : '')
      + (n.steps?.length ? `<text class="topo-node__count" y="80">${n.steps.length} step${n.steps.length === 1 ? '' : 's'}</text>` : '')
      + '</g>';
  },
  edge(x1, y1, x2, y2, label) {
    const mid = (x1 + x2) / 2;
    const path = y1 === y2 ? `M${x1 + 30},${y1} L${x2 - 34},${y2}` : `M${x1 + 30},${y1} C${mid},${y1} ${mid},${y2} ${x2 - 34},${y2}`;
    return `<path class="topo-edge" d="${path}" marker-end="url(#topoArrow)"></path>`
      + (label ? `<text class="topo-edge__label" x="${mid}" y="${(y1 + y2) / 2 - 8}">${esc(this.short(label, 24))}</text>` : '');
  },
  // One line for the folded diagram: the systems read and how each one is
  summary(t) {
    const nodes = (t?.lanes || []).flat().filter(n => n && n.id !== 'portal');
    const bad = nodes.filter(n => n.status === 'fail' || n.status === 'warn').map(n => n.label);
    if (!nodes.length) return '';
    return `${nodes.length} system${nodes.length === 1 ? '' : 's'}` + (bad.length ? `; findings on ${bad.slice(0, 3).join(', ')}` : '')
      + ' · open for the diagram';
  },
  // HTML for a topology from the server ({root, lanes}); '' when there is nothing to draw.
  html(t, running = false) {
    if (!t || !t.root || !(t.lanes || []).length) return '';
    const COL = 200, ROW = 130, X0 = 70, Y0 = 50;
    const height = Y0 + (t.lanes.length - 1) * ROW + 100;
    const width = X0 + Math.max(...t.lanes.map(l => l.length)) * COL + 60;
    const rootY = Y0 + ((t.lanes.length - 1) * ROW) / 2;
    let edges = '', nodes = this.node(t.root, X0, rootY, running);
    t.lanes.forEach((lane, r) => {
      const y = Y0 + r * ROW;
      lane.forEach((n, i) => {
        const x = X0 + (i + 1) * COL;
        edges += i === 0 ? this.edge(X0, rootY, x, y, n.via) : this.edge(x - COL, y, x, y, n.via);
        nodes += this.node(n, x, y, running);
      });
    });
    const legend = ['ok', 'warn', 'fail', 'reached'].map(k => `<span class="topo-legend__item is-${k}">${icon(this.STATUS[k][0])}${esc(this.STATUS[k][1])}</span>`).join('');
    return `<div class="topo" role="group" aria-label="Where it reads"><svg class="topo__svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}">`
      + '<defs><marker id="topoArrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">'
      + '<path d="M0,0 L10,5 L0,10 z" class="topo-arrow"></path></marker></defs>'
      + edges + nodes + `</svg></div><div class="topo-legend">${legend}<span class="pf-text-secondary">Read-only accounts; nothing is changed.</span></div>`;
  },
};

/* =========================================================================
   Where to look: the screens of a run, drawn from what the check read (wi_analysis/screens.py). The terminal is drawn
   in the page; every web console is an isolated iframe document with that console's own look (static/consoles: VMware
   Clarity CSS for vCloud Director / vSphere / NSX, the RCUE look of Horizon in RHOSP, ONTAP System Manager), 1280 px
   wide and scaled like a screenshot. Numbered marks point at what the check found; the notes say what they mean.
   ========================================================================= */
const Screens = {
  APP: {terminal: 'Terminal', horizon: 'Horizon (RHOSP)', vcd: 'vCloud Director', vsphere: 'vSphere Client', nsx: 'NSX Manager',
    ontap: 'ONTAP System Manager'},
  WIDTH: 1280,
  init() {
    const root = $('#runScreens');
    root.addEventListener('click', e => {
      const b = e.target.closest('[data-screen]');
      if (!b) return;
      $$('#runScreens [data-screen]').forEach(t => t.setAttribute('aria-selected', String(t === b)));
      $$('#runScreens [data-screen-panel]').forEach(p => { p.hidden = p.dataset.screenPanel !== b.dataset.screen; });
      this.fit();
    });
    // Now / after the fix (expected) / after the fix (as it ran)
    root.addEventListener('change', e => {
      const input = e.target.closest('.ws-switch input');
      if (!input) return;
      const panel = input.closest('[data-screen-panel]');
      $$('[data-view]', panel).forEach(v => { v.hidden = v.dataset.view !== input.value; });
      this.fit();
    });
    root.addEventListener('load', e => { if (e.target.tagName === 'IFRAME') this.fitFrame(e.target); }, true);
    window.addEventListener('resize', () => this.fit());
  },
  render(list, record = {}) {
    list = list || [];
    $('#runScreensCard').hidden = !list.length;
    $('#runScreens').innerHTML = list.length ? this.html(list, record) : '';
    this.fit();
  },
  // Scale every visible screen to the card width, its height to its content (fonts may load later: fit again).
  fit() { $$('#runScreens iframe.ws-iframe').forEach(f => this.fitFrame(f)); },
  fitFrame(f) {
    const wrap = f.parentElement;
    if (!wrap || !wrap.offsetParent) return;
    const doc = f.contentDocument;
    if (!doc || !doc.body) return;
    const k = Math.min(1, wrap.clientWidth / (Number(f.dataset.w) || this.WIDTH));
    const h = Math.max(doc.documentElement.scrollHeight, doc.body.scrollHeight);
    f.style.height = `${h}px`;
    f.style.transform = `scale(${k})`;
    wrap.style.height = `${Math.ceil(h * k)}px`;
    if (!f.dataset.fonts && doc.fonts) { f.dataset.fonts = '1'; doc.fonts.ready.then(() => this.fitFrame(f)); }
  },
  html(list, record) {
    const ran = (record.actions || []).filter(a => ['ok', 'failed'].includes(a.status) && (a.output || []).length);
    const tabs = list.map((s, i) => `<button type="button" role="tab" data-screen="${i}" aria-selected="${i === 0}">`
      + `${this.dot(s.status)}${esc(s.label)}</button>`).join('');
    return `<div class="subtabs" role="tablist" aria-label="Screens">${tabs}</div>`
      + list.map((s, i) => {
        const real = s.app === 'terminal' && s.key === 'term-host' ? ran : [];
        const views = [['now', `Now · found by run #${record.id || ''}`]];
        if (s.after) views.push(['after', 'After the fix · expected']);
        real.forEach(a => views.push([`fix${a.id}`, `After fix #${a.id} · as it ran`]));
        const sw = views.length > 1 ? `<div class="pf-toggle-group pf-m-compact ws-switch" role="radiogroup" aria-label="View">${views.map(([v, t], k) =>
          `<label><input type="radio" name="wsv-${i}" value="${v}"${k === 0 ? ' checked' : ''}><span>${esc(t)}</span></label>`).join('')}</div>` : '';
        return `<div class="ws-panel" role="tabpanel" data-screen-panel="${i}"${i ? ' hidden' : ''}>${sw}`
          + `<div data-view="now">${this.frame(s)}${this.notes(s)}</div>`
          + (s.after ? `<div data-view="after" hidden>${this.ribbon('expected')}${this.frame(Object.assign({}, s, s.after))}${this.notes(s.after)}</div>` : '')
          + real.map(a => `<div data-view="fix${a.id}" hidden>${this.ribbon('ran', a)}${this.frame(this.fixScreen(s, a))}</div>`).join('')
          + `<p class="ws-caption">${icon('info')} ${esc(this.APP[s.app] || s.app)}, drawn by the portal from what this run read. `
          + 'The real screen can differ a little by version.</p></div>';
      }).join('');
  },
  ribbon(kind, a) {
    if (kind === 'expected') return `<div class="ws-ribbon">${icon('info')} What this place looks like once How to fix it is done — the values come from the fix `
      + '(new IP, new rule, new quota…). Run the check again to confirm.</div>';
    const ok = a.status === 'ok';
    return `<div class="ws-ribbon${ok ? ' ws-ribbon--ok' : ' ws-ribbon--failed'}">${icon(ok ? 'check-circle' : 'x-circle')} Fix #${a.id} `
      + `${ok ? 'ran' : 'failed'} on ${esc(a.target)} by ${esc(a.username)}, ${esc(fmtTime(a.finished || a.ts))} — the real output.`
      + (a.verify_run_id ? ` Checked again: <a href="#/runs/${a.verify_run_id}">run #${a.verify_run_id}</a>.` : '') + '</div>';
  },
  // A fix that ran from the portal, as a terminal: each command with its real output.
  fixScreen(s, a) {
    const blocks = (a.output || []).map(st => ({type: 'terminal', command: st.command, rc: st.rc,
      lines: String(st.out || '').split('\n').slice(-40).map(t => ({t}))}));
    return {app: 'terminal', chrome: s.chrome, blocks};
  },
  dot(status) { return `<span class="ws-dot ws-tone--${esc(status || 'info')}" aria-hidden="true"></span>`; },
  mark(m) {
    if (!m) return '';
    return m.n ? `<span class="ws-mark ws-tone--${esc(m.tone)}" title="See note ${m.n}">${m.n}</span>` : `<span class="ws-dot ws-tone--${esc(m.tone)}"></span>`;
  },
  notes(s) {
    const items = (s.notes || []).map(n => `<li>${this.mark(n)}<span>${esc(n.text)}</span></li>`).join('');
    return items ? `<ol class="ws-notes">${items}</ol>` : '';
  },
  frame(s) {
    if (s.app === 'terminal') return this.terminal(s);
    const w = s.app === 'vcd' ? 1440 : this.WIDTH;
    return `<div class="ws-shot"><iframe class="ws-iframe" data-w="${w}" style="width:${w}px" title="${esc(s.label || this.APP[s.app] || '')}" sandbox="allow-same-origin" `
      + `srcdoc="${esc(this.doc(s))}"></iframe></div>`;
  },
  // ---------------------------------------------------------------- terminal (in the page)
  terminal(s) {
    const c = s.chrome || {};
    return `<div class="ws-scroll"><div class="ws ws--terminal"><div class="ws-term__bar"><span class="ws-browser__dots"><i></i><i></i><i></i></span>${esc(c.title || '')}</div>`
      + `<div class="ws-term">${(s.blocks || []).map(b => this.termBlock(b, c.prompt)).join('')}</div></div></div>`;
  },
  termBlock(b, prompt) {
    const lines = (b.lines || []).map(l => l.gap ? `<div class="ws-term__gap">⋮ ${l.gap} line${l.gap === 1 ? '' : 's'}</div>`
      : `<div class="ws-term__line${l.n || l.tone ? ` is-marked ws-tone--${esc(l.tone)}` : ''}"><span class="ws-term__gutter">${this.mark(l.n ? l : null)}</span><span>${esc(l.t) || ' '}</span></div>`).join('');
    return `<div class="ws-term__cmd"><span class="ws-term__prompt">${esc(prompt || '$')}</span> ${esc(b.command)}${this.mark(b.mark)}</div>${lines}`
      + (b.skipped ? `<div class="ws-term__line ws-term__note"># not run: ${esc(b.skipped)}</div>` : '')
      + (b.rc ? `<div class="ws-term__line ws-term__note"># exit code ${esc(b.rc)}</div>` : '');
  },
  // ---------------------------------------------------------------- console documents (iframe)
  doc(s) {
    const v = UI_VERSION ? `?v=${UI_VERSION}` : '';
    const css = [`${BASE}/static/consoles/consoles.css${v}`];
    if (['vcd', 'vsphere', 'nsx'].includes(s.app)) css.unshift(`${BASE}/static/consoles/clarity/clr-ui.min.css${v}`);
    const body = {vcd: () => this.vcd(s), horizon: () => this.horizon(s), vsphere: () => this.vsphere(s), nsx: () => this.nsx(s),
      ontap: () => this.ontap(s)}[s.app];
    return `<!doctype html><html lang="en"><head><meta charset="utf-8"><base target="_blank">${css.map(h => `<link rel="stylesheet" href="${h}">`).join('')}</head>`
      + `<body class="c-${esc(s.app)}">${body ? body() : ''}</body></html>`;
  },
  ico(name, cls = '') {
    const svg = (window.WS_ICONS || {})[name];
    return svg ? `<span class="ico ${cls}"><svg viewBox="0 0 36 36" aria-hidden="true">${svg}</svg></span>` : '';
  },
  mk(m) { return m ? (m.n ? `<span class="mk mk-${esc(m.tone)}">${m.n}</span>` : `<span class="mk mk-${esc(m.tone)}">•</span>`) : ''; },
  hl(m) { return m ? ` hl-${esc(m.tone)}` : ''; },
  // A Clarity datagrid (vCloud, vSphere, NSX, System Manager)
  dg(b, opts = {}) {
    const marks = b.marks || {};
    const sel = b.select === 'radio' ? '<span class="radio"></span>' : b.select === 'checkbox' ? '<span class="chk"></span>' : '';
    const head = (sel ? `<th class="sel">${b.select === 'checkbox' ? sel : ''}</th>` : '')
      + b.columns.map(c => `<th>${esc(c)}${opts.filters !== false && c !== '#' ? this.ico('filter-grid') : ''}</th>`).join('');
    const status = c => /^(Up|Normal|Active|Succeeded|Success|Yes|Powered on|Connected)$/.test(c) ? `<span class="ok">${this.ico('success-standard')}${esc(c)}</span>`
      : /^(Down|Error|Failed|Disabled|Not connected)$/.test(c) ? `<span class="bad">${this.ico('error-standard')}${esc(c)}</span>` : esc(c);
    const link = b.link_col === undefined ? 0 : b.link_col;
    const statusCol = b.columns.map(c => /^(Status|State|Connectivity Status|Connected)$/.test(c));
    const rows = b.rows.map((r, i) => {
      const m = marks[String(i)];
      return `<tr class="row${this.hl(m)}">${sel ? `<td class="sel">${sel}</td>` : ''}${r.map((c, j) =>
        `<td title="${esc(c)}">${j === link ? `<a>${esc(c)}</a>` : (statusCol[j] ? status(String(c)) : esc(c))}${j === 0 ? this.mk(m) : ''}</td>`).join('')}</tr>`;
    }).join('') || `<tr class="dg-empty"><td colspan="${b.columns.length + (sel ? 1 : 0)}">${esc(b.empty || 'No items to display.')}</td></tr>`;
    const total = b.total ?? b.rows.length;
    const count = b.count ? `${total ? `1 - ${total} of ${total}` : '0'} ${esc(b.count)}` : esc(b.footer || '');
    return `<div class="dg"><table><thead><tr>${head}</tr></thead><tbody>${rows}</tbody></table>`
      + (b.rows.length < 3 ? '<div class="dg-pad"></div>' : '')
      + `<div class="dg-foot"><span class="mc">Manage Columns</span>${b.per_page ? '<span>Rules per page <b>15</b></span>' : ''}<span class="cnt">${count}</span></div></div>`;
  },
  // ---------------------------------------------------------------- vCloud Director tenant portal
  vcd(s) {
    const c = s.chrome || {};
    const icons1 = {'Data Centers': 'data-cluster', Applications: 'vmw-app', Networking: 'cloud-network', 'Content Hub': 'book',
      Libraries: 'library', Administration: 'cog', Monitor: 'computer'};
    const nav1 = ['Data Centers', 'Applications', 'Networking', 'Content Hub', 'Libraries', '|', 'Administration', 'Monitor'].map(t => t === '|'
      ? '<div class="div"></div>' : `<div class="lnk${t === c.nav1 ? ' on' : ''}">${this.ico(icons1[t])}${esc(t)}</div>`).join('');
    const nav2 = (c.nav2 || []).map(g => `<div class="grp">${this.ico(g.icon)}${esc(g.group)}${this.ico('angle', 'chev')}</div>`
      + g.items.map(t => `<div class="lnk${t === c.nav2_active ? ' on' : ''}">${esc(t)}</div>`).join('')).join('');
    const header = `<div class="vcd-header"><div class="vcd-brand"><span class="vcd-logo"></span><span class="vcd-title">${esc(c.brand || 'IAAS ACME CLOUD')}</span></div>`
      + `<span class="vcd-sep"></span><div class="vcd-org">${this.ico('organization')}<div class="vcd-org-name"><span>${esc(c.org || 'Organization')}</span>`
      + `<small>${esc(c.host || '')}</small></div>${this.ico('angle', 'ico-s')}</div><div class="vcd-actions"><span>${this.ico('search')}</span>`
      + `<span>${this.ico('help')}${this.ico('angle', 'ico-s')}</span><span><div class="vcd-user"><span>administrator</span><small>System Administrator</small></div>`
      + `${this.ico('angle', 'ico-s')}</span></div></div>`;
    const crumbs = (c.crumbs || []).length ? `<div class="vcd-crumbs">${c.crumbs.map((x, i) => i < c.crumbs.length - 1
      ? `<a>${esc(x)}</a>${this.ico('angle')}` : `<span>${esc(x)}</span>`).join('')}</div>` : '';
    const blocks = (s.blocks || []).map(b => this.vcdBlock(b, c)).join('');
    let main;
    if (c.entity) {
      const e = c.entity;
      const side = (c.sidenav || []).map(g => g.group
        ? `<div class="grp">${esc(g.group)}</div>` + g.items.map(t => `<div class="lnk${t === c.side_active ? ' on' : ''}">${esc(t)}${this.mk((c.side_marks || {})[t])}</div>`).join('')
        : g.items.map(t => `<div class="top${t === c.side_active ? ' on' : ''}">${esc(t)}${this.mk((c.side_marks || {})[t])}</div>`).join('')).join('');
      const tabs = (c.tabs || []).length ? `<div class="vcd-tabs">${c.tabs.map(t => `<span class="${t === c.tab ? 'on' : ''}">${esc(t)}</span>`).join('')}</div>` : '';
      main = `${crumbs}<div class="vcd-entity">${this.ico(e.icon)}<div><h3>${esc(e.name)}</h3>${e.status ? `<span class="status${e.off ? ' off' : ''}">${esc(e.status)}</span>` : ''}</div>`
        + `${(e.actions || []).map((a, i) => `<span class="vcd-act${i > 1 && e.actions.length > 3 ? '' : ''}">${esc(a)}</span>`).join('')}</div>`
        + `<div class="vcd-split"><nav class="vcd-sidenav">${side}</nav><div>${c.section ? `<h4 class="vcd-h4">${esc(c.section)}</h4>` : ''}${tabs}${blocks}</div></div>`;
    } else {
      main = `${crumbs}${c.h2 ? `<h2 class="vcd-h2">${esc(c.h2)}</h2>` : ''}${blocks}`;
    }
    const recent = c.recent || [];
    const rt = `<div class="vcd-recent"><div class="rt-title">Recent Tasks <span>${this.ico('angle')}</span></div>`
      + this.dg({columns: ['Task', 'Status', 'Type', 'Initiator', 'Start Time', 'Completion Time'], rows: recent.slice(0, 3), marks: {}, empty: 'No recent tasks', link_col: 0}).replace(/<div class="dg-pad"><\/div>/, '').replace(/<div class="dg-foot">[\s\S]*<\/div><\/div>$/, '</div>') + '</div>';
    return `${header}<div class="vcd-body"><nav class="vcd-nav1">${nav1}<span class="vcd-collapse">«</span></nav><div class="vcd-page">`
      + `<div class="vcd-topbar"><a>${this.ico('angle', 'ico-s')} All Virtual data centers</a>Data center:<b>${esc(c.vdc || '')}</b></div>`
      + `<div class="vcd-cols"><nav class="vcd-nav2">${nav2}<span class="vcd-collapse">«</span></nav><main class="vcd-content">${main}</main></div>${rt}</div></div>`;
  },
  vcdBlock(b, c) {
    const toolbar = t => (t || []).length ? `<div class="vcd-toolbar">${t.map(x => `<span class="vcd-btn${x.disabled ? ' dis' : ''}">${esc(x.label)}${this.mk(x.mark)}</span>`).join('')}</div>` : '';
    if (b.type === 'grid') return toolbar(b.toolbar) + this.dg(b);
    if (b.type === 'props') {
      const title = b.title && b.title !== c.section ? `<div class="vcd-section">${esc(b.title)}</div>` : '';
      return title + (b.edit ? toolbar([{label: 'EDIT'}]) : '') + `<div class="sv flat">${(b.items || []).map(i =>
        `<div class="sv-row${this.hl(i.mark)}"><div>${esc(i.label)}</div><div>${esc(i.value)}${this.mk(i.mark)}</div></div>`).join('')}</div>`;
    }
    if (b.type === 'stack') return toolbar(b.toolbar) + `<div class="sv">${(b.blocks || []).map(blk => `<div class="sv-head">${this.ico('angle')}${esc(blk.head)}</div>`
      + blk.rows.map(r => `<div class="sv-row${this.hl(r[2])}"><div>${esc(r[0])}</div><div>${esc(r[1])}${this.mk(r[2])}</div></div>`).join('')).join('')}</div>`;
    if (b.type === 'cards') {
      const cards = (b.cards || []).map(x => `<div class="vcd-card${this.hl(x.mark)}"><div class="ch"><a>${esc(x.name)}</a>${this.mk(x.mark)}`
        + `<span class="st${x.on ? '' : ' off'}">${esc(x.status)}</span><a class="con">VM Console</a></div>`
        + `<dl>${(x.rows || []).map(([k, v]) => `<dt>${esc(k)}</dt><dd title="${esc(v)}">${esc(v)}</dd>`).join('')}</dl>`
        + `<div class="res">${(x.res || []).map(([k, v], i) => `<div>${this.ico(['cpu', 'storage', 'memory', 'network-globe'][i])}${esc(k)}<b>${esc(v)}</b></div>`).join('')}</div>`
        + '<div class="cf"><span>DETAILS</span><span>ACTIONS</span></div></div>').join('');
      return `<div class="vcd-findbar"><span>Find by:</span><span class="sel">Name</span></div><div class="vcd-toolbar"><span class="vcd-btn">NEW VM</span></div>`
        + `<p><b>${esc(String(b.count || '').split(' ')[0])}</b> ${esc(String(b.count || '').split(' ').slice(1).join(' '))}</p><div class="vcd-cards">${cards}</div>`;
    }
    return '';
  },
  // ---------------------------------------------------------------- Horizon of RHOSP (RCUE)
  HZ_ICON: {
    plus: '<svg class="hz-icon" viewBox="0 0 12 12"><path d="M5 1h2v4h4v2H7v4H5V7H1V5h4z"/></svg>',
    trash: '<svg class="hz-icon" viewBox="0 0 12 12"><path d="M4 0h4v1h3v2H1V1h3zM2 4h8l-.6 8H2.6z"/></svg>',
    cloud: '<svg class="hz-icon" viewBox="0 0 16 12"><path d="M4 11a4 4 0 0 1-.3-8A5 5 0 0 1 13 4.6 3.3 3.3 0 0 1 12.5 11H9V7.6l1.4 1.4 1-1L8 4.7 4.6 8l1 1L7 7.6V11z"/></svg>',
    user: '<svg viewBox="0 0 10 10"><circle cx="5" cy="3" r="2.4"/><path d="M0 10c0-3 2.2-4.4 5-4.4S10 7 10 10z"/></svg>',
  },
  horizon(s) {
    const c = s.chrome || {};
    const util = `<div class="hz-utility"><span class="hz-brand"><span class="hat"></span><b>Red Hat</b> OpenStack Platform</span>`
      + `<ul class="hz-tabs">${['Project', 'Admin', 'Identity'].map(t => `<li class="${t === c.dashboard ? 'on' : ''}">${t}</li>`).join('')}</ul>`
      + `<ul class="hz-right"><li>Project<span class="chev"></span></li><li>Help</li><li class="user">${this.HZ_ICON.user} ${esc(c.user || 'admin')}<span class="chev"></span></li></ul></div>`;
    const prim = `<div class="hz-primary">${(c.groups || []).map(g => `<span class="${g === c.group ? 'on' : ''}">${esc(g)}${g === c.group ? '' : '<span class="chev"></span>'}</span>`).join('')}</div>`;
    const pers = (c.panels || []).length ? `<div class="hz-persistent">${c.panels.map(p => `<span class="${p === c.panel ? 'on' : ''}">${esc(p)}</span>`).join('')}</div>` : '';
    const crumbs = `<ol class="hz-crumbs">${(c.crumbs || []).map((x, i, a) => `<li${i === a.length - 2 && c.detail ? ' class="lnk"' : ''}>${esc(x)}</li>`).join('')}</ol>`;
    const head = c.detail
      ? `<div class="hz-dhead"><span class="hz-h1">${esc(c.title || '')}</span>${c.detail_action ? this.hzSplit(c.detail_action, c.detail_mark) : ''}</div>`
      : `<h1 class="hz-h1">${esc(c.title || '')}</h1>`;
    const tabs = (c.tabs || []).length ? `<ul class="hz-navtabs">${c.tabs.map(t => `<li class="${t === c.tab ? 'on' : ''}">${esc(t)}</li>`).join('')}</ul>` : '';
    let limit = false;
    let first = true;
    const blocks = (s.blocks || []).map(b => {
      if (b.type === 'meters') {
        const h3 = limit ? '' : '<h3>Limit Summary</h3>';
        limit = true;
        return `<div class="hz-quota">${h3}<h4>${esc(b.title || '')}</h4><div class="hz-pies">${(b.items || []).map(i => this.pie(i)).join('')}</div></div>`;
      }
      if (b.type === 'props') {
        const top = first && (!b.title || b.title === 'Overview');
        first = false;
        return `<div class="hz-sec">${top ? '' : `<h4>${esc(b.title || '')}</h4><hr>`}<dl class="hz-dl">${(b.items || []).map(i =>
          `<dt title="${esc(i.label)}">${esc(i.label)}</dt><dd class="${this.hl(i.mark).trim()}">${this.hzText(i.value)}${this.mk(i.mark)}</dd>`).join('')}</dl></div>`;
      }
      if (b.type === 'grid') return this.hzTable(b);
      return '';
    }).join('');
    return `<div class="hz-header">${util}${prim}${pers}</div><div class="hz-content">${crumbs}${head}${tabs}${blocks}</div>`;
  },
  // Cell text: lines, **bold** parts (network names of the IP Address column).
  hzText(v) { return esc(v).replace(/\*\*(.+?)\*\*/g, '<b>$1</b>').replace(/\n/g, '<br>'); },
  hzSplit(label, mark, menu, danger) {
    const items = menu ? `<ul class="hz-menu">${menu.items.map(t => `<li class="${t === menu.active ? this.hl(menu.mark).trim() : ''}${/^Delete/.test(t) ? ' danger' : ''}">${esc(t)}${t === menu.active ? this.mk(menu.mark) : ''}</li>`).join('')}</ul>` : '';
    if (danger) return `<span class="hz-btn sm danger">${esc(label)}</span>`;
    return `<span class="hz-split"><span class="hz-btn sm">${esc(label)}${this.mk(mark)}</span><span class="hz-btn sm"><b class="caret" style="margin:0"></b></span>${items}</span>`;
  },
  pie(i) {
    const p = Math.max(0, Math.min(100, Number(i.pct) || 0));
    const full = p >= 100;
    const fill = full ? '#d9534f' : p >= 80 ? '#fdd835' : '#428bca';
    const a = (p / 100) * 2 * Math.PI;
    const x = 45 * Math.sin(a), y = -45 * Math.cos(a);
    const circle = 'M0,45A45,45 0 1,1 0,-45A45,45 0 1,1 0,45Z';
    const inner = full ? `<path d="${circle}" fill="${fill}"/>` : p <= 0 ? ''
      : `<path d="M0,-45A45,45 0 ${p > 50 ? 1 : 0},1 ${x.toFixed(3)},${y.toFixed(3)}L0,0Z" fill="${fill}"/>`;
    return `<div class="hz-pie${this.hl(i.mark)}"><svg viewBox="0 0 100 100"><g transform="translate(50,50)"><path d="${circle}" fill="#eee" stroke="#bbb" stroke-width="1"/>${inner}</g></svg>`
      + `<div class="t">${esc(i.label)}${this.mk(i.mark)}</div><div class="st">${esc(i.text)}</div></div>`;
  },
  hzTable(b) {
    const marks = b.marks || {};
    const n = b.total ?? b.rows.length;
    const icon = t => t.icon ? (this.HZ_ICON[t.icon] || `${esc(t.icon)} `) : '';
    const search = b.filter ? `<span class="hz-search"><span class="hz-btn">${esc(typeof b.filter === 'string' ? b.filter : 'Name =')}<b class="caret"></b></span>`
      + '<span class="hz-input"></span><span class="hz-btn">Filter</span></span>' : '';
    const acts = (b.toolbar || []).map(t => `<span class="hz-btn${t.style === 'danger' ? ' danger' : ''}${t.disabled ? ' dis' : ''}">${icon(t)}${esc(t.label)}`
      + `${t.caret ? '<b class="caret"></b>' : ''}${this.mk(t.mark)}</span>`).join('');
    const cols = b.columns.length + (b.select ? 1 : 0) + (b.row_action ? 1 : 0);
    const count = `Displaying ${n} item${n === 1 ? '' : 's'}`;
    const head = `<tr class="count"><th colspan="${cols}">${count}</th></tr><tr>${b.select ? '<th class="cb"><i></i></th>' : ''}${b.columns.map(c => `<th>${esc(c)}</th>`).join('')}${b.row_action ? '<th>Actions</th>' : ''}</tr>`;
    const link = b.link_col === undefined ? 0 : b.link_col;
    const menu = b.menu || null;
    const rows = b.rows.map((r, i) => {
      const m = marks[String(i)];
      const act = b.row_action ? `<td class="act">${this.hzSplit(b.row_action, null, menu && menu.row === i ? menu : null, b.row_action_danger)}</td>` : '';
      return `<tr class="${this.hl(m).trim()}">${b.select ? '<td class="cb"><i></i></td>' : ''}${r.map((c, j) =>
        `<td${/\S{26,}/.test(String(c)) ? ' class="brk"' : ''}>${j === link ? `<a>${this.hzText(c)}</a>` : this.hzText(c)}${j === link || (link < 0 && j === 0) ? this.mk(m) : ''}</td>`).join('')}${act}</tr>`;
    }).join('') || `<tr><td class="empty" colspan="${cols}">${esc(b.empty || 'No items to display.')}</td></tr>`;
    return `<table class="hz-table"><caption><span class="hz-actions">${search}${acts}</span></caption><thead>${head}</thead><tbody>${rows}</tbody>`
      + `<tfoot><tr><td colspan="${cols}">${count}</td></tr></tfoot></table>`;
  },
  // ---------------------------------------------------------------- vSphere Client
  TREE_ICON: {vcenter: 'computer', datacenter: 'data-cluster', cluster: 'cluster', host: 'host', vm: 'vm', pool: 'resource-pool',
    datastore: 'storage', folder: 'folder'},
  propsTable(b) {
    return (b.title ? `<h4 class="vcd-section">${esc(b.title)}</h4>` : '') + `<div class="sv flat">${(b.items || []).map(i =>
      `<div class="sv-row${this.hl(i.mark)}"><div>${esc(i.label)}</div><div>${esc(i.value)}${this.mk(i.mark)}</div></div>`).join('')}</div>`;
  },
  clBlock(b) {
    if (b.type === 'grid') return ((b.toolbar || []).length ? `<div class="cl-btns">${b.toolbar.map(t => `<span class="cl-btn${t.primary ? ' primary' : ''}">${esc(t.label)}${this.mk(t.mark)}</span>`).join('')}</div>` : '')
      + (b.title ? `<h4 class="vcd-section">${esc(b.title)}</h4>` : '') + this.dg(b, {filters: false});
    if (b.type === 'props') return this.propsTable(b);
    if (b.type === 'meters') return (b.items || []).map(i => `<div class="cl-meter" style="margin:0 0 10px;width:360px"><b>${esc(i.label)}</b>${this.mk(i.mark)} ${esc(i.text)}`
      + `<div class="cl-bar ${i.mark ? esc(i.mark.tone) : ''}"><span style="width:${Math.max(0, Math.min(100, Number(i.pct) || 0))}%"></span></div></div>`).join('');
    return '';
  },
  vsphere(s) {
    const c = s.chrome || {};
    const inv = [['hosts', 'host'], ['vms', 'vm'], ['storage', 'storage'], ['network', 'network-globe']];
    const tree = (c.tree || []).map(n => `<div class="cl-node${n.active ? ' on' : ''}" style="padding-left:${10 + (n.level || 0) * 16}px">`
      + `${this.ico(this.TREE_ICON[n.icon] || 'folder')}${esc(n.label)}${this.mk(n.mark)}</div>`).join('');
    const m = c.meter;
    const meter = m ? `<div class="cl-meter"><b>${esc(m.label)}</b> Free: ${esc(m.free)}${this.mk(m.mark)}<div class="cl-bar ${m.mark ? esc(m.mark.tone) : ''}">`
      + `<span style="width:${Math.max(0, Math.min(100, Number(m.pct) || 0))}%"></span></div>Used: ${esc(m.used)} · Capacity: ${esc(m.capacity)}</div>` : '';
    const body = (s.blocks || []).map(b => this.clBlock(b)).join('');
    const inner = c.side ? `<div class="cl-inner"><div class="cl-side">${c.side.map(g => `<div class="grp">${esc(g.group)}</div>`
      + g.items.map(t => `<div class="lnk${t === c.side_active ? ' on' : ''}">${esc(t)}</div>`).join('')).join('')}</div><div>${body}</div></div>` : body;
    return `<div class="cl-header"><span class="cl-brand"><span class="cl-logo"></span>vSphere Client</span><span class="cl-topnav"><span>Menu ▾</span></span>`
      + `<span class="cl-search">Search in all environments</span><span class="cl-right">administrator@vsphere.local ▾</span></div>`
      + `<div class="cl-layout"><aside class="cl-tree"><div class="cl-tree-tabs">${inv.map(([k, ic]) => `<span class="${k === c.inventory ? 'on' : ''}">${this.ico(ic)}</span>`).join('')}</div>${tree}</aside>`
      + `<main class="cl-main"><div class="cl-objhead">${this.ico(this.TREE_ICON[c.icon] || 'folder')}<h2>${esc(c.title || '')}</h2><span class="cl-actions">ACTIONS ▾</span>${meter}</div>`
      + `<div class="cl-tabs">${(c.tabs || []).map(t => `<span class="${t === c.tab ? 'on' : ''}">${esc(t)}</span>`).join('')}</div>${inner}</main></div>`
      + '<div class="cl-tasks"><span class="on">Recent Tasks</span><span>Alarms</span></div>';
  },
  // ---------------------------------------------------------------- NSX Manager
  nsx(s) {
    const c = s.chrome || {};
    const nav = (c.side || []).map(g => `<div class="grp">${esc(g.group)}</div>` + g.items.map(t => `<div class="lnk${t === c.side_active ? ' on' : ''}">${esc(t)}</div>`).join('')).join('');
    return `<div class="cl-header"><span class="cl-brand"><span class="cl-logo"></span>NSX</span><span class="cl-topnav">${(c.top || []).map(t => `<span class="${t === c.top_active ? 'on' : ''}">${esc(t)}</span>`).join('')}</span>`
      + `<span class="cl-right">admin ▾</span></div><div class="cl-layout"><nav class="cl-nav">${nav}</nav><main class="cl-main"><h1 class="cl-h1">${esc(c.title || '')}</h1>`
      + `<div>${(c.filters || []).map(([k, v]) => `<span class="cl-filter">${esc(k)}: <b>${esc(v)}</b> ▾</span>`).join('')}</div>${(s.blocks || []).map(b => this.clBlock(b)).join('')}</main></div>`;
  },
  // ---------------------------------------------------------------- ONTAP System Manager
  ontap(s) {
    const c = s.chrome || {};
    const nav = (c.side || []).map(g => (g.group ? `<div class="grp">${esc(g.group)}</div>` : '') + g.items.map(t => {
      const on = c.side_active === t || c.side_active === `${g.group}/${t}`;
      return `<div class="${g.group ? 'lnk' : 'top'}${on ? ' on' : ''}">${esc(t)}</div>`;
    }).join('')).join('');
    const body = (s.blocks || []).map(b => b.type === 'grid' ? `<div class="sm-card">${b.title ? `<h4>${esc(b.title)}</h4>` : ''}`
      + `${(b.toolbar || []).map(t => `<span class="sm-btn">${esc(t.label)}</span>`).join('')}${this.dg(b, {filters: false, status: true})}</div>` : this.clBlock(b)).join('');
    return `<div class="sm-header"><span class="sm-brand"><b>ONTAP</b> System Manager</span><span class="sm-cluster">${esc(c.cluster || '')}</span>`
      + `<span class="cl-right">admin ▾</span></div><div class="sm-layout"><nav class="sm-nav">${nav}</nav><main class="sm-main"><h1 class="sm-h1">${esc(c.title || '')}</h1>${body}</main></div>`;
  },
};

/* =========================================================================
   Start
   ========================================================================= */
document.addEventListener('DOMContentLoaded', async () => {
  UserMenu.init();
  Nav.init();
  Catalog.init();
  FixDialog.init();
  Screens.init();
  Hosts.init();
  document.addEventListener('click', e => { const b = e.target.closest('dialog [data-close]'); if (b) b.closest('dialog').close(); });
  Launch.init();
  TemplateForm.init();
  Bmcs.init();
  Runs.init();
  RunPage.init();
  RunningFixes.init();
  Router.init();
  if (!location.hash) history.replaceState(null, '', '#/checks');
  const status = await Session.refresh();
  if (!status) return toast('Cannot reach the portal server.');
  if (status.user) {
    Router.go();
    if (Session.allowed) Catalog.load().catch(() => {});   // the menu of products, on every page
    RunningFixes.load();
  }
  // Keep the portal session alive while this page is used.
  let active = false;
  ['click', 'keydown'].forEach(ev => document.addEventListener(ev, () => { active = true; }, {passive: true}));
  setInterval(async () => {
    if (!active) return;
    active = false;
    try {
      const res = await fetch('/api/keepalive', {method: 'POST'});
      const data = await res.json();
      if (!data.user) window.PortalLauncher?.signIn();
    } catch (e) { /* server not reachable for a moment */ }
  }, 120000);
});

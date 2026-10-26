'use strict';
/* ONTAP Restore module of the Ops Portal (/ontap/). PatternFly look like AWX: restore wizard, job page, job list,
   approvals. Sign-in, Users and Credentials belong to the portal (/); the masthead has the portal application launcher
   (/static/switcher.js). UI specification: docs/UI-SPEC.md */

/* =========================================================================
   Utilities
   ========================================================================= */
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
const qs = params => Object.entries(params).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v ?? '')}`).join('&');
const icon = name => `<svg class="pf-icon" aria-hidden="true"><use href="#i-${name}"></use></svg>`;
const sleep = ms => new Promise(r => setTimeout(r, ms));

function storage(area) {
  return {
    get(key) { try { return window[area].getItem(key); } catch (e) { return null; } },
    set(key, value) { try { window[area].setItem(key, value); } catch (e) { /* storage not available */ } },
  };
}
const tabStore = storage('sessionStorage');

// Every request of this module goes to /ontap/... (the portal itself serves /api/login, /api/logout and /api/admin/...).
const BASE = '/ontap';
const BASE_TITLE = document.title;
const UI_VERSION = document.querySelector('meta[name="ui-version"]')?.content || '';
const SITE_COLORS = ['#2b9af3', '#3e8635', '#8476d1', '#ec7a08', '#c9190b', '#009596'];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const PROJECT = /^[0-9A-Za-z_-]{8,64}$/;
const VOLUME_NAME = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const INSTANCE_NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$/;
const PLAN_TTL = 25 * 60 * 1000;   // below the server limit (30 minutes)

function bytes(n) {
  const v = Number(n);
  if (!Number.isFinite(v)) return '-';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
  const i = Math.min(units.length - 1, Math.floor(Math.log(Math.max(v, 1)) / Math.log(1024)));
  return `${(v / 1024 ** i).toFixed(i < 3 ? 0 : 1)} ${units[i]}`;
}
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
function duration(seconds) {
  const s = Math.max(0, Math.round(seconds));
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, '0')}s`;
}
// PatternFly description list; rows with a falsy value are skipped.
function dl(rows, horizontal = true) {
  const items = rows.filter(Boolean).map(([k, v]) => horizontal ? `<dt>${esc(k)}</dt><dd>${v}</dd>` : `<div class="pf-dl__group"><dt>${esc(k)}</dt><dd>${v}</dd></div>`);
  return `<dl class="pf-dl${horizontal ? ' pf-m-horizontal' : ''}">${items.join('')}</dl>`;
}
function alertBox(kind, title, body = '') {
  const name = {success: 'check-circle', danger: 'x-circle', warning: 'alert', info: 'info'}[kind];
  return `<div class="pf-alert pf-m-${kind}"${kind === 'danger' ? ' role="alert"' : ''}>${icon(name)}<div class="pf-alert__title">${title}</div>`
    + (body ? `<div class="pf-alert__body">${body}</div>` : '') + '</div>';
}
function copyable(text) {
  return `<span class="pf-copy"><span class="mono">${esc(text)}</span><button type="button" class="pf-btn pf-m-plain pf-m-small" data-copy="${esc(text)}" aria-label="Copy ${esc(text)}">${icon('copy')}</button></span>`;
}
document.addEventListener('click', e => {
  const btn = e.target.closest('[data-copy]');
  if (!btn) return;
  navigator.clipboard?.writeText(btn.dataset.copy).then(() => toast('Copied to clipboard', 'success'), () => toast('Copy failed'));
});

const STATUS = {
  success: ['Successful', 'green', 'check-circle'], failed: ['Failed', 'red', 'x-circle'],
  running: ['Running', 'blue', 'in-progress'], unknown: ['Unknown', 'gold', 'alert'],
};
const statusLabel = s => { const [text, color, ic] = STATUS[s] || [s, '', 'info']; return `<span class="pf-label pf-m-${color}">${icon(ic)}${esc(text)}</span>`; };
// Restore group and its volumes: also partial (all restored, an action after it failed), waiting and skipped (not started).
const GROUP_STATUS = {...STATUS, partial: ['Successful, action failed', 'gold', 'alert'], waiting: ['Waiting', '', 'circle'],
  skipped: ['Not started', '', 'circle']};
const groupStatusLabel = s => { const [text, color, ic] = GROUP_STATUS[s] || [s, '', 'info']; return `<span class="pf-label${color ? ` pf-m-${color}` : ''}">${icon(ic)}${esc(text)}</span>`; };

/* =========================================================================
   Requests and notifications
   ========================================================================= */
async function api(url, body, method) {
  const init = {method: method || (body === undefined ? 'GET' : 'POST')};
  if (body !== undefined) {
    init.headers = {'Content-Type': 'application/json'};
    init.body = JSON.stringify(body);
  }
  const res = await fetch(url, init);
  let data;
  try { data = await res.json(); } catch (e) { throw new Error(`Server Web UI error (HTTP ${res.status})`); }
  // The session ended (expired, signed out elsewhere, or access removed): sign in on the portal, then back here.
  if (res.status === 401) Session.expired(data.session);
  // No longer allowed to use this module, or no longer an administrator: refresh the page state and the menu.
  if (res.status === 403) Session.refresh();
  if (!data.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

// A file from the server (CSV export). Errors come back as JSON, like the API.
async function downloadFile(url, fallbackName) {
  const res = await fetch(url);
  if (!res.ok) {
    let data = {};
    try { data = await res.json(); } catch (e) { /* not JSON */ }
    if (res.status === 401) Session.expired(data.session);
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

// PatternFly toast. With action {label, fn}: it stays until it is closed or its action is clicked.
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

// Async action with a button in a loading state; an error is shown as a toast.
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
    Wizard.render();
  }
}

// Confirmation for destructive actions (PatternFly modal). Resolves true when the action button is clicked.
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
   Site, session, sign-in
   ========================================================================= */
const ROLE_LABELS = {admin: 'Administrator', operator: 'Operator'};
// How the current user signed in: an AD or a local portal account, with or without Duo.
function signedInWith(user) {
  const account = user.source === 'local' ? 'a local account' : 'Active Directory';
  return {sso: 'Signed in with Duo SSO', duo: `Signed in with ${account} and Duo`, none: `Signed in with ${account}`,
    bypassed: `Signed in with ${account} (Duo was unreachable and bypassed)`}[user.mfa] || '';
}

const Site = {
  current: '',
  list: [],
  locked: false,
  set(status) { this.list = (status.sites || []).map((x, i) => ({...x, color: SITE_COLORS[i % SITE_COLORS.length]})); },
  info(name) { return this.list.find(x => x.name === name) || {name, host: '', configured: false, color: SITE_COLORS[0]}; },
  // Every site can be selected. ONTAP is reached with the site's service account (Administration -> Credentials);
  // a site without one is marked here, and the Restore page explains what is missing.
  render() {
    $('#siteSwitch').innerHTML = this.list.map(x => `<label title="${esc(x.configured ? `ONTAP ${x.host}` : `No service account for ${x.name}`)}">`
      + `<input type="radio" name="site" value="${esc(x.name)}"${x.name === this.current ? ' checked' : ''}>`
      + `<span><span class="site-dot" style="--site-color:${x.color}"></span>${esc(x.name)}`
      + (x.configured ? '' : '<svg class="pf-icon site-warn" aria-hidden="true"><use href="#i-alert"></use></svg><span class="sr-only">(no service account)</span>')
      + '</span></label>').join('');
    $('#navSites').innerHTML = this.list.map(x => `<div><span class="site-dot" style="--site-color:${x.color}"></span>${esc(x.name)}`
      + `<span class="mono">${esc(x.host)}</span>${x.configured ? '' : '<span class="pf-label pf-m-gold pf-m-compact">No service account</span>'}</div>`).join('');
    this.lock(this.locked);
  },
  // While the check (plan) is running, the site cannot be changed.
  lock(locked) {
    this.locked = locked;
    $('#siteSwitch').classList.toggle('is-locked', locked);
    $$('#siteSwitch input').forEach(i => { i.disabled = locked; });
  },
  activate(name) {
    this.current = name;
    if (name) tabStore.set('ontap_site', name);
    document.title = name ? `[${name}] ${BASE_TITLE}` : BASE_TITLE;
    $$('.site-name-current').forEach(el => { el.textContent = name || '-'; });
  },
};

const Session = {
  user: null,              // {username, display_name, role, mfa, modules} of the signed-in account
  allowed: null,           // the account may use ONTAP Restore (portal Users page; administrators always)
  outdated: false,
  // The server already runs a new Web UI version (for example after install.sh), but this page is still the old one.
  checkVersion(status) {
    if (this.outdated || !status.ui_version || !UI_VERSION || status.ui_version === UI_VERSION) return;
    this.outdated = true;
    toast('A new version of this app is available. Reload the page; unsaved input will be lost.', 'info',
      {label: 'Reload', fn: () => location.reload()});
  },
  isAdmin() { return this.user?.role === 'admin'; },
  // Every session answer (/api/session, or the session part of a 401) passes through here.
  update(status) {
    this.checkVersion(status);
    if (!status.user) return this.signIn();
    if (!$('#appView').hidden) this.apply(status);
  },
  // User menu, role, access to this module, and sites (with or without a service account) from a session answer.
  apply(status) {
    const wasAllowed = this.allowed;
    this.user = status.user;
    this.allowed = Boolean(status.allowed);
    if (wasAllowed === false && this.allowed) return location.reload();   // access given since the page was opened
    Site.set(status);
    const names = Site.list.map(x => x.name);
    Site.activate([Site.current, tabStore.get('ontap_site')].find(n => n && names.includes(n))
      || (Site.list.find(x => x.configured) || Site.list[0])?.name || '');
    Site.render();
    UserMenu.render(this.user, status.client);
    $$('.admin-only').forEach(el => { el.hidden = !this.isAdmin(); });
    // Signed in, but the account may not use this module: only the "No access" page (no navigation, site, approvals).
    if (!this.allowed) {
      $('#appView').classList.add('is-nav-collapsed');
      $('#appView').classList.remove('is-nav-open');
      ['#navToggle', '#siteSwitch', '#notifyBtn'].forEach(sel => { $(sel).hidden = true; });
    }
    Wizard.render();
    if (wasAllowed && !this.allowed) Router.go();
  },
  // No (more) portal session: the portal sign-in opens, and comes back to this page afterwards.
  signIn() {
    UserMenu.close();
    $('#appView').hidden = true;
    document.title = BASE_TITLE;
    PortalLauncher.signIn();
  },
  enter(status) {
    // Another account signed in on this page after the previous session ended: start with a clean page.
    if (this.user && this.user.username !== status.user.username) return location.reload();
    this.checkVersion(status);
    $('#appView').hidden = false;
    this.apply(status);
    Router.go();
    if (this.allowed) Notify.start();
  },
  expired(status) {
    if (status) this.update(status);
    else this.refresh();
  },
  async refresh() {
    try {
      this.update(await (await fetch(`${BASE}/api/session`)).json());
    } catch (e) { /* server not reachable: keep the page as it is */ }
  },
  async logout() {
    UserMenu.close();
    try { await fetch('/api/logout', {method: 'POST'}); } catch (e) { /* the session still ends when it expires */ }
    // The portal home: nothing of this session stays on the page, and it opens on the sign-in form.
    location.assign('/');
  },
};

// User menu in the masthead: name, role, how the session was signed in, and Sign out.
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
  // client: the address the portal sees for this browser (logged with every action), e.g. "10.252.2.3" or
  // "172.26.0.100 (RDP 10.252.2.3, INTRANET\\jdoe)" for a browser on the bastion itself.
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
   Navigation (hash): #/restore, #/jobs, #/jobs/<id>, #/groups/<id>, #/approvals (old #/history links go to #/jobs;
   #/users and #/credentials are pages of the portal)
   ========================================================================= */
const PORTAL_PAGES = ['users', 'credentials'];
const Router = {
  init() {
    window.addEventListener('hashchange', () => this.go());
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
    const [, section = 'restore', id] = (location.hash.match(/^#\/([a-z]+)(?:\/(\d+))?/) || []);
    if (section === 'history') return location.replace(`#/jobs${id ? `/${id}` : ''}`);   // link from an old version
    if (PORTAL_PAGES.includes(section)) return location.replace(`/#/${section}`);   // Administration of the portal
    const page = !Session.allowed ? 'noaccess' : section === 'jobs' ? (id ? 'job' : 'jobs') : section === 'groups' && id ? 'group'
      : section === 'approvals' ? 'approvals' : 'restore';
    $$('[data-page]').forEach(el => { el.hidden = el.dataset.page !== page; });
    $$('.pf-nav__link').forEach(a => a.classList.toggle('is-current', a.dataset.route === (['job', 'group'].includes(page) ? 'jobs' : page)));
    if (page !== 'job') JobPage.stop();
    if (page !== 'group') GroupPage.stop();
    Notify.refresh();
    if (page === 'restore') Wizard.render();
    if (page === 'jobs') run(null, () => History.load());
    if (page === 'job') JobPage.open(Number(id));
    if (page === 'group') GroupPage.open(Number(id));
    if (page === 'approvals') {
      $$('#toasts .pf-alert.is-approvals').forEach(el => el.remove());
      run(null, () => Approvals.load());
    }
    window.scrollTo(0, 0);
  },
};

/* =========================================================================
   Restore wizard: Volume -> Snapshot -> Target project -> Review
   ========================================================================= */
const Wizard = {
  steps: ['Volume', 'Snapshot', 'Target project', 'Review'],
  step: 0,
  data: null,            // result of /api/snapshots (LUN, FlexVol, snapshots)
  os: null,              // result of volume_info (OpenStack volume, instance, volume role): {status, result, error}
  osToken: 0,
  snapshot: '',
  filter: '',
  plan: null,            // {jobId, key, result, at, name, pool, action, attachId, instanceName}
  planRunning: false,
  // More volumes of the same instance, restored with it (a group): [{id, device, role, status, data, error}].
  // Then plans holds the plan of every volume ({volumeId, jobId, key, result, at, name, pool}) and plan the choices of the group.
  extra: [],
  plans: null,

  init() {
    // The wizard navigation is built once; render() only changes the state so the keyboard focus is not lost.
    $('#wizNav').innerHTML = this.steps.map((name, i) => `<li><button type="button" class="pf-wizard__nav-link" data-go="${i}">${esc(name)}</button></li>`).join('');
    $('#wizNav').addEventListener('click', e => { const b = e.target.closest('button[data-go]'); if (b && !b.disabled) this.go(Number(b.dataset.go)); });
    $('#volumeForm').addEventListener('submit', e => { e.preventDefault(); if (!this.blocked()) run($('#findBtn'), () => this.find()); });
    $('#volumeId').addEventListener('input', () => {
      if (this.data && this.volumeId() !== this.data.volume_id) this.reset();
      this.volumeError('');
      this.render();
    });
    $('#snapFilter').addEventListener('change', e => { this.filter = e.target.value; this.renderSnapshots(); });
    $('#snapList').addEventListener('change', e => this.select(e.target.value));
    $('#snapList').addEventListener('click', e => {
      const row = e.target.closest('tr[data-snap]');
      if (row && e.target.tagName !== 'INPUT') this.select(row.dataset.snap);
    });
    $('#projectId').addEventListener('input', () => this.render());
    $('#osInfo').addEventListener('change', e => { if (e.target.name === 'groupVol') this.toggleExtra(e.target.value, e.target.checked); });
    $('#reviewBody').addEventListener('input', e => {
      if (e.target.id === 'newName') this.nameChanged();
      if (e.target.dataset.nameFor !== undefined) this.groupNameChanged(Number(e.target.dataset.nameFor));
      if (e.target.id === 'attachId') this.attachChanged();
      if (e.target.id === 'instanceName') this.instanceNameChanged();
      this.render();
    });
    $('#reviewBody').addEventListener('change', e => {
      if (e.target.id === 'scheduleDelete') this.plan.scheduleDelete = e.target.checked;
      if (e.target.name === 'pool') this.poolChanged(e.target.value);
      if (e.target.name?.startsWith('pool-')) this.poolChanged(e.target.value, Number(e.target.name.slice(5)));
      if (e.target.id === 'targetType') return this.typeChanged(e.target.value);
      if (e.target.dataset.typeFor !== undefined) return this.typeChanged(e.target.value, Number(e.target.dataset.typeFor));
      if (e.target.dataset.portNet !== undefined) return this.portNetChanged(Number(e.target.dataset.portNet), e.target.value);
      if (e.target.dataset.portSubnet !== undefined) return this.portSubnetChanged(Number(e.target.dataset.portSubnet), e.target.value);
      if (e.target.name === 'afterAction') this.actionChanged(e.target.value);
      this.render();
    });
    $('#reviewBody').addEventListener('click', e => {
      if (e.target.closest('#recheckBtn')) return this.startPlan();
      const row = e.target.closest('tr[data-pool]');
      if (row && e.target.tagName !== 'INPUT' && !row.classList.contains('is-disabled')) {
        this.poolChanged(row.dataset.pool, row.dataset.plan === undefined ? null : Number(row.dataset.plan));
        this.render();
      }
    });
    $('#wizNext').addEventListener('click', () => this.next());
    $('#wizBack').addEventListener('click', () => this.go(this.step - 1));
    $('#wizCancel').addEventListener('click', () => this.clear());
    $('#siteSwitch').addEventListener('change', e => {
      if (e.target.name !== 'site') return;
      this.switchSite(e.target.value);
      // An administrator may have set the service account since this page was loaded.
      if (!Site.info(e.target.value).configured) Session.refresh();
    });
  },
  // No ONTAP service account for the selected site: every wizard action is blocked (the server would refuse it too).
  blocked() { return !Site.info(Site.current).configured; },
  renderSiteWarning() {
    let title = '';
    if (!Site.list.length) title = 'No sites are configured. Add them to sites.yml on the server.';
    else if (this.blocked()) {
      title = `No service account for ${esc(Site.current)}. `
        + (Session.isAdmin() ? '<a href="/#/credentials">Set it in Credentials.</a>' : 'Ask an administrator to set it in Administration → Credentials.');
    }
    const box = $('#siteWarning');
    if (box.dataset.title !== title) {   // only when it changes: render() also runs on every keystroke
      box.dataset.title = title;
      box.innerHTML = title ? alertBox('warning', title) : '';
    }
  },
  volumeId() { return $('#volumeId').value.trim().toLowerCase(); },
  projectId() { return $('#projectId').value.trim(); },
  planKey() { return [Site.current, this.data?.volume_id, this.snapshot, this.projectId(), this.extra.map(x => x.id).join(',')].join('|'); },
  groupMode() { return this.extra.length > 0; },
  // The search result, snapshots and plan are dropped; the volume and project inputs are not changed.
  reset() {
    this.data = null;
    this.os = null;
    this.osToken += 1;
    this.snapshot = '';
    this.filter = '';
    this.plan = null;
    this.plans = null;
    this.extra = [];
    this.step = 0;
    $('#volumeInfo').innerHTML = '';
    $('#osInfo').innerHTML = '';
    $('#snapFilter').innerHTML = '';
    $('#snapList').innerHTML = '';
    $('#reviewBody').innerHTML = '';
    this.render();
  },
  clear() {
    $('#volumeId').value = '';
    $('#projectId').value = '';
    this.volumeError('');
    this.reset();
    $('#volumeId').focus();
  },
  switchSite(name) {
    Site.activate(name);
    Site.render();
    this.clear();
  },
  volumeError(message) {
    $('#volumeId').classList.toggle('is-invalid', Boolean(message));
    $('#volumeHelp').className = `pf-helper-text${message ? ' pf-m-error' : ''}`;
    $('#volumeHelp').textContent = message || 'Copy it from the ID column of openstack volume list, or from Horizon.';
  },

  // What each step needs before the user can continue.
  valid(step) {
    const d = this.data;
    if (step === 0) return Boolean(d && d.flexvol.state === 'online' && !d.restore_path_exists && d.snapshots.length && this.spaceOk()
      && this.extra.every(x => !this.extraProblem(x)));
    if (step === 1) return Boolean(this.snapshot);
    if (step === 2) return !this.projectId() || PROJECT.test(this.projectId());
    if (step === 3 && this.groupMode()) {
      const plans = this.plans || [];
      return Boolean(plans.length && plans.every(pl => pl.result.ready && pl.key === this.planKey() && VOLUME_NAME.test(pl.name) && this.selectedPool(pl))
        && new Set(plans.map(pl => pl.name)).size === plans.length && !this.actionProblem() && $('#reviewAck')?.checked);
    }
    if (step === 3) {
      const r = this.plan?.result;
      const name = $('#newName')?.value.trim() || '';
      return Boolean(r && r.ready && this.plan.key === this.planKey() && VOLUME_NAME.test(name) && this.selectedPool()
        && !this.actionProblem() && $('#reviewAck')?.checked);
    }
    return false;
  },
  // Same as the "space" condition in the playbook: the free space of the FlexVol must fit the LUN data (used).
  spaceOk() { return Number(this.data.flexvol.available) >= Number(this.data.lun.used); },
  reachable(step) { return [...Array(step).keys()].every(i => this.valid(i)); },
  go(step) {
    if (step < 0 || step > 3 || !this.reachable(step) || this.planRunning) return;
    this.step = step;
    if (step === 3) this.review();
    this.render();
    $('.pf-wizard__body').scrollIntoView({block: 'nearest'});
  },
  next() {
    if (this.blocked() || !this.valid(this.step)) return;
    if (this.step < 3) return this.go(this.step + 1);
    // The server refuses a plan older than 30 minutes: check again first so the data is current.
    if (Date.now() - this.plan.at > PLAN_TTL) {
      toast('The check is older than 25 minutes; running it again first.', 'info');
      return this.startPlan();
    }
    run($('#wizNext'), () => this.launch());
  },
  render() {
    const blocked = this.blocked();
    this.renderSiteWarning();
    $$('#wizNav button').forEach((b, i) => {
      b.classList.toggle('is-current', i === this.step);
      b.classList.toggle('is-done', i < this.step && this.valid(i));
      b.disabled = !this.reachable(i) || this.planRunning || blocked;
      if (i === this.step) b.setAttribute('aria-current', 'step'); else b.removeAttribute('aria-current');
    });
    $$('[data-step]').forEach(el => { el.hidden = Number(el.dataset.step) !== this.step; });
    $('#findBtn').disabled = blocked || $('#findBtn').classList.contains('is-loading');
    $('#wizNext').textContent = this.step === 3 ? (this.groupMode() ? `Launch restore of ${this.extra.length + 1} volumes` : 'Launch restore') : 'Next';
    $('#wizNext').disabled = !this.valid(this.step) || this.planRunning || blocked;
    $('#wizBack').disabled = this.step === 0 || this.planRunning;
    $('#wizCancel').disabled = this.planRunning;
    const pid = this.projectId(), badProject = Boolean(pid) && !PROJECT.test(pid);
    $('#projectId').classList.toggle('is-invalid', badProject);
    $('#projectHelp').className = `pf-helper-text${badProject ? ' pf-m-error' : ''}`;
    $('#projectHelp').textContent = badProject ? 'Project ID: letters, digits, - and _ only (8-64 characters).' : 'Leave empty to use the original volume\'s project.';
    $('#wizHint').textContent = this.hint();
    Site.lock(this.planRunning);
    window.PortalGuide?.refresh();   // the guide of the Review step, or the one of the other steps
  },
  // What the user does next, under the wizard (also shown by the guide)
  hint() {
    const r = this.plan?.result;
    const chosen = this.data?.snapshots.find(s => s.name === this.snapshot);
    const group = this.groupMode() && this.plans;
    return [
      !this.data ? 'Find the volume LUN first.' : this.extra.some(x => x.status === 'loading') ? 'Reading the other volumes…'
        : this.extra.some(x => this.extraProblem(x)) ? 'Untick or fix the volumes marked in red.' : '',
      chosen ? `Selected: ${chosen.local_time}` : 'Select a snapshot.',
      '',
      this.planRunning ? 'Checking prerequisites…' : group ? this.groupHint() : !r ? '' : !r.ready ? 'Fix the failed prerequisites, then check again.'
        : !this.selectedPool() ? 'Select a Cinder pool.' : this.actionProblem() || 'Review, then tick the confirmation.',
    ][this.step];
  },

  // ---------- step 1: volume ----------
  async find() {
    if (this.blocked()) return;
    const id = this.volumeId();
    if (!UUID.test(id)) {
      this.volumeError('The volume ID must be an OpenStack UUID, for example a80a1a07-06b8-489b-a984-b046981f68b9');
      $('#volumeId').focus();
      return;
    }
    this.reset();
    // The requested flow: volume show first, then its instance. It runs in the background (through the management host
    // -> director), at the same time as reading the LUN and snapshots from ONTAP.
    this.loadOpenStack(id);
    $('#volumeInfo').innerHTML = '<p class="pf-text-secondary pf-mt-md" id="findStatus"><span class="pf-spinner"></span> Reading the LUN and snapshots from ONTAP…</p>';
    // LUN volume-<ID> not found: the server checks the name_id in OpenStack (via the management host), a few seconds.
    const slow = setTimeout(() => {
      const el = $('#findStatus');
      if (el) el.innerHTML = '<span class="pf-spinner"></span> LUN <span class="mono">volume-&lt;ID&gt;</span> not found; checking the volume name_id in OpenStack (10–30 seconds)…';
    }, 2500);
    try {
      const data = await api(`${BASE}/api/snapshots?${qs({site: Site.current, volume_id: id})}`);
      this.data = {...data, volume_id: id, site: Site.current};
    } catch (e) {
      $('#volumeInfo').innerHTML = `<div class="pf-mt-md">${alertBox('danger', 'Cannot use this LUN', esc(e.message))}</div>`;
      return;
    } finally {
      clearTimeout(slow);
    }
    this.renderInfo();
    this.renderFilter();
    this.renderSnapshots();
  },
  renderInfo() { $('#volumeInfo').innerHTML = this.infoHtml(this.data); },
  // What ONTAP has for the volume: its LUN, FlexVol and snapshots (also drawn by the guide of this page)
  infoHtml(data) {
    const {lun, flexvol} = data;
    const alerts = [];
    if (data.restore_path_exists) {
      alerts.push(alertBox('warning', 'A LUN from an earlier restore still exists',
        `<span class="mono">${esc(data.restore_path)}</span> already exists. Delete or manage that LUN before restoring this volume again.`));
    }
    if (flexvol.state !== 'online') alerts.push(alertBox('danger', `FlexVol ${esc(flexvol.name)} is ${esc(flexvol.state)}`));
    if (Number(flexvol.available) < Number(lun.used)) {
      alerts.push(alertBox('danger', 'Not enough free space in the FlexVol',
        `Free ${bytes(flexvol.available)}, LUN data ${bytes(lun.used)}. Add capacity to FlexVol ${esc(flexvol.name)}, then find the LUN again.`));
    }
    if (!data.snapshots.length) {
      alerts.push(alertBox('warning', `FlexVol ${esc(flexvol.name)} has no snapshots`,
        'Volumes in this Cinder pool cannot be restored from ONTAP snapshots. Check the snapshot policy of the FlexVol.'));
    }
    const viaNameId = data.name_id ? alertBox('info', 'LUN found by name_id',
      `LUN <span class="mono">volume-${esc(data.volume_id)}</span> does not exist in ONTAP. According to <span class="mono">openstack volume show</span>, `
      + `this volume uses name_id <span class="mono">${esc(data.name_id)}</span> (usually after a migrate or retype), `
      + 'so that LUN is used for the restore.') : '';
    return `<div class="pf-mt-md">${alerts.length ? alerts.join('') : alertBox('success', 'LUN found')}${viaNameId}</div>`
      + '<h3 class="review-section pf-mt-lg">ONTAP</h3>' + dl([
        ['LUN', `<span class="mono">${esc(lun.name)}</span>`],
        data.name_id && ['name_id', `<span class="mono">${esc(data.name_id)}</span>`],
        ['SVM', esc(lun.svm)],
        ['FlexVol', `${esc(lun.flexvol)} <span class="pf-text-secondary">(${esc(flexvol.state)})</span>`],
        ['LUN size', `${bytes(lun.size)} · ${bytes(lun.used)} used`],
        ['FlexVol free', `${bytes(flexvol.available)} of ${bytes(flexvol.size)}`],
        ['Snapshots', `${data.snapshots.length} available`],
      ]);
  },
  // volume show -> instance (job volume_info.yml with_instance, read-only)
  async loadOpenStack(id) {
    const token = ++this.osToken;
    this.os = {status: 'running'};
    $('#osInfo').innerHTML = this.osHtml();
    try {
      const {job_id: jobId} = await api(`${BASE}/api/volume_info`, {site: Site.current, volume_id: id});
      let since = 0, data;
      for (;;) {
        data = await api(`${BASE}/api/jobs/${encodeURIComponent(jobId)}?since=${since}`);
        since = data.next;
        if (token !== this.osToken) return;
        if (data.task && $('#osStatus')) $('#osStatus').innerHTML = `<span class="pf-spinner"></span> ${esc(data.task)}…`;
        if (data.status !== 'running') break;
        await sleep(1000);
      }
      this.os = data.status === 'success' ? {status: 'success', result: data.result} : {status: 'failed', error: data.error};
    } catch (e) {
      if (token !== this.osToken) return;
      this.os = {status: 'failed', error: e.message};
    }
    this.renderOpenStack();
  },
  renderOpenStack() { $('#osInfo').innerHTML = this.osHtml(); },
  // What OpenStack has for the volume: the volume, its instance and the other disks of that instance (also drawn by the
  // guide of this page)
  osHtml() {
    if (!this.os || this.os.status === 'running') {
      return '<h3 class="review-section pf-mt-lg">OpenStack</h3><p class="pf-text-secondary" id="osStatus"><span class="pf-spinner"></span> '
        + 'Reading the volume and the instance it is attached to (flavor, network interfaces, volumes) from OpenStack…</p>';
    }
    if (this.os.status === 'failed') {
      return '<h3 class="review-section pf-mt-lg">OpenStack</h3>'
        + alertBox('warning', 'The OpenStack volume could not be read', `${esc(this.os.error)}<br>The Review step checks OpenStack again.`);
    }
    const {volume: v, instance, role, instance_error: instErr} = this.os.result;
    return '<h3 class="review-section pf-mt-lg">OpenStack volume</h3>' + dl([
      ['Volume', `${esc(v.name || '(no name)')} <span class="mono pf-text-secondary">${esc(v.id)}</span>`],
      ['Details', `${esc(v.size_gb)} GB · ${esc(v.status)} · type ${esc(v.type || '-')}${v.bootable ? ' · bootable' : ''}`],
      ['Cinder pool', `<span class="mono">${esc(v.host)}</span>`],
      ['Role', roleLabel(role)],
    ]) + (instErr ? `<div class="pf-mt-md">${alertBox('warning', 'The instance could not be read', esc(instErr))}</div>` : '')
      + (instance && instance.id ? instanceDetail(instance) : '') + `<div id="groupPick">${this.groupPicker()}</div>`;
  },

  // ---- More volumes of the same instance (group): same snapshot time, same project, one job per volume ----
  groupPicker() {
    const inst = this.os?.status === 'success' ? this.os.result.instance : null;
    const others = (inst?.volumes || []).filter(v => !v.this && UUID.test(String(v.id)));
    if (!others.length || !this.data) return '';
    const rows = others.map(v => {
      const item = this.extra.find(x => x.id === v.id);
      const problem = item ? this.extraProblem(item) : '';
      const state = !item ? '<span class="pf-text-secondary">not included</span>'
        : item.status === 'loading' ? '<span class="pf-spinner"></span> Reading the LUN from ONTAP…'
        : problem ? `<span class="pf-text-danger">${icon('x-circle')} ${esc(problem)}</span>`
        : `<span class="pf-text-success">${icon('check-circle')} LUN found</span><span class="pf-table__sub">FlexVol ${esc(item.data.lun.flexvol)} · ${item.data.snapshots.length} snapshots</span>`;
      return `<tr${item ? ' class="is-selected"' : ''}><td><input type="checkbox" name="groupVol" value="${esc(v.id)}"${item ? ' checked' : ''} aria-label="Restore ${esc(v.device || v.id)} too"></td>`
        + `<td class="mono">${esc(v.device || '-')}</td><td class="mono">${esc(v.id)}</td>`
        + `<td>${v.role === 'boot' ? 'Boot disk' : v.role === 'extended' ? 'Extended disk' : '-'}</td><td>${state}</td></tr>`;
    }).join('');
    return `<div class="group-pick"><h3 class="review-section">Restore more volumes of ${esc(inst.name)}</h3>`
      + '<p class="pf-text-secondary">Tick the other disks of this instance to restore them too: from the same snapshot time, into the same project, one volume after the other. '
      + 'With the boot disk included, the Review step offers a new instance that gets all the new volumes.</p>'
      + '<div class="pf-table-wrap"><table class="pf-table" aria-label="Other volumes of the instance"><thead><tr><th style="width: 48px;"><span class="sr-only">Include</span></th>'
      + `<th>Device</th><th>Volume ID</th><th>Role</th><th>ONTAP</th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
  },
  // Same checks as for the first volume (step 1): LUN found, FlexVol online, room for the data, snapshots, no -restore LUN.
  extraProblem(item) {
    if (item.status === 'loading') return 'Reading the LUN…';
    if (item.status === 'error') return item.error;
    const d = item.data;
    if (d.restore_path_exists) return `A LUN from an earlier restore still exists: ${d.restore_path}`;
    if (d.flexvol.state !== 'online') return `FlexVol ${d.flexvol.name} is ${d.flexvol.state}`;
    if (Number(d.flexvol.available) < Number(d.lun.used)) return `Not enough free space in FlexVol ${d.flexvol.name}`;
    if (!d.snapshots.length) return `FlexVol ${d.flexvol.name} has no snapshots`;
    return '';
  },
  async toggleExtra(id, on) {
    const v = (this.os?.result?.instance?.volumes || []).find(x => x.id === id);
    if (!v) return;
    if (!on) {
      this.extra = this.extra.filter(x => x.id !== id);
      return this.groupChanged();
    }
    const item = {id, device: v.device || '', role: v.role || '', status: 'loading', data: null, error: ''};
    this.extra.push(item);
    this.groupChanged();
    try {
      item.data = await api(`${BASE}/api/snapshots?${qs({site: Site.current, volume_id: id})}`);
      item.status = 'ok';
    } catch (e) {
      Object.assign(item, {status: 'error', error: e.message});
    }
    if (this.extra.includes(item)) this.groupChanged();
  },
  groupChanged() {
    this.plans = null;
    if (this.snapshot && !this.commonSnapshots().some(x => x.name === this.snapshot)) this.snapshot = '';
    $('#groupPick').innerHTML = this.groupPicker();
    this.renderFilter();
    this.renderSnapshots();
    this.render();
  },
  // Snapshots of the volume; with more volumes only those that exist (same name) in the FlexVol of every one of them.
  commonSnapshots() {
    if (!this.data) return [];
    const others = this.extra.filter(x => x.data).map(x => new Set(x.data.snapshots.map(y => y.name)));
    return this.data.snapshots.filter(x => others.every(names => names.has(x.name)));
  },

  // ---------- step 2: snapshot ----------
  renderFilter() {
    if (!this.data) return;
    $('#snapFilter').innerHTML = this.filterHtml();
  },
  filterHtml() {
    const kinds = [...new Set(this.commonSnapshots().map(s => s.schedule))];
    return [['', 'All'], ...kinds.map(k => [k, k])]
      .map(([v, label]) => `<label><input type="radio" name="snapFilter" value="${esc(v)}"${v === this.filter ? ' checked' : ''}><span>${esc(label)}</span></label>`).join('');
  },
  renderSnapshots() {
    if (!this.data) return;
    const view = this.snapshotsView();
    $('#snapCount').textContent = view.count;
    $('#snapList').innerHTML = view.rows;
  },
  // The count and rows of the snapshot list, with the filter and the volumes of a group (also drawn by the guide).
  // limit: at most that many snapshots, the chosen one always among them.
  snapshotsView(limit = Infinity) {
    const snaps = this.commonSnapshots(), volumes = this.extra.length + 1;
    const shown = snaps.filter(s => !this.filter || s.schedule === this.filter);
    const count = `${shown.length} of ${snaps.length} snapshots${volumes > 1 ? ` that exist for all ${volumes} volumes` : ''}`;
    if (!shown.length) {
      const text = volumes > 1 && !snaps.length ? `No snapshot with the same name exists for all ${volumes} volumes. Restore them one by one.`
        : 'No snapshots with this schedule.';
      return {count, rows: `<tr><td colspan="4"><div class="pf-empty-state">${icon('info')}<span>${esc(text)}</span></div></td></tr>`};
    }
    const some = shown.slice(0, limit), chosen = shown.find(x => x.name === this.snapshot);
    if (chosen && !some.includes(chosen)) some.splice(-1, 1, chosen);
    return {count, rows: this.snapRowsHtml(some, this.snapshot)};
  },
  snapRowsHtml(shown, chosen) {
    let lastDay = '';
    return shown.map(s => {
      const day = s.local_time.slice(0, 10);
      const group = day !== lastDay
        ? `<tr class="pf-table__group"><td colspan="4">${esc(new Date(`${day}T00:00:00`).toLocaleDateString('en-GB', {weekday: 'long', day: 'numeric', month: 'long', year: 'numeric'}))}</td></tr>` : '';
      lastDay = day;
      const selected = s.name === chosen;
      return group + `<tr class="is-clickable${selected ? ' is-selected' : ''}" data-snap="${esc(s.name)}">`
        + `<td><input type="radio" name="snapshot" value="${esc(s.name)}"${selected ? ' checked' : ''} aria-label="${esc(s.local_time)} ${esc(s.name)}"></td>`
        + `<td><b>${esc(s.local_time.slice(11))}</b></td><td class="mono">${esc(s.name)}</td>`
        + `<td><span class="pf-label">${esc(s.schedule)}</span></td></tr>`;
    }).join('');
  },
  select(name) {
    this.snapshot = name;
    $$('#snapList tr[data-snap]').forEach(row => {
      const on = row.dataset.snap === name;
      row.classList.toggle('is-selected', on);
      row.querySelector('input').checked = on;
    });
    this.render();
  },

  // ---------- step 4: review (Ansible plan, read-only) ----------
  review() {
    if (this.plan && this.plan.key === this.planKey() && Date.now() - this.plan.at < PLAN_TTL && (!this.groupMode() || this.plans)) {
      return this.renderReview();
    }
    this.startPlan();
  },
  async startPlan() {
    if (this.groupMode()) return this.startGroupPlan();
    if (this.planRunning || this.blocked()) return;
    const keep = this.plan || {};   // the operator's choices are kept on Check again when they still apply
    this.plan = null;
    this.planRunning = true;
    this.render();
    const box = $('#reviewBody');
    box.innerHTML = this.checkingHtml('Running playbook plan.yml…');
    const recheck = '<div class="pf-mt-md"><button type="button" class="pf-btn pf-m-secondary" id="recheckBtn">Check again</button></div>';
    try {
      const key = this.planKey();
      const {job_id: jobId} = await api(`${BASE}/api/plan`, {site: Site.current, volume_id: this.data.volume_id, snapshot: this.snapshot, project_id: this.projectId()});
      let since = 0, lines = [], data;
      for (;;) {
        data = await api(`${BASE}/api/jobs/${encodeURIComponent(jobId)}?since=${since}`);
        since = data.next;
        lines = lines.concat(data.lines);
        if ($('#planTask') && data.task) $('#planTask').textContent = data.task;
        if (data.status !== 'running') break;
        await sleep(1000);
      }
      if (data.status !== 'success') {
        box.innerHTML = alertBox('danger', 'Check failed', esc(data.error)) + recheck
          + `<details class="pf-mt-lg"><summary>Ansible output (${lines.length} lines)</summary><div class="pf-log pf-mt-md">${LogView.html(lines)}</div></details>`;
        return;
      }
      this.plan = this.planFrom(jobId, key, data.result, keep);
      this.renderReview();
    } catch (e) {
      box.innerHTML = alertBox('danger', 'Check failed', esc(e.message)) + recheck;
    } finally {
      this.planRunning = false;
      this.render();
    }
  },

  checkingHtml(task) {
    return '<div class="pf-empty-state"><span class="pf-spinner pf-m-lg"></span><h3 class="pf-title">Checking restore prerequisites</h3>'
      + `<span id="planTask">${esc(task)}</span></div>`;
  },
  // The plan of the Review step from the result of plan.yml; keep: the choices of the plan before (Check again).
  planFrom(jobId, key, r, keep = {}) {
    const ni = r.after_restore?.new_instance || {};
    const kept = (r.type_options || []).find(o => o.name === keep.type)?.pools || r.pools;
    const pool = (kept?.pools || []).find(p => p.host === keep.pool && p.selectable) ? keep.pool : '';
    const action = keep.action === 'instance' && !ni.possible ? 'none' : (keep.action || 'none');
    const type = (r.type_options || []).some(o => o.name === keep.type) ? keep.type : (r.volume.type || '');
    return {jobId, key, result: r, at: Date.now(), type, name: keep.key === key && keep.name ? keep.name : r.default_new_name, pool, action,
            attachId: keep.attachId || '', instanceName: keep.instanceName || ni.default_name || '',
            portNets: this.keptPortNets(keep.portNets, ni), scheduleDelete: keep.scheduleDelete ?? true};
  },

  // ---- Volume type and Cinder pool: chosen by the operator; the pool follows the chosen type (default: original type) ----
  // plan: the plan of one volume (default: the single restore); index: its place in plans for a group.
  // The volume type of the new volume (default: the original type) and its pools; another type is reached with lun move.
  typeOption(plan = this.plan) { return (plan.result.type_options || []).find(o => o.name === plan.type) || null; },
  typeChangedFrom(plan = this.plan) { return plan.type !== (plan.result.volume.type || '') ? (plan.result.volume.type || 'no type') : ''; },
  pools(plan = this.plan) { return this.typeOption(plan)?.pools || plan.result.pools || {pools: [], max_used_percent: 85}; },
  typeField(plan = this.plan, index = null) {
    const options = plan.result.type_options || [];
    if (options.length < 2) return '';
    const id = index === null ? 'targetType' : `targetType${index}`, opt = this.typeOption(plan), from = this.typeChangedFrom(plan);
    const items = options.map(o => `<option value="${esc(o.name)}"${o.name === plan.type ? ' selected' : ''}${!o.selectable && !o.original ? ' disabled' : ''}>`
      + `${esc(o.name || '(no type)')}${o.original ? ' (original)' : ''} · ${o.selectable ? `${o.selectable} usable pool${o.selectable === 1 ? '' : 's'}` : 'no usable pool'}`
      + `${o.description ? ` · ${esc(o.description)}` : ''}</option>`).join('');
    const help = from
      ? `The new volume gets volume type <b>${esc(plan.type)}</b> instead of ${esc(from)} (backend ${esc(opt?.backend || '-')}): `
        + `the restored LUN is moved with lun move to a pool of that type in SVM ${esc(plan.result.lun.svm)}, then managed with that type.`
      : 'Same type as the original volume. Pick another type to change the tier; the pools below follow the type.';
    return `<div class="pf-form-group type-field"><label class="pf-form-label" for="${id}">Volume type of the new volume</label>`
      + `<select class="pf-form-control" id="${id}"${index === null ? '' : ` data-type-for="${index}"`}>${items}</select>`
      + `<span class="pf-helper-text">${help}</span></div>`;
  },
  // The prerequisites of the plan; the pool check follows the volume type chosen here (the plan checked the original).
  checks(plan) {
    const from = this.typeChangedFrom(plan);
    if (!from) return plan.result.checks;
    const pools = this.pools(plan).pools, usable = pools.filter(p => p.selectable).length;
    return plan.result.checks.map(c => c.key !== 'pool_available' ? c : {...c, ok: usable > 0,
      detail: `${usable} of ${pools.length} Cinder pool${pools.length === 1 ? '' : 's'} of volume type ${plan.type} can take the volume`});
  },
  typeChanged(value, index = null) {
    const plan = index === null ? this.plan : this.plans[index];
    plan.type = value;
    if (!this.pools(plan).pools.some(p => p.host === plan.pool && p.selectable)) plan.pool = '';
    if (index === null) this.renderReview(); else this.renderGroupReview();
    this.render();
  },
  selectedPool(plan = this.plan) { return plan ? this.pools(plan).pools.find(p => p.host === plan.pool && p.selectable) || null : null; },
  poolTable(plan = this.plan, index = null) {
    const info = this.pools(plan), limit = info.max_used_percent;
    const radio = index === null ? 'pool' : `pool-${index}`, of = index === null ? '' : ` data-plan="${index}"`;
    const rows = info.pools.map(p => {
      const selected = p.host === plan.pool && p.selectable;
      const tags = [p.current ? '<span class="pf-label pf-m-blue pf-m-compact">LUN pool · no lun move</span>' : '',
                    p.test ? '<span class="pf-label pf-m-gold pf-m-compact">test pool</span>' : ''].join('');
      const status = p.selectable
        ? `<span class="pf-text-success">${icon('check-circle')} Available</span>`
          + (p.filter_ok === false && p.utilization != null ? `<span class="pf-table__sub">Performance utilization ${esc(p.utilization)}% (NetApp filter_function)</span>` : '')
        : `<span class="pf-text-danger">${icon('x-circle')} ${esc(p.reason)}</span>`;
      const ontap = p.svm ? `ONTAP ${bytes(p.ontap_available)} free · ${esc(p.svm)}` : 'ONTAP: FlexVol not read';
      const capacity = p.basis === 'allocated'
        ? `${gib(p.allocated_gb)} of ${gib(p.capacity_gb)}<span class="pf-table__sub">${p.ratio !== 1
          ? `total ${gib(p.total_gb)} × ${esc(p.ratio)} (overcommit ${esc(p.ratio)}:1)` : `total ${gib(p.total_gb)} (no overcommit)`}</span>`
        : p.free_gb != null ? `${gib(p.free_gb)} free of ${gib(p.total_gb)}<span class="pf-table__sub">allocated not reported by Cinder</span>`
        : '<span class="pf-text-secondary">not reported by Cinder</span>';
      return `<tr class="${p.selectable ? 'is-clickable' : 'is-disabled'}${selected ? ' is-selected' : ''}" data-pool="${esc(p.host)}"${of} title="${esc(p.host)}">`
        + `<td><input type="radio" name="${radio}" value="${esc(p.host)}"${selected ? ' checked' : ''}${p.selectable ? '' : ' disabled'} aria-label="${esc(p.flexvol)}"></td>`
        + `<td><b class="mono">${esc(p.flexvol)}</b> ${tags}<span class="pf-table__sub">${ontap}</span></td>`
        + `<td>${usageBar(p.used_pct, limit)}</td>`
        + `<td class="pf-nowrap">${capacity}</td>`
        + `<td>${status}</td></tr>`;
    }).join('');
    const unread = !info.pool_found ? alertBox('warning', 'The Cinder pools could not be read',
      'Only the pool of the LUN can be used (no lun move). Its capacity comes from ONTAP.') : '';
    return unread + '<div class="pf-table-wrap pool-table"><table class="pf-table" aria-label="Cinder pools">'
      + '<thead><tr><th style="width: 48px;"><span class="sr-only">Select</span></th><th>Pool (FlexVol)</th><th>Used</th>'
      + '<th>Allocated (Cinder)</th><th>Status</th></tr></thead>'
      + `<tbody>${rows}</tbody></table></div>`
      + `<p class="pf-helper-text pf-mt-sm">Pools of volume type <b>${esc(info.type || plan.result.volume.type || '-')}</b>`
      + `${info.backend ? ` (backend ${esc(info.backend)})` : ''}. Nothing is selected for you. Used = what Cinder allocated on the pool against its capacity `
      + `(total${(info.overcommit_ratio || 1) !== 1 ? ` × ${esc(info.overcommit_ratio)}, overcommit ${esc(info.overcommit_ratio)}:1 on this site` : ', no overcommit on this site'}); `
      + `a pool is full at ${esc(limit)}% used. Another pool than the LUN pool is reached with lun move (same SVM, used data only) before cinder manage.</p>`;
  },
  poolChanged(host, index = null) {
    const plan = index === null ? this.plan : this.plans[index];
    const p = this.pools(plan).pools.find(x => x.host === host && x.selectable);
    if (!p) return;
    plan.pool = host;
    $$(index === null ? '#reviewBody tr[data-pool]' : `#reviewBody tr[data-pool][data-plan="${index}"]`).forEach(row => {
      const on = row.dataset.pool === host;
      row.classList.toggle('is-selected', on);
      const input = row.querySelector('input');
      if (input) input.checked = on;
    });
    if (index === null) $('#poolSummary').innerHTML = this.poolSummary();
    else $$(`[data-pool-summary="${index}"]`).forEach(el => { el.innerHTML = this.poolSummary(plan); });
    this.renderCommands();
  },
  poolSummary(plan = this.plan) {
    const p = this.selectedPool(plan);
    if (!p) return '<span class="pf-text-secondary">Select a pool below</span>';
    return `<b class="mono">${esc(p.flexvol)}</b> ${p.current ? '<span class="pf-text-secondary">(pool of the LUN, no lun move)</span>'
      : `<span class="pf-text-secondary">(lun move from ${esc(plan.result.lun.flexvol)}; extra time depends on the ${bytes(plan.result.lun.used)} of data)</span>`}`;
  },

  // ---- After the restore: transfer only / attach to an instance (Instance ID) / new instance (boot volume) ----
  after() { return this.plan.result.after_restore || {servers: [], new_instance: {}}; },
  attachServer() { return this.after().servers.find(x => x.id === this.plan.attachId.toLowerCase()) || null; },
  actionProblem() {
    if (!this.plan) return '';
    if (this.plan.action === 'attach') {
      const s = this.attachServer();
      if (!UUID.test(this.plan.attachId.toLowerCase())) return 'Enter the ID of the instance to attach the volume to.';
      if (!s) return 'That instance is not in the target project.';
      if (!s.attachable) return `Instance ${s.name} is ${s.status}; a volume cannot be attached to it.`;
    }
    if (this.plan.action === 'instance') {
      const ni = this.after().new_instance;
      if (!ni.possible) return 'A new instance cannot be created.';
      if (!INSTANCE_NAME.test(this.plan.instanceName)) return 'Enter a valid name for the new instance.';
      const open = (ni.ports || []).find(pt => !this.portNet(pt).network_id);
      if (open) return `Choose a network for network interface ${open.index} of the new instance.`;
    }
    return '';
  },
  // ---- Network of every network interface of a new instance: the original network when the target project can use
  // it, otherwise a network of that project (its VPC) or a shared network, chosen here ----
  defaultPortNets(ni) {
    return (ni?.ports || []).map(pt => ({network_id: pt.network_id || '',
      subnet_id: pt.network_id && pt.network_id !== pt.original_network_id ? (pt.subnet_ids[0] || '') : ''}));
  },
  // The choices of an earlier plan (Check again), as long as the new plan still offers them.
  keptPortNets(kept, ni) {
    const defaults = this.defaultPortNets(ni);
    if (!Array.isArray(kept)) return defaults;
    return defaults.map((d, i) => {
      const k = kept[i], pt = ni.ports[i];
      if (!k?.network_id) return d;
      const option = (ni.network_options || []).find(o => o.id === k.network_id);
      const original = k.network_id === pt.original_network_id && pt.original_usable !== false;
      if (!original && !option) return d;
      return {network_id: k.network_id, subnet_id: !k.subnet_id || (option?.subnets || []).some(s => s.id === k.subnet_id) ? k.subnet_id : d.subnet_id};
    });
  },
  portNet(pt) { return this.plan.portNets?.[pt.index - 1] || {network_id: pt.network_id || '', subnet_id: ''}; },
  // What a port of the new instance gets with the current choice (the playbook works it out the same way).
  portView(pt) {
    const ni = this.after().new_instance || {}, sel = this.portNet(pt), originalId = pt.original_network_id ?? pt.network_id;
    const onOriginal = Boolean(sel.network_id) && sel.network_id === originalId && pt.original_usable !== false;
    const option = (ni.network_options || []).find(o => o.id === sel.network_id) || null;
    const subnets = onOriginal ? [] : option?.subnets || [];
    const subnet = subnets.find(s => s.id === sel.subnet_id) || null;
    const hasIp = onOriginal || !sel.network_id ? pt.original_ips.length > 0 : subnets.length > 0;
    const normal = (pt.vnic_type || 'normal') === 'normal';
    const security = (hasIp && normal) || (!normal && pt.original_port_security !== false);
    return {sel, onOriginal, option, subnets, subnet, security,
            name: onOriginal ? (pt.original_network_name || pt.network_name) : option?.name || '',
            subnetIds: onOriginal ? (pt.original_subnet_ids || pt.subnet_ids) : subnet ? [subnet.id] : [],
            groups: security && ni.same_project !== false ? (pt.original_security_groups || pt.security_groups) : []};
  },
  portNetCell(pt) {
    const ni = this.after().new_instance || {}, v = this.portView(pt), p = this.plan.result.project;
    const project = esc(p.name || p.id), was = esc(pt.original_network_name || pt.original_network_id || pt.network_name);
    if (!ni.networks_read) return `${esc(pt.network_name)}<span class="pf-table__sub mono">${esc(pt.network_id)}</span>`;
    const cidrs = o => o.subnets.filter(s => s.cidr).map(s => s.cidr).join(', ');
    const label = o => `${o.name}${cidrs(o) ? ` · ${cidrs(o)}` : ''}${o.id === pt.original_network_id ? ' (original)' : ''}`
      + `${o.external ? ' (external)' : ''}${o.up === false ? ' (DOWN)' : o.status && o.status !== 'ACTIVE' ? ` (${o.status})` : ''}`;
    const opt = o => `<option value="${esc(o.id)}"${o.id === v.sel.network_id ? ' selected' : ''}>${esc(label(o))}</option>`;
    const own = ni.network_options.filter(o => o.own), shared = ni.network_options.filter(o => !o.own);
    const original = pt.original_usable !== false && !ni.network_options.some(o => o.id === pt.original_network_id)
      ? `<option value="${esc(pt.original_network_id)}"${v.onOriginal ? ' selected' : ''}>${was} (original)</option>` : '';
    const select = `<select class="pf-form-control" data-port-net="${pt.index}" aria-label="Network of network interface ${pt.index}">`
      + (v.sel.network_id ? '' : '<option value="" selected>Choose a network…</option>') + original
      + (own.length ? `<optgroup label="Networks of project ${project}">${own.map(opt).join('')}</optgroup>` : '')
      + (shared.length ? `<optgroup label="Shared networks">${shared.map(opt).join('')}</optgroup>` : '') + '</select>';
    const subnet = v.subnets.length > 1 && v.subnets.some(s => s.cidr)
      ? `<select class="pf-form-control pf-mt-sm" data-port-subnet="${pt.index}" aria-label="Subnet of network interface ${pt.index}">`
        + v.subnets.map(s => `<option value="${esc(s.id)}"${s.id === v.sel.subnet_id ? ' selected' : ''}>${esc(s.cidr || s.id)}${s.name ? ` · ${esc(s.name)}` : ''}</option>`).join('')
        + '</select>' : '';
    const note = pt.original_usable === false
      ? `<span class="pf-helper-text${v.sel.network_id ? '' : ' pf-m-error'}">Was ${was}: not available in project ${project}</span>`
      : v.onOriginal ? '' : `<span class="pf-helper-text">Was ${was}</span>`;
    return select + subnet + note;
  },
  portNetChanged(index, value) {
    const ni = this.after().new_instance || {}, pt = ni.ports.find(x => x.index === index);
    const option = (ni.network_options || []).find(o => o.id === value);
    const original = value === pt.original_network_id && pt.original_usable !== false;
    if (!this.plan.portNets) this.plan.portNets = this.defaultPortNets(ni);
    this.plan.portNets[index - 1] = {network_id: value, subnet_id: original ? '' : (option?.subnets || []).find(s => s.ip_version === '4')?.id || ''};
    this.refreshAfter(`[data-port-net="${index}"]`);
  },
  portSubnetChanged(index, value) {
    this.plan.portNets[index - 1].subnet_id = value;
    this.refreshAfter(`[data-port-subnet="${index}"]`);
  },
  refreshAfter(focus) {
    $('#afterDetail').innerHTML = this.afterDetail();
    this.renderCommands();
    this.render();
    $(`#afterDetail ${focus}`)?.focus();
  },
  portNetsBody() {
    return (this.after().new_instance?.ports || []).map(pt => ({network_id: this.portNet(pt).network_id, subnet_id: this.portNet(pt).subnet_id || ''}));
  },
  portCommands(ni, name) {
    return ni.ports.map(pt => {
      const v = this.portView(pt);
      return `openstack port create --network ${v.sel.network_id || '<choose a network>'}${v.subnetIds.map(s => ` --fixed-ip subnet=${s}`).join('')}`
        + (v.security ? ` --enable-port-security${v.groups.map(g => ` --security-group ${g.id}`).join('')}` : ' --disable-port-security --no-security-group')
        + ` ${name}-port${pt.index}`;
    });
  },
  afterField() {
    const r = this.plan.result, a = this.after(), ni = a.new_instance || {}, role = r.role?.role, p = r.project;
    const radio = (value, title, body, disabled = false) => `<label class="pf-radio-card${this.plan.action === value ? ' is-selected' : ''}${disabled ? ' is-disabled' : ''}">`
      + `<input type="radio" name="afterAction" value="${value}"${this.plan.action === value ? ' checked' : ''}${disabled ? ' disabled' : ''}>`
      + `<span><b>${title}</b><span class="pf-helper-text">${body}</span></span></label>`;
    const others = this.groupMode() ? this.plans.length - 1 : 0;
    const options = [
      radio('none', `Only move the volume${others ? 's' : ''} to project ${esc(p.name || p.id)}`,
        others ? 'The new volumes stay detached in the project.' : 'The new volume stays detached in the project.'),
      radio('attach', 'Attach to an instance', `Enter the instance ID; the instance must be in project ${esc(p.name || p.id)}.`
        + (others ? ' Every new volume is attached to it, in device order.' : '')),
    ];
    if (role === 'boot') {
      options.push(radio('instance', `Create a new instance like ${esc(r.instance?.name || '')}`,
        ni.possible ? `${ni.same_project === false ? `Same flavor and availability zone, on networks of project ${esc(p.name || p.id)} (chosen below)`
          : 'Same flavor, networks, security groups and availability zone'}; boots from the new volume${others
          ? `. The other ${others} new volume${others === 1 ? ' is' : 's are'} restored first and attached when the instance is created` : ''}.`
          : `Not possible: ${esc(ni.reason)}`, !ni.possible));
    }
    return `<div class="pf-radio-cards" role="radiogroup" aria-label="After the restore">${options.join('')}</div><div id="afterDetail">${this.afterDetail()}</div>`;
  },
  afterDetail() {
    const r = this.plan.result, a = this.after(), ni = a.new_instance || {};
    if (this.plan.action === 'attach') {
      const s = this.attachServer(), id = this.plan.attachId.trim();
      let help = 'The ID column of openstack server list, or pick one from the list.', bad = false;
      if (id && !UUID.test(id.toLowerCase())) { help = 'The instance ID must be an OpenStack UUID.'; bad = true; }
      else if (id && !s) { help = `No instance with this ID in project ${esc(r.project.name || r.project.id)}.`; bad = true; }
      else if (s && !s.attachable) { help = `${esc(s.name)} is ${esc(s.status)}; a volume can be attached when it is ACTIVE, SHUTOFF, PAUSED, SUSPENDED or SHELVED.`; bad = true; }
      else if (s) help = `${icon('check-circle')} <b>${esc(s.name)}</b> · ${esc(s.status)}${s.original ? ' · the instance of the original volume' : ''}`;
      const warn = [];
      if (s?.original) {
        warn.push(alertBox('warning', 'This is the instance of the original volume',
          'The restored disk is a copy of a disk this instance already uses: same filesystem UUIDs and LVM names. Mount it by device '
          + '(for example /dev/vdc) to copy files; make sure /etc/fstab or LVM does not pick the copy instead of the original at the next boot.'));
      }
      if (r.role?.role === 'boot' && s) {
        warn.push(alertBox('info', 'A boot disk as an extra disk', 'The instance does not boot from it: mount it to copy files.'));
      }
      if (!a.servers_read) warn.push(alertBox('warning', 'The instances of the target project could not be read', 'Check again, or choose another action.'));
      return '<div class="pf-form-group pf-mt-md"><label class="pf-form-label" for="attachId">Instance ID <span class="pf-required" aria-hidden="true">*</span></label>'
        + `<input class="pf-form-control mono${bad ? ' is-invalid' : ''}" id="attachId" list="attachList" value="${esc(this.plan.attachId)}" maxlength="36" autocomplete="off" spellcheck="false" aria-describedby="attachHelp" placeholder="5e000000-0000-4000-8000-000000000001">`
        + `<datalist id="attachList">${a.servers.map(x => `<option value="${esc(x.id)}">${esc(x.name)} · ${esc(x.status)}</option>`).join('')}</datalist>`
        + `<span class="pf-helper-text${bad ? ' pf-m-error' : ''}" id="attachHelp">${help}</span></div>` + warn.join('');
    }
    if (this.plan.action === 'instance' && ni.possible) {
      const f = ni.flavor || {};
      const project = esc(r.project.name || r.project.id);
      const ports = ni.ports.map(pt => {
        const v = this.portView(pt);
        const address = !v.sel.network_id ? '-' : v.onOriginal ? 'new IP' : v.subnet?.cidr ? `new IP from ${esc(v.subnet.cidr)}`
          : v.subnets.length ? 'new IP (OpenStack picks the subnet)' : 'no IP (the network has no subnet)';
        const groups = !v.security ? 'port security off' : v.groups.length ? esc(v.groups.map(g => g.name).join(', '))
          : ni.same_project === false ? `default of project ${project}` : 'default of the project';
        return `<tr><td>${pt.index}</td><td class="port-net">${this.portNetCell(pt)}</td>`
          + `<td>${address} <span class="pf-table__sub">was ${esc(pt.original_ips.join(', ') || '-')}</span></td>`
          + `<td>${groups}</td><td>${esc(pt.vnic_type)}</td></tr>`;
      }).join('');
      const props = Object.entries(ni.properties || {});
      return '<div class="pf-form-group pf-mt-md"><label class="pf-form-label" for="instanceName">New instance name <span class="pf-required" aria-hidden="true">*</span></label>'
        + `<input class="pf-form-control mono${INSTANCE_NAME.test(this.plan.instanceName) ? '' : ' is-invalid'}" id="instanceName" value="${esc(this.plan.instanceName)}" maxlength="63" autocomplete="off" spellcheck="false" aria-describedby="instanceNameHelp">`
        + '<span class="pf-helper-text" id="instanceNameHelp">Letters, digits, _ . - (max. 63, starting with a letter or digit).</span></div>'
        + dl([
          ['Copied from', `${esc(ni.source_name)} <span class="mono pf-text-secondary">${esc(ni.source_id)}</span>`],
          ['Flavor', `${esc(f.name)} · ${esc(f.vcpus ?? '?')} vCPU · ${f.ram_mb != null ? esc(f.ram_mb / 1024) : '?'} GiB RAM · ${esc(f.disk_gb ?? '?')} GB disk`],
          ['Availability zone', esc(ni.availability_zone || '-')],
          ['Boot', 'from the new volume (vda); image properties of the original volume are copied to it'],
          this.groupMode() && ['Other disks', this.runOrder().filter(pl => pl.result.role?.role !== 'boot')
            .map(pl => `${esc(this.deviceOf(pl))} ← new volume <span class="mono">${esc(pl.name)}</span>`).join('<br>')],
          props.length && ['Properties', props.map(([k, v]) => `<span class="mono">${esc(k)}=${esc(v)}</span>`).join(', ')],
          ni.config_drive && ['Config drive', 'yes'],
        ])
        + '<div class="pf-table-wrap pf-mt-md"><table class="pf-table" aria-label="Network interfaces of the new instance"><thead><tr><th>#</th><th>Network</th>'
        + `<th>Address</th><th>Security groups</th><th>vNIC</th></tr></thead><tbody>${ports}</tbody></table></div>`
        + (ni.warnings.length ? `<div class="pf-mt-md">${alertBox('warning', 'Check before launching', `<ul>${ni.warnings.map(w => `<li>${esc(w)}</li>`).join('')}</ul>`)}</div>` : '')
        + `<div class="pf-mt-sm">${alertBox('info', 'Good to know', `<ul>${ni.notes.map(n => `<li>${esc(n)}</li>`).join('')}</ul>`)}</div>`;
    }
    return '';
  },
  actionChanged(value) {
    this.plan.action = value;
    if (this.groupMode()) return this.renderGroupReview();   // the order of the volumes depends on the action
    $$('#reviewBody .pf-radio-card').forEach(card => card.classList.toggle('is-selected', card.querySelector('input').value === value));
    $('#afterDetail').innerHTML = this.afterDetail();
    this.renderCommands();
  },
  attachChanged() {
    this.plan.attachId = $('#attachId').value.trim();
    const pos = $('#attachId').selectionStart;
    $('#afterDetail').innerHTML = this.afterDetail();
    const input = $('#attachId');
    input.focus();
    input.setSelectionRange(pos, pos);
    this.renderCommands();
  },
  instanceNameChanged() {
    const input = $('#instanceName');
    this.plan.instanceName = input.value.trim();
    input.classList.toggle('is-invalid', !INSTANCE_NAME.test(this.plan.instanceName));
    this.renderCommands();
  },

  // The commands that will run, following the pool choice and the action after the restore.
  movePath(plan = this.plan) {
    const p = this.selectedPool(plan);
    return p && !p.current ? `/vol/${p.flexvol}/${plan.result.restore_path.split('/').pop()}` : '';
  },
  // restore-file, lun move, cinder manage, image properties, and transfer of one volume.
  volumeCommands(plan, ref = '<new volume ID>') {
    const r = plan.result, v = r.volume, p = this.selectedPool(plan), move = this.movePath(plan);
    const list = [r.restore_file_cli];
    if (move) list.push(`lun move start -vserver ${r.lun.svm} -source-path ${r.restore_path} \\\n  -destination-path ${move}`);
    list.push(`cinder manage --id-type source-name --name ${plan.name || '<new volume name>'}${plan.type ? ` --volume-type ${plan.type}` : ''}${v.bootable ? ' --bootable' : ''} \\\n`
      + `  ${p ? p.host : '<select a Cinder pool>'} \\\n  ${move || r.restore_path}`);
    const props = Object.entries(r.image_properties || {});
    if (props.length) list.push(`openstack volume set ${props.map(([k, val]) => `--image-property ${k}=${val}`).join(' ')} ${ref}`);
    if (r.transfer.needed) list.push(`openstack volume transfer request create ${ref}   # accepted in project ${r.project.name || r.project.id}`);
    return list;
  },
  commands() {
    if (this.groupMode()) return this.groupCommands();
    const r = this.plan.result, v = r.volume;
    const list = this.volumeCommands(this.plan);
    if (this.plan.action === 'attach') list.push(`openstack server add volume ${this.plan.attachId || '<instance ID>'} <new volume ID>`);
    if (this.plan.action === 'instance' && r.after_restore?.new_instance?.possible) {
      const ni = r.after_restore.new_instance, name = this.plan.instanceName || '<name>';
      list.push(...this.portCommands(ni, name));
      const props = {...(ni.properties || {}), restore_source_server: ni.source_id, restore_source_volume: v.id, restore_snapshot: r.snapshot.name};
      list.push(`openstack server create --flavor ${ni.flavor.id} --volume <new volume ID> ${ni.ports.map(pt => `--nic port-id=<port${pt.index}>`).join(' ')}`
        + `${ni.availability_zone ? ` --availability-zone ${ni.availability_zone}` : ''}${ni.config_drive ? ' --config-drive True' : ''} \\\n  `
        + Object.entries(props).map(([k, val]) => `--property ${k}=${val}`).join(' ') + ` \\\n  ${name}`);
    }
    return list;
  },
  renderCommands() {
    if (!$('#reviewCmds')) return;
    $('#reviewCmds').innerHTML = this.commandsHtml();
  },
  commandsHtml() { return this.commands().map(c => `<pre class="pf-code-block">${esc(c)}</pre>`).join(''); },
  nameChanged() {
    const input = $('#newName');
    this.plan.name = input.value.trim();
    const ok = VOLUME_NAME.test(this.plan.name);
    input.classList.toggle('is-invalid', !ok);
    $('#newNameHelp').classList.toggle('pf-m-error', !ok);
    this.renderCommands();
  },
  renderReview() {
    if (this.groupMode()) return this.renderGroupReview();
    $('#reviewBody').innerHTML = this.reviewHtml();
    this.renderCommands();
  },
  // The Review step of one volume, from its plan (also drawn by the guide of the Review step)
  reviewHtml() {
    const r = this.plan.result, v = r.volume, p = r.project, t = r.transfer;
    const failed = r.checks.filter(c => !c.ok);
    return (failed.length ? alertBox('danger', 'The restore cannot run yet', failed.map(c => esc(c.detail)).join('<br>'))
        + '<div class="pf-mt-md pf-mb-lg"><button type="button" class="pf-btn pf-m-secondary" id="recheckBtn">Check again</button></div>' : '')
      + '<h3 class="review-section">Source</h3>' + dl([
        ['Site', `${esc(r.site)} · ${esc(r.cluster)}`],
        ['Source volume', `${esc(v.name || '(no name)')} <span class="mono pf-text-secondary">${esc(v.id)}</span>`],
        ['Volume details', `${esc(v.size_gb)} GB · ${esc(v.status)} · type ${esc(v.type || '-')}${v.bootable ? ' · bootable' : ''}`],
        ['Attached to', r.instance?.id ? `${esc(r.instance.name)} <span class="mono pf-text-secondary">${esc(r.instance.id)}</span> ${roleLabel(r.role)}`
          : roleLabel(r.role) + (r.instance_error ? ` <span class="pf-text-secondary">${esc(r.instance_error)}</span>` : '')],
        ['Source LUN', `<span class="mono">${esc(r.lun.name)}</span>`
          + (r.lun.ref_id && r.lun.ref_id !== v.id ? ` <span class="pf-label pf-m-blue">via name_id</span>` : '')],
        ['Snapshot', `<b>${esc(r.snapshot.local_time)}</b> <span class="mono pf-text-secondary">${esc(r.snapshot.name)}</span>`],
      ])
      + '<h3 class="review-section">Result</h3>' + dl([
        ['Restored LUN', `<span class="mono">${esc(r.restore_path)}</span>`],
        ['Wait for used space', `until the restored LUN uses ≈ <b>${bytes(r.lun.used)}</b> (like the original LUN), then cinder manage`],
        ['Volume type', this.typeChangedFrom() ? `<b>${esc(this.plan.type)}</b> <span class="pf-label pf-m-gold pf-m-compact">changed from ${esc(this.typeChangedFrom())}</span>`
          : `${esc(v.type || 'no type')} <span class="pf-text-secondary">(same as the original volume)</span>`],
        ['Cinder pool', `<span id="poolSummary">${this.poolSummary()}</span>`],
        ['Target project', `<b>${esc(p.name)}</b> <span class="mono pf-text-secondary">${esc(p.id)}</span>${p.same_as_source ? ' (original volume project)' : ''}`],
        ['Project move', t.needed ? `Volume transfer${t.temporary_role ? `; admin gets the <b>${esc(t.temporary_role)}</b> role temporarily, removed afterwards` : ''}` : 'Not needed'],
      ])
      + `<h3 class="review-section">Prerequisites${failed.length ? '' : ' <button type="button" class="pf-btn pf-m-link pf-m-inline" id="recheckBtn">Check again</button>'}</h3><ul class="pf-checks">`
      + this.checks(this.plan).map(c => `<li class="${c.ok ? 'is-ok' : 'is-bad'}">${icon(c.ok ? 'check-circle' : 'x-circle')}<span>${esc(c.detail)}</span></li>`).join('') + '</ul>'
      + (failed.length ? '' : '<h3 class="review-section">Volume type and Cinder pool <span class="pf-required" aria-hidden="true">*</span></h3>' + this.typeField() + this.poolTable()
        + '<h3 class="review-section">After the restore</h3>' + this.afterField())
      + '<h3 class="review-section">Commands</h3><div id="reviewCmds"></div>'
      + (failed.length ? '' : '<div class="pf-form-group pf-mt-lg"><label class="pf-form-label" for="newName">New volume name <span class="pf-required" aria-hidden="true">*</span></label>'
        + `<input class="pf-form-control mono" id="newName" value="${esc(this.plan.name)}" maxlength="128" autocomplete="off" spellcheck="false" aria-describedby="newNameHelp">`
        + '<span class="pf-helper-text" id="newNameHelp">Letters, digits, _ . : - (max. 128, starting with a letter or digit).</span></div>'
        + '<div class="pf-form-group"><label class="pf-check"><input type="checkbox" id="scheduleDelete"' + (this.plan.scheduleDelete ? ' checked' : '') + '>'
        + `<span>After ${esc(r.delete_after_hours || 72)} hours, ask an administrator to approve deleting the original volume `
        + `<span class="mono">${esc(v.id)}</span><span class="pf-helper-text">Nothing is deleted without that approval (menu Approvals). `
        + 'The deletion is refused while the original volume is attached to an instance or has snapshots.</span></span></label></div>'
        + '<div class="pf-confirm"><label class="pf-check"><input type="checkbox" id="reviewAck"><span>I have checked the volume, snapshot, Cinder pool, target project and the action after the restore. '
        + 'The original volume is not overwritten; the restore creates a new LUN and a new volume.</span></label></div>');
  },
  // ---------- Review of a group: one plan per volume, one action after the restore for all ----------
  deviceOf(plan) { return String(plan.result.role?.device || '').replace('/dev/', '') || '-'; },
  planLabel(plan) { return `${this.deviceOf(plan)} · ${plan.result.volume?.name || plan.volumeId}`; },
  // The order the server runs them: by device (boot disk first); with a new instance the boot disk comes last, so the
  // instance gets the other new volumes when it is created.
  runOrder() {
    const boot = pl => pl.result.role?.role === 'boot';
    const byDevice = [...this.plans].sort((a, b) => boot(b) - boot(a) || String(a.result.role?.device || '~').localeCompare(String(b.result.role?.device || '~')));
    return this.plan?.action === 'instance' ? [...byDevice.filter(pl => !boot(pl)), ...byDevice.filter(boot)] : byDevice;
  },
  async runPlan(volumeId, onTask) {
    const {job_id: jobId} = await api(`${BASE}/api/plan`, {site: Site.current, volume_id: volumeId, snapshot: this.snapshot, project_id: this.projectId()});
    let since = 0, data;
    for (;;) {
      data = await api(`${BASE}/api/jobs/${encodeURIComponent(jobId)}?since=${since}`);
      since = data.next;
      if (data.task) onTask(data.task);
      if (data.status !== 'running') return {jobId, ...data};
      await sleep(1000);
    }
  },
  async startGroupPlan() {
    if (this.planRunning || this.blocked()) return;
    const old = Object.fromEntries((this.plans || []).map(pl => [pl.volumeId, pl])), keep = this.plan || {};
    this.plans = null;
    this.plan = null;
    this.planRunning = true;
    this.render();
    const ids = [this.data.volume_id, ...this.extra.map(x => x.id)], tasks = {};
    const box = $('#reviewBody');
    box.innerHTML = this.checkingHtml(`Running playbook plan.yml for ${ids.length} volumes…`);
    const recheck = '<div class="pf-mt-md"><button type="button" class="pf-btn pf-m-secondary" id="recheckBtn">Check again</button></div>';
    try {
      const key = this.planKey();
      // At most 3 plans at a time: each one opens its own SSH session to the director.
      const done = new Array(ids.length);
      let next = 0;
      const worker = async () => {
        while (next < ids.length) {
          const i = next++;
          done[i] = await this.runPlan(ids[i], task => {
            tasks[ids[i]] = task;
            if ($('#planTask')) $('#planTask').textContent = Object.values(tasks).join(' · ');
          });
        }
      };
      await Promise.all(Array.from({length: Math.min(3, ids.length)}, worker));
      const failed = done.filter(x => x.status !== 'success');
      if (failed.length) {
        box.innerHTML = alertBox('danger', 'Check failed', failed.map(x => esc(x.error)).join('<br>')) + recheck;
        return;
      }
      this.plans = done.map((x, i) => {
        const was = old[ids[i]] || {};
        const type = (x.result.type_options || []).some(o => o.name === was.type) ? was.type : (x.result.volume.type || '');
        const pools = (x.result.type_options || []).find(o => o.name === type)?.pools || x.result.pools;
        const pool = (pools?.pools || []).find(p => p.host === was.pool && p.selectable) ? was.pool : '';
        return {volumeId: ids[i], jobId: x.jobId, key, result: x.result, at: Date.now(), type, pool,
                name: was.key === key && was.name ? was.name : x.result.default_new_name};
      });
      // The choices of the group; its result is that of the boot disk (new instance) or of the first volume.
      const base = this.plans.find(pl => pl.result.role?.role === 'boot') || this.plans[0], ni = base.result.after_restore?.new_instance || {};
      this.plan = {key, at: Date.now(), result: base.result, action: keep.action === 'instance' && !ni.possible ? 'none' : (keep.action || 'none'),
                   attachId: keep.attachId || '', instanceName: keep.instanceName || ni.default_name || '',
                   portNets: this.keptPortNets(keep.portNets, ni), scheduleDelete: keep.scheduleDelete ?? true};
      this.renderGroupReview();
    } catch (e) {
      box.innerHTML = alertBox('danger', 'Check failed', esc(e.message)) + recheck;
    } finally {
      this.planRunning = false;
      this.render();
    }
  },
  groupHint() {
    const plans = this.plans;
    if (plans.some(pl => !pl.result.ready)) return 'Fix the failed prerequisites, then check again.';
    const missing = this.runOrder().filter(pl => !this.selectedPool(pl));
    if (missing.length) return `Select a Cinder pool for ${missing.map(pl => this.deviceOf(pl)).join(', ')}.`;
    if (new Set(plans.map(pl => pl.name)).size !== plans.length) return 'Each new volume needs its own name.';
    return this.actionProblem() || 'Review, then tick the confirmation.';
  },
  groupNameChanged(index) {
    const plan = this.plans[index];
    plan.name = $(`[data-name-for="${index}"]`).value.trim();
    const counts = {};
    this.plans.forEach(pl => { counts[pl.name] = (counts[pl.name] || 0) + 1; });
    this.plans.forEach((pl, i) => $(`[data-name-for="${i}"]`)?.classList.toggle('is-invalid', !VOLUME_NAME.test(pl.name) || counts[pl.name] > 1));
    this.renderCommands();
  },
  groupCommands() {
    const list = [], order = this.runOrder();
    order.forEach(pl => {
      const [first, ...rest] = this.volumeCommands(pl, `<new volume ID ${this.deviceOf(pl)}>`);
      list.push(`# ${this.planLabel(pl)}\n${first}`, ...rest);
    });
    const ref = pl => `<new volume ID ${this.deviceOf(pl)}>`;
    if (this.plan.action === 'attach') order.forEach(pl => list.push(`openstack server add volume ${this.plan.attachId || '<instance ID>'} ${ref(pl)}`));
    const ni = this.plan.result.after_restore?.new_instance;
    if (this.plan.action === 'instance' && ni?.possible) {
      const name = this.plan.instanceName || '<name>', boot = order[order.length - 1];
      list.push(...this.portCommands(ni, name));
      list.push(`openstack server create --flavor ${ni.flavor.id} --volume ${ref(boot)} \\\n  `
        + order.slice(0, -1).map(pl => `--block-device-mapping ${this.deviceOf(pl)}=${ref(pl)}:volume::false`).join(' \\\n  ')
        + ` \\\n  ${ni.ports.map(pt => `--nic port-id=<port${pt.index}>`).join(' ')}${ni.availability_zone ? ` --availability-zone ${ni.availability_zone}` : ''} ${name}`);
    }
    return list;
  },
  renderGroupReview() {
    $('#reviewBody').innerHTML = this.groupReviewHtml();
    this.renderCommands();
  },
  // The Review step of a group (also drawn by the guide of the Review step)
  groupReviewHtml() {
    const plans = this.plans, base = this.plan.result, p = base.project, t = base.transfer, order = this.runOrder();
    const notReady = plans.filter(pl => !pl.result.ready);
    const failedText = pl => pl.result.checks.filter(c => !c.ok).map(c => esc(c.detail)).join('; ');
    const rows = order.map(pl => {
      const i = plans.indexOf(pl), r = pl.result, bad = r.checks.filter(c => !c.ok).length;
      return `<tr><td class="mono">${esc(this.deviceOf(pl))}</td>`
        + `<td>${esc(r.volume.name || '(no name)')}<span class="pf-table__sub mono">${esc(r.volume.id)}</span>`
        + `<span class="pf-table__sub">${esc(r.volume.size_gb)} GB · type ${esc(r.volume.type || '-')}${r.volume.bootable ? ' · bootable' : ''}</span></td>`
        + `<td>${bad ? `<span class="pf-text-danger">${icon('x-circle')} ${bad} not met</span>` : `<span class="pf-text-success">${icon('check-circle')} All met</span>`}</td>`
        + `<td><span data-pool-summary="${i}">${this.poolSummary(pl)}</span><span class="pf-table__sub">type ${esc(pl.type || 'no type')}${this.typeChangedFrom(pl) ? ` (changed from ${esc(this.typeChangedFrom(pl))})` : ''}</span></td>`
        + `<td><input class="pf-form-control mono" data-name-for="${i}" value="${esc(pl.name)}" maxlength="128" autocomplete="off" spellcheck="false" aria-label="New volume name for ${esc(this.planLabel(pl))}"></td></tr>`;
    }).join('');
    const details = order.map(pl => {
      const i = plans.indexOf(pl), r = pl.result;
      return `<details class="group-volume" open><summary><b>${esc(this.planLabel(pl))}</b> <span class="pf-text-secondary">· LUN ${esc(r.lun.name)}</span></summary>`
        + dl([
          ['Source LUN', `<span class="mono">${esc(r.lun.name)}</span>${r.lun.ref_id && r.lun.ref_id !== r.volume.id ? ' <span class="pf-label pf-m-blue">via name_id</span>' : ''}`],
          ['Snapshot', `<b>${esc(r.snapshot.local_time)}</b> <span class="mono pf-text-secondary">${esc(r.snapshot.name)}</span>`],
          ['Restored LUN', `<span class="mono">${esc(r.restore_path)}</span> <span class="pf-text-secondary">(waits until it uses ≈ ${bytes(r.lun.used)})</span>`],
          ['Cinder pool', `<span data-pool-summary="${i}">${this.poolSummary(pl)}</span>`],
        ])
        + '<ul class="pf-checks">' + this.checks(pl).map(c => `<li class="${c.ok ? 'is-ok' : 'is-bad'}">${icon(c.ok ? 'check-circle' : 'x-circle')}<span>${esc(c.detail)}</span></li>`).join('') + '</ul>'
        + (r.ready ? `<h4 class="review-subsection">Volume type and Cinder pool <span class="pf-required" aria-hidden="true">*</span></h4>${this.typeField(pl, i)}${this.poolTable(pl, i)}` : '')
        + '</details>';
    }).join('');
    return (notReady.length ? alertBox('danger', 'The restore cannot run yet',
        notReady.map(pl => `<b>${esc(this.planLabel(pl))}</b>: ${failedText(pl)}`).join('<br>'))
        + '<div class="pf-mt-md pf-mb-lg"><button type="button" class="pf-btn pf-m-secondary" id="recheckBtn">Check again</button></div>' : '')
      + `<h3 class="review-section">${plans.length} volumes of ${esc(base.instance?.name || 'the instance')}${notReady.length ? ''
        : ' <button type="button" class="pf-btn pf-m-link pf-m-inline" id="recheckBtn">Check again</button>'}</h3>` + dl([
        ['Site', `${esc(base.site)} · ${esc(base.cluster)}`],
        ['Instance', `${esc(base.instance?.name || '')} <span class="mono pf-text-secondary">${esc(base.instance?.id || '')}</span>`],
        ['Snapshot', `<b>${esc(base.snapshot.local_time)}</b> <span class="mono pf-text-secondary">${esc(base.snapshot.name)}</span> (the same for every volume)`],
        ['Target project', `<b>${esc(p.name)}</b> <span class="mono pf-text-secondary">${esc(p.id)}</span>${p.same_as_source ? ' (original volume project)' : ''}`],
        ['Project move', t.needed ? `Volume transfer${t.temporary_role ? `; admin gets the <b>${esc(t.temporary_role)}</b> role temporarily, removed afterwards` : ''}` : 'Not needed'],
        ['Order', `${order.map(pl => esc(this.deviceOf(pl))).join(', then ')}: one restore (job) after the other. A failed restore stops the group; the volumes after it are not restored.`],
      ])
      + '<div class="pf-table-wrap pf-mt-md"><table class="pf-table" aria-label="Volumes to restore"><thead><tr><th>Device</th><th>Source volume</th>'
      + `<th>Prerequisites</th><th>Cinder pool</th><th>New volume name</th></tr></thead><tbody>${rows}</tbody></table></div>`
      + '<h3 class="review-section">Each volume</h3>' + details
      + (notReady.length ? '' : '<h3 class="review-section">After the restore</h3>' + this.afterField())
      + '<h3 class="review-section">Commands</h3><div id="reviewCmds"></div>'
      + (notReady.length ? '' : '<div class="pf-form-group pf-mt-lg"><label class="pf-check"><input type="checkbox" id="scheduleDelete"' + (this.plan.scheduleDelete ? ' checked' : '') + '>'
        + `<span>After ${esc(base.delete_after_hours || 72)} hours, ask an administrator to approve deleting the ${plans.length} original volumes`
        + '<span class="pf-helper-text">Nothing is deleted without that approval (menu Approvals). The deletion is refused while an original volume is attached to an instance or has snapshots.</span></span></label></div>'
        + `<div class="pf-confirm"><label class="pf-check"><input type="checkbox" id="reviewAck"><span>I have checked the ${plans.length} volumes, the snapshot, the Cinder pools, the target project and the action after the restore. `
        + 'The original volumes are not overwritten; each restore creates a new LUN and a new volume.</span></label></div>');
  },
  async launch() {
    if (this.groupMode()) return this.launchGroup();
    const body = {plan_job_id: this.plan.jobId, new_volume_name: this.plan.name, target_pool: this.plan.pool, post_action: this.plan.action,
                  schedule_delete: Boolean(this.plan.scheduleDelete), confirm: true};
    if (this.plan.action === 'attach') body.attach_server_id = this.plan.attachId.toLowerCase();
    if (this.plan.action === 'instance') Object.assign(body, {new_instance_name: this.plan.instanceName, new_port_networks: this.portNetsBody()});
    if (this.typeChangedFrom()) body.target_type = this.plan.type;
    const {history_id: historyId} = await api(`${BASE}/api/restore`, body);
    toast(`Restore #${historyId} launched.`, 'info');
    JobPage.pending = {historyId, withTransfer: Boolean(this.plan.result.transfer.needed), withMove: Boolean(this.movePath()), action: this.plan.action};
    this.clear();
    location.hash = `#/jobs/${historyId}`;
  },
  async launchGroup() {
    const body = {volumes: this.plans.map(pl => ({plan_job_id: pl.jobId, target_pool: pl.pool, new_volume_name: pl.name,
                                                   ...(this.typeChangedFrom(pl) ? {target_type: pl.type} : {})})),
                  post_action: this.plan.action, schedule_delete: Boolean(this.plan.scheduleDelete), confirm: true};
    if (this.plan.action === 'attach') body.attach_server_id = this.plan.attachId.toLowerCase();
    if (this.plan.action === 'instance') Object.assign(body, {new_instance_name: this.plan.instanceName, new_port_networks: this.portNetsBody()});
    const {group_id: groupId} = await api(`${BASE}/api/restore_group`, body);
    toast(`Restore group #${groupId} launched: ${this.plans.length} volumes, one after the other.`, 'info');
    this.clear();
    location.hash = `#/groups/${groupId}`;
  },
};

// The role of the volume in its instance.
function roleLabel(role) {
  const dev = String(role?.device || '').replace('/dev/', '');
  if (role?.role === 'boot') return `<span class="pf-label pf-m-blue">Boot disk${dev ? ` · ${esc(dev)}` : ''}</span>`;
  if (role?.role === 'extended') return `<span class="pf-label pf-m-green">Extended disk${dev ? ` · ${esc(dev)}` : ''}</span>`;
  return '<span class="pf-label">Not attached</span>';
}

// The instance the volume is attached to: flavor, network interfaces, other volumes (Volume step).
function instanceDetail(inst) {
  const f = inst.flavor || {};
  const ports = inst.ports.map((p, i) => `<tr><td>${i + 1}</td><td>${esc(p.network_name || '-')}<span class="pf-table__sub mono">${esc(p.network_id)}</span></td>`
    + `<td class="mono">${esc(p.ips.join(', ') || '-')}</td><td class="mono">${esc(p.mac)}</td>`
    + `<td>${esc(p.security_groups.join(', ') || '-')}</td><td>${p.port_security ? 'on' : '<span class="pf-label pf-m-gold pf-m-compact">off</span>'}</td></tr>`).join('');
  const vols = inst.volumes.map(v => `<tr${v.this ? ' class="is-selected"' : ''}><td class="mono">${esc(v.device || '-')}</td>`
    + `<td class="mono">${esc(v.id)}${v.this ? ' <span class="pf-label pf-m-blue pf-m-compact">this volume</span>' : ''}</td>`
    + `<td>${v.role === 'boot' ? 'Boot disk' : v.role === 'extended' ? 'Extended disk' : '-'}</td></tr>`).join('');
  return '<h3 class="review-section">Instance</h3>' + dl([
    ['Instance', `<b>${esc(inst.name)}</b> <span class="mono pf-text-secondary">${esc(inst.id)}</span> <span class="pf-label pf-m-compact">${esc(inst.status)}</span>`],
    ['Flavor', `${esc(f.name || f.id || '?')}${f.vcpus != null ? ` · ${esc(f.vcpus)} vCPU · ${esc(f.ram_mb / 1024)} GiB RAM · ${esc(f.disk_gb)} GB disk` : ''}${f.found === false ? ' <span class="pf-label pf-m-gold pf-m-compact">flavor not found</span>' : ''}`],
    ['Availability zone', esc(inst.availability_zone || '-')],
    ['Boot', inst.booted_from_volume ? 'from volume' : `from image ${esc(inst.image)}`],
    ['Key pair', esc(inst.key_name || '-')],
    ['Security groups', esc(inst.security_groups.join(', ') || '-')],
  ])
    + `<div class="pf-table-wrap pf-mt-md"><table class="pf-table" aria-label="Network interfaces"><thead><tr><th>#</th><th>Network</th><th>IP addresses</th><th>MAC</th><th>Security groups</th><th>Port security</th></tr></thead><tbody>${ports || '<tr><td colspan="6" class="pf-text-secondary">No network interfaces</td></tr>'}</tbody></table></div>`
    + `<div class="pf-table-wrap pf-mt-md"><table class="pf-table" aria-label="Volumes of the instance"><thead><tr><th>Device</th><th>Volume ID</th><th>Role</th></tr></thead><tbody>${vols}</tbody></table></div>`;
}

// Pool usage: a bar whose colour follows the full limit (pool_max_used_percent).
function usageBar(pct, limit) {
  if (pct == null) return '<span class="pf-text-secondary">not reported</span>';
  const state = pct >= limit ? ' is-full' : pct >= limit - 15 ? ' is-high' : '';
  return `<div class="pool-usage${state}"><div class="pool-usage__bar" role="img" aria-label="${pct.toFixed(1)}% used"><div style="width:${Math.min(100, pct)}%"></div></div>`
    + `<span>${pct.toFixed(1)}%</span></div>`;
}

function gib(n) {
  const v = Number(n);
  return v >= 1024 ? `${(v / 1024).toFixed(1)} TiB` : `${v.toFixed(0)} GiB`;
}

/* =========================================================================
   Ansible output (AWX style: line numbers, ok/changed/failed colours)
   ========================================================================= */
const LogView = {
  kind(line) {
    if (/^PLAY( RECAP)? \[?/.test(line)) return 'is-play';
    if (/^TASK \[/.test(line)) return 'is-task';
    if (/^(ok|included):/.test(line)) return 'is-ok';
    if (/^changed:/.test(line)) return 'is-changed';
    if (/^(fatal|failed):|FAILED!/.test(line)) return 'is-failed';
    if (/^skipping:/.test(line)) return 'is-skip';
    if (/^PROGRESS (used|move) /.test(line)) return 'is-progress';
    return '';
  },
  text(line) { return /^PROGRESS (used|move) /.test(line) ? line.split(' | ')[1] || line : line; },
  html(lines, start = 0) {
    return lines.map((line, i) => `<div class="pf-log__line"><span class="pf-log__num">${start + i + 1}</span>`
      + `<span class="pf-log__text ${this.kind(line)}">${esc(this.text(line)) || '&nbsp;'}</span></div>`).join('');
  },
};

/* =========================================================================
   Job page (like AWX: Details, Progress, Output)
   ========================================================================= */
// [label, task name pattern, marker]. A pattern is matched against the START of the task name (see playbooks/tasks/*.yml)
// and is only used after the re-check stage is done: the re-check tasks also mention "cinder manage", "lun move", and
// "tier move". The lines "PROGRESS used=" and "PROGRESS move" mark the 'used' and 'move' steps as active.
const RESTORE_STEPS = [
  ['Check all prerequisites again', /^$/],
  ['ONTAP: restore-file from snapshot to LUN -restore', /^ONTAP: volume snapshot restore-file/],
  ['ONTAP: wait for LUN -restore to be online', /^(ONTAP: wait for LUN .* to be online|Verify the restored LUN is online)/],
  ['ONTAP: wait for LUN -restore used space to match the original', /^ONTAP: (wait for restored LUN used space)/, 'used'],
  ['ONTAP: lun move LUN -restore to the selected pool', /^ONTAP: (lun move )/, 'move'],
  ['OpenStack: cinder manage (management → director → overcloudrc)', /^(Set new volume name|Validate new volume name|OpenStack: cinder manage)/],
  ['OpenStack: wait for the new volume to be available', /^(OpenStack: wait for the new volume to be available|Verify the new volume is available|OpenStack: copy (\d+ )?image properties)/],
  ['OpenStack: transfer the volume to the target project', /^(OpenStack: )?(Initialize transfer status|Initialize project actions|Transfer the volume to the target project|add temporary role|create transfer request|accept transfer)/i, 'transfer'],
  ['OpenStack: attach the volume to the instance', /^OpenStack: (instance [0-9a-f-]{36}$|attach (the )?volume|wait for the volume to be attached)/, 'attach'],
  ['OpenStack: create the new instance (ports, then the instance)', /^OpenStack: (create (\d+ port|ports for instance|instance )|wait for instance)/, 'instance'],
];
const CHECKS_DONE_TASKS = ['Verify all prerequisites are met'];

const JobPage = {
  id: null,
  pending: null,     // restore just started from the wizard: {historyId, withTransfer, withMove}
  token: 0,
  steps: RESTORE_STEPS,
  step: 0,
  progress: null,
  lineCount: 0,

  stop() { this.token += 1; },
  async open(id) {
    this.stop();
    const token = this.token;
    this.id = id;
    this.step = 0;
    this.progress = null;
    this.moveProgress = null;
    this.checked = false;   // the re-check stage (discover tasks) is already past
    this.lineCount = 0;
    ['#jobLog', '#jobOutcome', '#jobSteps', '#jobDetail', '#jobStatus'].forEach(sel => { $(sel).innerHTML = ''; });
    ['#jobElapsed', '#jobLines', '#jobTitle'].forEach(sel => { $(sel).textContent = ''; });
    $('#jobCrumb').textContent = `Restore #${id}`;
    let record;
    try {
      const data = await api(`${BASE}/api/history/${id}`);
      record = data.item;
      this.deletion = data.deletion;
    } catch (e) {
      $('#jobTitle').textContent = `Restore #${id}`;
      $('#jobOutcome').innerHTML = alertBox('danger', 'Job not found', esc(e.message));
      return;
    }
    if (token !== this.token) return;
    this.stepsFor(record);
    this.renderHeader(record);
    this.renderDetail(record, null);
    if (record.status === 'running' && record.job_id) {
      await this.follow(record, token);
    } else {
      this.consume((record.log || '').split('\n').filter((l, i, all) => l || i < all.length - 1));
      this.renderSteps(record.status);
      this.renderOutcome(record, null);
      if (!record.log) $('#jobLog').innerHTML = '<div class="pf-log-empty">No output yet.</div>';
    }
  },
  // The transfer step shows only when the target project differs. From the history this is certain only after a successful
  // restore (a transfer ID exists or not); otherwise the step is shown. The lun move step shows only when the chosen pool
  // is not the LUN pool (the target FlexVol is in the history); attach / new instance follow the action after the restore.
  stepsFor(record) {
    const mine = this.pending?.historyId === record.id;
    const transfer = mine ? this.pending.withTransfer : record.status === 'success' ? Boolean(record.transfer_id) : true;
    const move = mine ? this.pending.withMove : Boolean(record.move_flexvol);
    const action = mine ? this.pending.action : String(record.post_action || '').split(' ')[0];
    this.steps = RESTORE_STEPS.filter(s => (transfer || s[2] !== 'transfer') && (move || s[2] !== 'move')
      && (action === 'attach' || s[2] !== 'attach') && (action === 'instance' || s[2] !== 'instance'));
  },
  // Follow the running job until it finishes, then reload the final history record.
  async follow(record, token) {
    const started = Date.now();
    for (;;) {
      let data;
      try {
        data = await api(`${BASE}/api/jobs/${encodeURIComponent(record.job_id)}?since=${this.lineCount}`);
      } catch (e) {
        $('#jobOutcome').innerHTML = alertBox('warning', 'Cannot follow the progress', esc(e.message));
        return;
      }
      if (token !== this.token) return;
      this.consume(data.lines);
      $('#jobElapsed').textContent = duration(data.elapsed ?? (Date.now() - started) / 1000);
      this.renderSteps(data.status);
      if (data.status !== 'running') {
        const again = await api(`${BASE}/api/history/${record.id}`);
        const final = again.item;
        this.deletion = again.deletion;
        if (token !== this.token) return;
        this.stepsFor(final);
        this.renderSteps(final.status);
        this.renderHeader(final);
        this.renderDetail(final, data.result);
        this.renderOutcome(final, data.result);
        return;
      }
      await sleep(1000);
    }
  },
  consume(lines) {
    if (!lines.length) return;
    const log = $('#jobLog');
    const atBottom = log.scrollTop + log.clientHeight >= log.scrollHeight - 30;
    log.insertAdjacentHTML('beforeend', LogView.html(lines, this.lineCount));
    this.lineCount += lines.length;
    if (atBottom) log.scrollTop = log.scrollHeight;
    $('#jobLines').textContent = `${this.lineCount} lines`;
    for (const line of lines) {
      const p = line.match(/PROGRESS used=(\d+) target=(\d+)/);
      if (p) {
        this.progress = {used: Number(p[1]), target: Number(p[2])};
        this.step = Math.max(this.step, this.steps.findIndex(s => s[2] === 'used'));
        continue;
      }
      const mv = line.match(/PROGRESS move pct=(\d+) status=(\S+)/);
      if (mv) {
        this.moveProgress = {pct: Number(mv[1]), status: mv[2]};
        this.step = Math.max(this.step, this.steps.findIndex(s => s[2] === 'move'));
        continue;
      }
      const m = line.match(/^TASK \[(.+)\]/);
      if (!m) continue;
      if (!this.checked) {
        this.checked = CHECKS_DONE_TASKS.includes(m[1]);
        continue;
      }
      this.steps.forEach(([, re], i) => { if (i > this.step && re.test(m[1])) this.step = i; });
    }
  },
  renderHeader(r) {
    $('#jobTitle').textContent = r.volume_name || r.volume_id;
    $('#jobStatus').innerHTML = statusLabel(r.status);
    if (r.finished) $('#jobElapsed').textContent = duration((new Date(r.finished) - new Date(r.ts)) / 1000);
  },
  renderDetail(r, result) {
    const used = result?.used_wait;
    $('#jobDetail').innerHTML = dl([
      ['Site', esc(r.site)],
      ['Launched by', `${esc(r.username)} <span class="pf-text-secondary">from ${esc(r.client_ip || '-')}</span>`],
      ['Started', esc(fmtTime(r.ts))],
      r.finished && ['Finished', esc(fmtTime(r.finished))],
      ['Source volume', `${esc(r.volume_name || '')} <span class="mono pf-text-secondary">${esc(r.volume_id)}</span>`],
      ['Snapshot', `${esc(r.snapshot_time || '')} <span class="mono pf-text-secondary">${esc(r.snapshot)}</span>`],
      ['Restored LUN', `<span class="mono">${esc(r.restore_path || '-')}</span>`],
      ['Target project', `${esc(r.project_name || '')} <span class="mono pf-text-secondary">${esc(r.project_id || '')}</span>`],
      ['New volume', r.new_volume_id ? `${copyable(r.new_volume_id)} ${esc(r.new_volume_name || '')}` : esc(r.new_volume_name || '-')],
      r.volume_type && ['Volume type', esc(r.volume_type)],
      (r.cinder_pool || r.move_flexvol) && ['Cinder pool', r.cinder_pool
        ? `<span class="mono">${esc(r.cinder_pool.split('#').pop())}</span>${r.move_flexvol ? ' <span class="pf-text-secondary">· lun move</span>' : ' <span class="pf-text-secondary">· pool of the LUN</span>'}`
        : `lun move to FlexVol <span class="mono">${esc(r.move_flexvol)}</span>`],
      r.transfer_id && ['Transfer ID', `<span class="mono">${esc(r.transfer_id)}</span>`],
      ['After the restore', afterText(r)],
      r.group_id && ['Group', `<a href="#/groups/${r.group_id}">Restore group #${esc(r.group_id)}</a> <span class="pf-text-secondary">(several volumes of one instance)</span>`],
      this.deletion && ['Original volume', deletionText(this.deletion)],
      used && ['Restored LUN used space', `${bytes(used.used)} of ${bytes(used.target)} · ${used.reason === 'match' ? 'matches the original' : esc(used.note)}`],
      result?.transfer?.role_added && ['Temporary role', result.transfer.role_removed ? 'removed' : '<b class="pf-text-danger">NOT removed, remove it manually</b>'],
    ]);
  },
  renderSteps(status) {
    const done = status === 'success';
    $('#jobSteps').innerHTML = this.steps.map(([label, , tag], i) => {
      const state = done || i < this.step ? 'is-done' : i === this.step ? ({running: 'is-current', failed: 'is-failed', unknown: 'is-failed'}[status] || '') : '';
      const ic = {'is-done': 'check-circle', 'is-current': 'in-progress', 'is-failed': 'x-circle'}[state] || 'circle';
      let desc = '';
      if (tag === 'used' && this.progress && state) {
        const {used, target} = this.progress;
        const pct = target > 0 ? Math.min(100, Math.floor(used * 100 / target)) : 100;
        desc = `<div class="pf-progress-step__desc"><div class="pf-progress"><div class="pf-progress__bar" role="progressbar" aria-valuenow="${pct}" aria-valuemin="0" aria-valuemax="100">`
          + `<div class="pf-progress__indicator" style="width:${pct}%"></div></div><span>${bytes(used)} / ${bytes(target)} (${pct}%)</span></div></div>`;
      }
      if (tag === 'move' && this.moveProgress && state) {
        const {pct, status: st} = this.moveProgress;
        desc = `<div class="pf-progress-step__desc"><div class="pf-progress"><div class="pf-progress__bar" role="progressbar" aria-valuenow="${pct}" aria-valuemin="0" aria-valuemax="100">`
          + `<div class="pf-progress__indicator" style="width:${pct}%"></div></div><span>${pct}% · ${esc(st)}</span></div></div>`;
      }
      return `<li class="pf-progress-step ${state}"><span class="pf-progress-step__icon">${icon(ic)}</span>`
        + `<span class="pf-progress-step__title">${esc(label)}</span>${desc}</li>`;
    }).join('');
  },
  renderOutcome(r, result) {
    const post = String(r.post_result || '');
    if (r.status === 'success' && post.startsWith('failed')) {
      $('#jobOutcome').innerHTML = alertBox('warning', 'Restore finished, but the action after the restore failed',
        `New volume ${r.new_volume_id ? `<span class="mono">${esc(r.new_volume_id)}</span>` : ''} is in project ${esc(r.project_name || r.project_id)}. `
        + esc(post.replace(/^failed: /, '')));
    } else if (r.status === 'success') {
      $('#jobOutcome').innerHTML = alertBox('success', 'Restore finished',
        `New volume ${r.new_volume_id ? `<span class="mono">${esc(r.new_volume_id)}</span>` : ''} is in project ${esc(r.project_name || r.project_id)}`
        + (post.startsWith('ok: ') ? `, ${esc(post.slice(4))}.` : '.'));
    } else if (r.status === 'failed') {
      $('#jobOutcome').innerHTML = alertBox('danger', 'Restore failed', esc(r.error || result?.error || ''));
    } else if (r.status === 'unknown') {
      $('#jobOutcome').innerHTML = alertBox('warning', 'Unknown result', esc(r.error || 'Check the -restore LUN in ONTAP and the volume in OpenStack.'));
    }
  },
};

/* =========================================================================
   Restore group: several volumes of one instance, one restore (job) after the other
   ========================================================================= */
const GroupPage = {
  token: 0,
  stop() { this.token += 1; },
  async open(id) {
    this.stop();
    const token = this.token;
    $('#groupCrumb').textContent = `Restore group #${id}`;
    $('#groupTitle').textContent = `Restore group #${id}`;
    ['#groupList', '#groupDetail', '#groupOutcome', '#groupStatus'].forEach(sel => { $(sel).innerHTML = ''; });
    // Followed while it runs; each volume links to its own job page (progress and Ansible output).
    for (;;) {
      let group;
      try {
        group = (await api(`${BASE}/api/restore_groups/${id}`)).group;
      } catch (e) {
        if (token === this.token) $('#groupOutcome').innerHTML = alertBox('danger', 'Group not found', esc(e.message));
        return;
      }
      if (token !== this.token) return;
      this.render(group);
      if (group.status !== 'running') return;
      await sleep(2000);
    }
  },
  render(g) {
    $('#groupTitle').textContent = `${g.instance_name || g.instance_id || 'Instance'}: ${g.members.length} volumes`;
    $('#groupStatus').innerHTML = groupStatusLabel(g.status);
    $('#groupList').innerHTML = g.members.map((m, i) => {
      const note = m.status === 'running' ? m.task : String(m.note || '').replace(/^ok: /, '');
      return `<tr><td>${i + 1}</td><td class="mono">${esc(String(m.device || '').replace('/dev/', '') || '-')}</td>`
        + `<td>${esc(m.volume_name || '(no name)')}<span class="pf-table__sub mono">${esc(m.volume_id)}</span></td>`
        + `<td>${esc(m.new_volume_name)}${m.new_volume_id ? `<span class="pf-table__sub mono">${esc(m.new_volume_id)}</span>` : ''}`
        + `${m.volume_type ? `<span class="pf-table__sub">type ${esc(m.volume_type)}</span>` : ''}`
        + `<span class="pf-table__sub mono" title="${esc(m.cinder_pool)}">${esc(poolName(m.cinder_pool))}${m.lun_move ? ' · lun move' : ''}</span></td>`
        + `<td>${groupStatusLabel(m.status)}${note ? `<span class="pf-table__sub">${esc(note)}</span>` : ''}</td>`
        + `<td>${m.restore_id ? `<a class="pf-nowrap" href="#/jobs/${m.restore_id}">Restore #${m.restore_id}</a>` : '<span class="pf-text-secondary">—</span>'}</td></tr>`;
    }).join('');
    const after = String(g.post_action || '');
    $('#groupDetail').innerHTML = dl([
      ['Site', esc(g.site)],
      ['Launched by', `${esc(g.username)} <span class="pf-text-secondary">from ${esc(g.client_ip || '-')}</span>`],
      ['Started', esc(fmtTime(g.ts))],
      g.finished && ['Finished', esc(fmtTime(g.finished))],
      ['Instance', `${esc(g.instance_name || '')} <span class="mono pf-text-secondary">${esc(g.instance_id || '')}</span>`],
      ['Snapshot', `${esc(g.snapshot_time || '')} <span class="mono pf-text-secondary">${esc(g.snapshot)}</span>`],
      ['Target project', `${esc(g.project_name || '')} <span class="mono pf-text-secondary">${esc(g.project_id || '')}</span>`],
      ['After the restore', after.startsWith('attach ') ? `Attach every new volume to instance <span class="mono">${esc(after.slice(7))}</span>`
        : after.startsWith('instance ') ? `New instance <b>${esc(after.slice(9))}</b> with all new volumes` : 'Only moved to the project'],
    ]);
    const outcome = {
      success: ['success', 'All volumes restored'], partial: ['warning', 'All volumes restored, but an action after a restore failed'],
      failed: ['danger', 'The group stopped'], unknown: ['warning', 'Unknown result'],
    }[g.status];
    $('#groupOutcome').innerHTML = outcome ? alertBox(outcome[0], outcome[1], esc(g.error || '')) : '';
  },
};

// After-restore action in the history: post_action "attach <id>" / "instance <name>", post_result "ok: ..." / "failed: ...".
function afterText(r) {
  const action = String(r.post_action || ''), post = String(r.post_result || '');
  const what = action.startsWith('attach ') ? `Attach to instance <span class="mono">${esc(action.slice(7))}</span>`
    : action.startsWith('instance ') ? `New instance <b>${esc(action.slice(9))}</b>` : 'Only moved to the project';
  const result = post.startsWith('ok: ') ? `<div class="pf-text-success after-result">${icon('check-circle')} ${esc(post.slice(4))}</div>`
    : post.startsWith('failed: ') ? `<div class="pf-text-danger after-result">${icon('x-circle')} Failed: ${esc(post.slice(8))}</div>` : '';
  return `${what}${result}`;
}

// Deletion schedule of the original volume on the job page.
const DELETION_STATES = {
  scheduled: ['Scheduled', 'blue'], awaiting: ['Waiting for an administrator', 'gold'], deleting: ['Deleting', 'blue'],
  deleted: ['Deleted', 'green'], kept: ['Kept', ''], failed: ['Not deleted', 'red'],
};
function deletionLabel(state) {
  const [text, color] = DELETION_STATES[state] || [state, ''];
  return `<span class="pf-label pf-m-compact${color ? ` pf-m-${color}` : ''}">${esc(text)}</span>`;
}
function deletionText(d) {
  const when = d.state === 'scheduled' ? `deletion due ${esc(fmtTime(d.due))}, then an administrator decides`
    : d.state === 'awaiting' ? `due since ${esc(fmtTime(d.due))}` : d.decided_by ? `by ${esc(d.decided_by)} · ${esc(fmtTime(d.decided_at))}` : '';
  return `${deletionLabel(d.state)} <span class="pf-text-secondary">${when}</span> <a href="#/approvals">Approvals</a>`;
}

/* =========================================================================
   Approvals: delete the original volume after a restore, only with administrator approval
   ========================================================================= */
const Approvals = {
  view: 'open',
  items: [],
  checks: {},     // result of the Check button per ID (job delete_volume.yml check_only)
  busy: {},
  init() {
    $('#apView').addEventListener('change', e => { this.view = e.target.value; run(null, () => this.load()); });
    $('#apList').addEventListener('click', e => {
      const b = e.target.closest('button[data-act]');
      if (!b) return;
      const item = this.items.find(x => x.id === Number(b.dataset.id));
      if (item) run(b, () => this[b.dataset.act](item, b));
    });
  },
  async load() {
    const data = await api(`${BASE}/api/deletions?view=${encodeURIComponent(this.view)}`);
    this.items = data.items;
    Notify.show(data.summary);
    this.render();
  },
  render() {
    const admin = Session.isAdmin();
    $('#apNotice').innerHTML = admin ? '' : `<div class="pf-mb-lg">${alertBox('info', 'Only administrators decide',
      'You can check a volume; an administrator approves the deletion, keeps the volume, or postpones it.')}</div>`;
    $('#apShown').textContent = this.items.length ? `${this.items.length} volume${this.items.length === 1 ? '' : 's'}` : '';
    $('#apList').innerHTML = this.items.map(d => this.rowHtml(d, admin)).join('') || `<tr><td colspan="6"><div class="pf-empty-state">${icon('check-circle')}<h2 class="pf-title">Nothing here</h2>`
      + '<span>Original volumes appear here when a restore schedules them for deletion (Review step).</span></div></td></tr>';
  },
  rowHtml(d, admin) {
    const open = ['scheduled', 'awaiting', 'failed'].includes(d.state);
    const actions = d.state === 'deleted' || d.state === 'deleting' ? []
      : [`<button type="button" class="pf-btn pf-m-secondary pf-m-small" data-act="check" data-id="${d.id}">Check</button>`];
    if (admin && open) {
      if (d.state !== 'scheduled') actions.push(`<button type="button" class="pf-btn pf-m-danger pf-m-small" data-act="approve" data-id="${d.id}">Approve…</button>`);
      actions.push(`<select class="pf-form-control" id="apHours${d.id}" aria-label="Postpone by"><option value="24">1 day</option><option value="72">3 days</option><option value="168">7 days</option></select>`
        + `<button type="button" class="pf-btn pf-m-secondary pf-m-small" data-act="postpone" data-id="${d.id}">Postpone</button>`);
      actions.push(`<button type="button" class="pf-btn pf-m-link pf-m-small" data-act="keep" data-id="${d.id}">Keep volume</button>`);
    }
    const check = ['deleted', 'deleting'].includes(d.state) ? null
      : this.checks[d.id] || (d.check_result ? {result: safeJson(d.check_result), at: d.checked_at} : null);
    return `<tr><td class="pf-nowrap">${esc(fmtTime(d.due))}${d.state === 'scheduled' ? `<span class="pf-table__sub">${esc(untilText(d.due))}</span>` : ''}</td>`
      + `<td>${esc(d.volume_name || '(no name)')}<span class="pf-table__sub mono">${esc(d.volume_id)}</span>`
      + `<span class="pf-table__sub">project <span class="mono">${esc(d.project_name || d.project_id)}</span></span>${checkText(check)}</td>`
      + `<td class="pf-nowrap"><span class="site-dot" style="--site-color:${Site.info(d.site).color}"></span> ${esc(d.site)}</td>`
      + `<td><a href="#/jobs/${d.restore_id}">Restore #${d.restore_id}</a><span class="pf-table__sub">by ${esc(d.restored_by)} · new volume</span>`
      + `<span class="pf-table__sub mono">${esc(d.new_volume_id)}</span></td>`
      + `<td>${deletionLabel(d.state)}${d.decided_by ? `<span class="pf-table__sub">${esc(d.decided_by)} · ${esc(fmtTime(d.decided_at))}</span>` : ''}`
      + `${d.error ? `<span class="pf-table__sub pf-text-danger">${esc(d.error)}</span>` : ''}${d.note ? `<span class="pf-table__sub">${esc(d.note)}</span>` : ''}</td>`
      + `<td class="pf-table__actions"><div class="ap-actions">${actions.join('')}</div></td></tr>`;
  },
  async waitJob(jobId) {
    for (;;) {
      const data = await api(`${BASE}/api/jobs/${encodeURIComponent(jobId)}`);
      if (data.status !== 'running') return data;
      await sleep(1500);
    }
  },
  async check(d) {
    const {job_id: jobId} = await api(`${BASE}/api/deletions/${d.id}/check`, {});
    const data = await this.waitJob(jobId);
    this.checks[d.id] = {result: data.status === 'success' ? data.result : {error: data.error}, at: new Date().toISOString()};
    this.render();
  },
  // Approve: the check (OpenStack + LUN in NetApp) runs first; the dialog only offers what that check allows.
  // The playbook checks everything again right before it detaches or deletes anything.
  async approve(d) {
    const dialog = $('#approveDialog');
    $('#approveTitle').textContent = `Delete original volume ${d.volume_name || d.volume_id}?`;
    $('#approveBody').innerHTML = '<div class="pf-empty-state"><span class="pf-spinner pf-m-lg"></span>'
      + '<span>Checking the volume in OpenStack and its LUN in NetApp…</span></div>';
    $('#approveFooter').innerHTML = '<button type="submit" class="pf-btn pf-m-link" value="cancel">Cancel</button>';
    dialog.returnValue = '';
    dialog.showModal();
    const closed = new Promise(resolve => dialog.addEventListener('close', () => resolve(dialog.returnValue), {once: true}));
    let result;
    try {
      const {job_id: jobId} = await api(`${BASE}/api/deletions/${d.id}/check`, {});
      const data = await this.waitJob(jobId);
      result = data.status === 'success' ? data.result : {error: data.error};
    } catch (e) {
      result = {error: e.message};
    }
    this.checks[d.id] = {result, at: new Date().toISOString()};
    if (!dialog.open) return this.render();
    $('#approveBody').innerHTML = approveBody(d, result);
    const buttons = [];
    const snaps = (result.snapshots || []).length;
    if (result.can_delete) buttons.push(`<button type="submit" class="pf-btn pf-m-danger" value="delete">${snaps ? `Delete ${snaps} snapshot${snaps > 1 ? 's' : ''} and the volume` : 'Delete volume'}</button>`);
    if (result.can_detach) buttons.push('<button type="submit" class="pf-btn pf-m-danger" value="detach">Detach and delete</button>');
    const inst = result.can_delete_instance ? (result.attachments || [])[0] : null;
    if (inst) buttons.push('<button type="submit" class="pf-btn pf-m-danger" value="instance" id="apInstanceBtn" disabled>Delete instance and volume</button>');
    if (result.gone) buttons.push('<button type="submit" class="pf-btn pf-m-primary" value="gone">Close as already deleted</button>');
    buttons.push('<button type="submit" class="pf-btn pf-m-link" value="cancel" autofocus>Cancel</button>');
    $('#approveFooter').innerHTML = buttons.join('');
    if (inst) {   // the instance is deleted only after its exact name is typed
      const box = $('#apInstanceName');
      box?.addEventListener('input', () => { $('#apInstanceBtn').disabled = box.value.trim() !== (inst.server_name || inst.server_id); });
    }
    const choice = await closed;
    this.render();
    if (!['delete', 'detach', 'gone', 'instance'].includes(choice)) return;
    const body = {confirm: true, snapshots: (result.snapshots || []).map(x => x.id)};
    if (choice === 'detach') Object.assign(body, {detach: true, detach_servers: result.attachments.map(a => a.server_id)});
    if (choice === 'instance') Object.assign(body, {delete_instance: true, delete_server: inst.server_id,
                                                   delete_server_name: $('#apInstanceName').value.trim()});
    const {job_id: jobId} = await api(`${BASE}/api/deletions/${d.id}/approve`, body);
    toast(choice === 'gone' ? 'Recording the volume as already deleted…' : choice === 'instance'
      ? `Deleting instance ${inst.server_name || inst.server_id}, then volume ${d.volume_id}…`
      : `${choice === 'detach' ? 'Detaching and deleting' : 'Deleting'} ${(result.snapshots || []).length ? 'the snapshots, then ' : ''}volume ${d.volume_id}…`, 'info');
    await this.load();
    const data = await this.waitJob(jobId);
    if (data.status === 'success') toast(data.result?.summary || 'The volume was deleted.', 'success');
    else toast(`The volume was not deleted: ${data.error}`, 'danger');
    await this.load();
  },
  async keep(d) {
    const ok = await Confirm.ask(`Keep volume ${d.volume_name || d.volume_id}?`,
      'The original volume is not deleted and leaves this list. You can still delete it yourself later in OpenStack.', 'Keep volume');
    if (!ok) return;
    await api(`${BASE}/api/deletions/${d.id}/keep`, {note: ''});
    toast('The original volume is kept.', 'success');
    await this.load();
  },
  async postpone(d) {
    const hours = Number($(`#apHours${d.id}`).value);
    const {item} = await api(`${BASE}/api/deletions/${d.id}/postpone`, {hours});
    toast(`Postponed to ${fmtTime(item.due)}.`, 'success');
    await this.load();
  },
};

function safeJson(text) { try { return JSON.parse(text); } catch (e) { return null; } }
function untilText(iso) {
  const hours = Math.max(0, (new Date(iso) - Date.now()) / 3600000);
  return hours >= 48 ? `in ${Math.round(hours / 24)} days` : hours >= 1 ? `in ${Math.round(hours)} hours` : 'in less than an hour';
}
function checkText(check) {
  if (!check || !check.result) return '';
  const r = check.result;
  if (r.error) return `<div class="ap-check pf-text-danger">${icon('x-circle')} Check failed: ${esc(r.error)}</div>`;
  const tone = r.can_delete || r.gone ? 'pf-text-success' : r.can_detach || r.can_delete_instance ? '' : 'pf-text-danger';
  const items = (r.checks || []).map(c => `<li class="${c.ok ? '' : 'pf-text-danger'}">${esc(c.detail)}</li>`).join('')
    + (r.warnings || []).map(w => `<li>${esc(w)}</li>`).join('');
  return `<div class="ap-check ${tone}">${icon(r.can_delete || r.gone ? 'check-circle' : 'info')} ${esc(r.summary)} `
    + `<span class="pf-text-secondary">(checked ${esc(shortTime(check.at))})</span>${items ? `<ul>${items}</ul>` : ''}</div>`;
}

// Content of the Approve dialog: the result of the OpenStack and NetApp check, then what will be done.
function approveBody(d, r) {
  if (r.error) return alertBox('danger', 'The check failed', `${esc(r.error)}<br>Nothing can be approved until the check works.`);
  const byKey = Object.fromEntries((r.checks || []).map(c => [c.key, c]));
  const line = c => (c ? `<span class="${c.ok ? '' : 'pf-text-danger'}">${icon(c.ok ? 'check-circle' : 'x-circle')} ${esc(c.detail)}</span>` : '-');
  const atts = (r.attachments || []).map(a => `${esc(a.server_name || a.server_id)} <span class="pf-text-secondary">(${esc(a.server_status || '?')})</span>`
    + ` as <span class="mono">${esc(a.device || '?')}</span>${a.reason ? ` <span class="${a.instance_deletable ? 'pf-text-secondary' : 'pf-text-danger'}">— ${esc(a.reason)}</span>` : ''}`).join('<br>');
  const luns = (r.luns || []).map(l => `<span class="mono">${esc(l.name)}</span><br><span class="pf-text-secondary">SVM ${esc(l.svm)} · `
    + `${bytes(l.size)} · ${bytes(l.used)} used · ${esc(l.state || '?')} · ${l.mapped ? 'mapped' : 'not mapped'}</span>`).join('<br>');
  const snaps = r.snapshots || [];
  const snapList = snaps.map(x => `${esc(x.name || '(no name)')} <span class="mono pf-text-secondary">${esc(x.id)}</span>`
    + `<br><span class="${['available', 'error'].includes(x.status) ? 'pf-text-secondary' : 'pf-text-danger'}">${esc(x.size_gb)} GB · ${esc(x.status || '?')}`
    + `${x.created ? ` · created ${esc(fmtTime(x.created))}` : ''}</span>`).join('<br>');
  const snapFirst = snaps.length ? `Its ${snaps.length} Cinder snapshot${snaps.length > 1 ? 's are' : ' is'} deleted first (Cinder does not delete a volume `
    + 'that has snapshots); the volume only once they are gone. ' : '';
  let verdict;
  if (r.can_delete) {
    verdict = alertBox('warning', 'The volume can be deleted',
      `${snaps.length ? `Delete ${snaps.length} snapshot${snaps.length > 1 ? 's' : ''} and the volume` : 'Delete volume'} removes `
      + `<span class="mono">${esc(d.volume_id)}</span> from OpenStack; Cinder also removes its LUN in NetApp. ${snapFirst}`
      + 'This cannot be undone (the data stays in the FlexVol snapshots until they expire).');
  } else if (r.can_detach) {
    verdict = alertBox('warning', 'Still attached: detach first',
      `Detach and delete removes the disk from ${(r.attachments || []).map(a => `${esc(a.server_name || a.server_id)} (${esc(a.device)})`).join(', ')} `
      + `first, then deletes the volume. ${snapFirst}Make sure it is no longer mounted or used inside the operating system.`);
  } else if (r.can_delete_instance) {
    const a = r.attachments[0];
    const name = a.server_name || a.server_id;
    verdict = alertBox('danger', `Boot disk of instance ${esc(name)}: the instance is deleted first`,
      `Delete instance and volume deletes instance <b>${esc(name)}</b> <span class="mono">${esc(a.server_id)}</span> `
      + `(${esc(a.server_status || '?')}) first: it stops, Nova removes the ports it created and frees its floating IPs. `
      + (a.delete_on_termination
        ? 'The volume is set to <b>delete on termination</b>: Nova deletes it together with the instance; the portal then checks that the volume and its LUN are gone. '
        : 'Then the volume (no longer attached) is deleted; Cinder also removes its LUN in NetApp. ')
      + snapFirst
      + ((a.other_volumes || []).length ? `Its other disks (${a.other_volumes.map(esc).join(', ')}) are only detached and stay. ` : '')
      + 'This cannot be undone.'
      + `<div class="pf-form__group pf-mt-md"><label class="pf-form__label" for="apInstanceName">Type the instance name <b>${esc(name)}</b> to confirm</label>`
      + `<input class="pf-form-control" id="apInstanceName" autocomplete="off" spellcheck="false"></div>`);
  } else if (r.gone) {
    verdict = alertBox('info', 'Already deleted', `${esc(r.summary)} Close records it as deleted; nothing is run in OpenStack.`);
  } else if (r.orphan) {
    verdict = alertBox('danger', 'LUN left in NetApp', `${esc(r.summary)} Keep the volume on the list (Keep volume) once it is handled.`);
  } else {
    verdict = alertBox('danger', 'Cannot be deleted now', esc(r.summary));
  }
  return '<h3 class="review-section">OpenStack</h3>' + dl([
    ['Volume', !byKey.exists?.ok ? line(byKey.exists) : `${esc(r.volume?.name || '(no name)')} <span class="mono pf-text-secondary">${esc(d.volume_id)}</span>`
      + `<br><span class="pf-text-secondary">${esc(r.volume?.size_gb)} GB · ${esc(r.volume?.status)}</span>`],
    byKey.project && ['Project', line(byKey.project)],
    byKey.detached && ['Attached', atts || line(byKey.detached)],
    byKey.snapshots && ['Snapshots', snapList ? `${line(byKey.snapshots)}<br>${snapList}` : line(byKey.snapshots)],
  ]) + '<h3 class="review-section">NetApp</h3>' + dl([
    ['LUN', luns || line(byKey.netapp)],
    (r.warnings || []).length && ['Note', esc(r.warnings.join(' '))],
  ]) + `<div class="pf-mt-md">${verdict}</div>`;
}

// Notification in the masthead and the menu: original volumes that wait for an administrator decision.
// Updated when the page changes and when the tab becomes active again, not with a timer: every API call extends the
// session, so polling in the background would keep the session from ever ending because of idle time.
const Notify = {
  announced: false,
  listening: false,
  last: 0,
  start() {
    if (!this.listening) {
      this.listening = true;
      window.addEventListener('focus', () => this.refresh(30000));
      document.addEventListener('visibilitychange', () => { if (!document.hidden) this.refresh(30000); });
    }
    this.refresh();
  },
  async refresh(minGap = 0) {
    if ($('#appView').hidden || !Session.allowed || Date.now() - this.last < minGap) return;
    this.last = Date.now();
    try {
      const {summary} = await api(`${BASE}/api/deletions/summary`);
      this.show(summary);
    } catch (e) { /* not signed in or server not reachable: the next call shows it */ }
  },
  show(summary) {
    const n = summary?.needs_decision || 0;
    const admin = Session.isAdmin();
    $('#navApprovalsBadge').hidden = !n;
    $('#navApprovalsBadge').textContent = n;
    $('#notifyBtn').hidden = !(n && admin);
    $('#notifyCount').textContent = n;
    const text = `${n} original volume${n === 1 ? ' is' : 's are'} due for deletion and wait${n === 1 ? 's' : ''} for an administrator`;
    $('#notifyBtn').title = text;
    $('#notifyBtn').setAttribute('aria-label', text);
    if (n && admin && !this.announced && !location.hash.startsWith('#/approvals')) {
      this.announced = true;
      toast(`${text}.`, 'warning', {label: 'Open Approvals', fn: () => { location.hash = '#/approvals'; }});
      $('#toasts').lastElementChild?.classList.add('is-approvals');
    }
  },
};

/* =========================================================================
   History (a table like the Jobs list in AWX)
   ========================================================================= */
const History = {
  items: [],
  total: 0,
  timer: null,
  poll: null,
  init() {
    ['#hiUser', '#hiSite', '#hiStatus'].forEach(sel => $(sel).addEventListener('change', () => run(null, () => this.load())));
    $('#hiQ').addEventListener('input', () => { clearTimeout(this.timer); this.timer = setTimeout(() => run(null, () => this.load()), 300); });
    $('#hiMoreBtn').addEventListener('click', () => run($('#hiMoreBtn'), () => this.load(true)));
    // All jobs that match the filters (not only the loaded page), for an audit.
    $('#hiExportBtn').addEventListener('click', e => run(e.currentTarget, () => downloadFile(`${BASE}/export/jobs.csv?${qs(this.filters())}`, 'jobs.csv')));
    $('#hiList').addEventListener('click', e => { const row = e.target.closest('tr[data-id]'); if (row) location.hash = `#/jobs/${row.dataset.id}`; });
    $('#hiList').addEventListener('keydown', e => { const row = e.target.closest('tr[data-id]'); if (row && e.key === 'Enter') location.hash = `#/jobs/${row.dataset.id}`; });
  },
  // more: the next page; refresh: reload as many as are already shown (for the automatic update).
  filters() {
    return {user: $('#hiUser').value, site: $('#hiSite').value, status: $('#hiStatus').value, q: $('#hiQ').value.trim()};
  },
  async load(more = false, refresh = false) {
    const params = {...this.filters(), limit: refresh ? Math.max(50, this.items.length) : 50, offset: more ? this.items.length : 0};
    const data = await api(`${BASE}/api/history?${qs(params)}`);
    this.items = more ? [...this.items, ...data.items] : data.items;
    this.total = data.total;
    const keep = (sel, values, all) => {
      const current = $(sel).value;
      $(sel).innerHTML = `<option value="">${all}</option>` + values.map(v => `<option${v === current ? ' selected' : ''}>${esc(v)}</option>`).join('');
    };
    keep('#hiUser', data.users, 'All users');
    keep('#hiSite', Site.list.map(x => x.name), 'All sites');
    this.render();
  },
  filtered() { return ['#hiQ', '#hiUser', '#hiSite', '#hiStatus'].some(sel => $(sel).value.trim()); },
  render() {
    $('#hiList').innerHTML = this.items.map(x => this.rowHtml(x)).join('')
      || `<tr><td colspan="8"><div class="pf-empty-state">${this.filtered()
        ? `${icon('search')}<h2 class="pf-title">No results found</h2><span>Change the search or filters.</span>`
        : `${icon('cubes')}<h2 class="pf-title">No restores yet</h2><span>Restores launched from this app are listed here.</span>`}</div></td></tr>`;
    this.after();
  },
  rowHtml(x) {
    return `<tr class="is-clickable" data-id="${x.id}" tabindex="0">`
      + `<td>${x.id}${x.group_id ? `<a class="pf-table__sub pf-nowrap" href="#/groups/${x.group_id}">group #${esc(x.group_id)}</a>` : ''}</td>`
      + `<td><a href="#/jobs/${x.id}">${esc(x.volume_name || '(no name)')}</a><span class="pf-table__sub mono pf-nowrap">${esc(x.volume_id)}</span></td>`
      + `<td>${statusLabel(x.status)}${String(x.post_result || '').startsWith('failed') ? ` <span class="pf-label pf-m-gold pf-m-compact" title="${esc(x.post_result)}">${icon('alert')}action failed</span>` : ''}</td>`
      + `<td class="pf-nowrap"><span class="site-dot" style="--site-color:${Site.info(x.site).color}"></span> ${esc(x.site)}</td>`
      + `<td class="pf-nowrap" title="${esc(x.snapshot)}">${esc(x.snapshot_time || x.snapshot)}</td>`
      + `<td>${esc(x.project_name || x.project_id || '')}<span class="pf-table__sub">${esc(afterSummary(x))}</span>`
      + `${x.cinder_pool ? `<span class="pf-table__sub mono" title="${esc(x.cinder_pool)}">${esc(poolName(x.cinder_pool))}</span>` : ''}</td>`
      + `<td class="pf-nowrap">${esc(x.username)}</td>`
      + `<td class="pf-nowrap" title="${esc(fmtTime(x.ts))}">${esc(shortTime(x.ts))}</td></tr>`;
  },
  after() {
    $('#hiShown').textContent = this.total ? `${this.items.length} of ${this.total}` : '';
    $('#hiMore').hidden = this.items.length >= this.total;
    // Like the Jobs list in AWX: the status of a restore that is still running updates by itself.
    clearTimeout(this.poll);
    if (this.items.some(x => x.status === 'running')) {
      this.poll = setTimeout(() => { if (!$('#page-jobs').hidden) run(null, () => this.load(false, true)); }, 5000);
    }
  },
};

// Short text of the action after a restore for the Jobs list: its result when known, otherwise what was asked for.
function afterSummary(r) {
  const action = String(r.post_action || ''), post = String(r.post_result || '');
  if (post.startsWith('ok: ')) return post.slice(4);
  if (post.startsWith('failed: ')) return 'Action after the restore failed';
  if (action.startsWith('attach ')) return `Attach to instance ${action.slice(7)}`;
  if (action.startsWith('instance ')) return `New instance ${action.slice(9)}`;
  return 'Only moved to the project';
}
// host@backend#pool -> pool (the FlexVol); the full name is in the title.
const poolName = host => String(host || '').split('#').pop();

/* =========================================================================
   Start
   ========================================================================= */
document.addEventListener('DOMContentLoaded', async () => {
  UserMenu.init();
  Wizard.init();
  History.init();
  Approvals.init();
  Router.init();
  document.addEventListener('click', e => { const b = e.target.closest('dialog [data-close]'); if (b) b.closest('dialog').close(); });
  if (!location.hash) history.replaceState(null, '', '#/restore');
  try {
    const status = await (await fetch(`${BASE}/api/session`)).json();
    if (status.user) Session.enter(status);
    else Session.update(status);   // not signed in: the portal sign-in, then back to this page
  } catch (e) {
    toast('Cannot reach the web server.');
  }
  Wizard.render();
});

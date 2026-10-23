'use strict';
/* Ops Portal: sign-in (Active Directory + Duo), the module gallery (PatternFly card view), and for administrators
   the Users (role + module access, activity) and Credentials pages. Taken from ONTAP Restore Web UI so that every
   page of the portal looks and behaves the same. UI specification: docs/UI-SPEC.md */

/* =========================================================================
   Utilities
   ========================================================================= */
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
const qs = params => Object.entries(params).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v ?? '')}`).join('&');
const icon = name => `<svg class="pf-icon" aria-hidden="true"><use href="#i-${name}"></use></svg>`;

function storage(area) {
  return {
    get(key) { try { return window[area].getItem(key); } catch (e) { return null; } },
    set(key, value) { try { window[area].setItem(key, value); } catch (e) { /* storage not available */ } },
    remove(key) { try { window[area].removeItem(key); } catch (e) { /* storage not available */ } },
  };
}
const tabStore = storage('sessionStorage');
const localStore = storage('localStorage');

const BASE_TITLE = document.title;
const UI_VERSION = document.querySelector('meta[name="ui-version"]')?.content || '';
const SITE_COLORS = ['#2b9af3', '#3e8635', '#8476d1', '#ec7a08', '#c9190b', '#009596'];
const MODULE_ICONS = {checklist: 'checklist', database: 'database', network: 'network'};

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
// host[:port] from what was typed or pasted (a whole console URL is fine): the same rule as the server.
function normalizeAddress(value) {
  let t = String(value || '').trim();
  if (t.includes('://')) t = t.split('://', 2)[1];
  t = t.split('/')[0].split('?')[0].split('#')[0];
  if (t.includes('@')) t = t.slice(t.lastIndexOf('@') + 1);
  return t.trim();
}
function alertBox(kind, title, body = '') {
  const name = {success: 'check-circle', danger: 'x-circle', warning: 'alert', info: 'info'}[kind];
  return `<div class="pf-alert pf-m-${kind}"${kind === 'danger' ? ' role="alert"' : ''}>${icon(name)}<div class="pf-alert__title">${title}</div>`
    + (body ? `<div class="pf-alert__body">${body}</div>` : '') + '</div>';
}

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
  try { data = await res.json(); } catch (e) { throw new Error(`Portal server error (HTTP ${res.status})`); }
  // The session ended (expired, signed out elsewhere, or access removed): back to the sign-in page.
  if (res.status === 401 && url !== '/api/login') Session.refresh();
  // No longer an administrator: refresh the menu (the page is left by the router).
  if (res.status === 403 && url.startsWith('/api/admin/')) Session.refresh();
  if (!data.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

// A file from the server (CSV export). Errors come back as JSON, like the API.
async function downloadFile(url, fallbackName) {
  const res = await fetch(url);
  if (!res.ok) {
    let data = {};
    try { data = await res.json(); } catch (e) { /* not JSON */ }
    if (res.status === 401) Session.refresh();
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

// PatternFly toast. With action {label, fn}: stays until it is closed or its action is clicked.
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

// Async action with a loading button; errors become a toast.
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
   Session and sign-in
   ========================================================================= */
const ROLE_LABELS = {admin: 'Administrator', operator: 'Operator'};
// How the current user signed in: an AD or a local portal account, with or without Duo.
function signedInWith(user) {
  const account = user.source === 'local' ? 'a local account' : 'Active Directory';
  return {sso: 'Signed in with Duo SSO', duo: `Signed in with ${account} and Duo`, none: `Signed in with ${account}`,
    bypassed: `Signed in with ${account} (Duo was unreachable and bypassed)`}[user.mfa] || '';
}

// Page of a module to open after the sign-in (?next=/ontap/#/jobs). Kept in the tab while Duo or Duo SSO is open.
const Next = {
  KEY: 'portal_next',
  remember() {
    const next = new URLSearchParams(location.search).get('next');
    if (next && /^\/(?!\/)[\w\-/.#?=&%]*$/.test(next)) tabStore.set(this.KEY, next);
    if (next !== null) history.replaceState(null, '', `${location.pathname}${location.hash}`);
  },
  take() {
    const next = tabStore.get(this.KEY);
    tabStore.remove(this.KEY);
    return next && next !== '/' && !next.startsWith('/#') ? next : '';
  },
};

const Session = {
  user: null,              // {username, display_name, role, mfa, modules}
  status: null,
  auth: {duo: false, problems: []},
  outdated: false,
  // The server already runs a newer portal (for example after install.sh); this page is an older version.
  checkVersion(status) {
    if (this.outdated || !status.ui_version || !UI_VERSION || status.ui_version === UI_VERSION) return;
    this.outdated = true;
    toast('A new version of the portal is available. Reload the page.', 'info', {label: 'Reload', fn: () => location.reload()});
  },
  isAdmin() { return this.user?.role === 'admin'; },
  // Every session answer (/api/session, or the session part of a 401) passes through here.
  update(status) {
    this.checkVersion(status);
    this.auth = status.auth || this.auth;
    Login.render(this.auth);
    if (!status.user) return this.showLogin();
    if (!$('#appView').hidden) this.apply(status);
  },
  apply(status) {
    this.user = status.user;
    this.status = status;
    UserMenu.render(this.user, status.client);
    $$('.admin-only').forEach(el => { el.hidden = !this.isAdmin(); });
    Home.render(status);
    window.PortalLauncher?.refresh();
    if (!this.isAdmin() && /^#\/(users|credentials)\b/.test(location.hash)) location.replace('#/home');
  },
  showLogin() {
    UserMenu.close();
    $('#appView').hidden = true;
    $('#loginView').hidden = false;
    document.title = BASE_TITLE;
    ($('#loginUser').value ? $('#loginPass') : $('#loginUser')).focus();
  },
  enter(status) {
    // Another account signed in on this page after the previous session ended: start with a clean page.
    if (this.user && this.user.username !== status.user.username) return location.reload();
    const next = Next.take();
    if (next) return location.assign(next);
    this.checkVersion(status);
    this.auth = status.auth || this.auth;
    $('#loginView').hidden = true;
    $('#appView').hidden = false;
    this.apply(status);
    Router.go();
  },
  async refresh() {
    try {
      this.update(await (await fetch('/api/session')).json());
    } catch (e) { /* server not reachable: keep the page as it is */ }
  },
  async logout() {
    UserMenu.close();
    try { await fetch('/api/logout', {method: 'POST'}); } catch (e) { /* the session still ends when it expires */ }
    history.replaceState(null, '', `${location.pathname}#/home`);
    location.reload();
  },
};

// Sign-in with the AD account (and Duo, when enabled) or a local portal account.
const Login = {
  init() {
    $('#togglePass').addEventListener('click', () => {
      const show = $('#loginPass').type === 'password';
      $('#loginPass').type = show ? 'text' : 'password';
      $('#togglePass').setAttribute('aria-pressed', String(show));
      $('#togglePass').setAttribute('aria-label', show ? 'Hide password' : 'Show password');
      $('#togglePass').innerHTML = icon(show ? 'eye-closed' : 'eye');
    });
    $('#loginForm').addEventListener('submit', e => this.submit(e));
    $('#loginUser').value = localStore.get('portal_user') || '';
  },
  // How sign-in works (from /api/session): Duo, and configuration problems that block every sign-in.
  render(auth) {
    $('#loginIntro').textContent = auth.sso
      ? 'Active Directory accounts sign in with Duo SSO.' + (auth.ad_password ? ' The form below takes an AD or local portal account.' : ' The form below is for local portal accounts.')
      : 'Use your Active Directory account or a local portal account.' + (auth.ad_push
        ? ' With an AD account, approve the Duo Push on your phone after you select Sign in (or type a Duo passcode after'
          + ' your password, separated by a comma).'
        : auth.duo ? ' You may be asked to approve the sign-in with Duo.' : '');
    $('#ssoBlock').hidden = !auth.sso;
    $('#ssoLabel').textContent = auth.sso_label || 'Sign in with Duo SSO';
    $('#ssoDivider').textContent = auth.ad_password ? 'or with a password' : 'or with a local portal account';
    $('#loginBtn').classList.toggle('pf-m-primary', !auth.sso);
    $('#loginBtn').classList.toggle('pf-m-secondary', Boolean(auth.sso));
    const problems = auth.problems || [];
    const title = auth.sso ? 'Duo SSO is not configured correctly'
      : auth.local_accounts ? 'Active Directory sign-in is not configured yet' : 'Sign-in is not configured yet';
    const hint = auth.local_accounts ? '<p>Local portal accounts can still sign in.</p>'
      : '<p>Or create a local administrator on the server: <code>sudo /opt/ops-portal/deploy/local-admin.sh add &lt;name&gt;</code></p>';
    $('#loginNotice').innerHTML = problems.length ? alertBox('warning', title,
      `<ul>${problems.map(p => `<li>${esc(p)}</li>`).join('')}</ul>${hint}`) : '';
  },
  error(message) {
    $('#loginError').hidden = !message;
    $('#loginError').innerHTML = message ? `${icon('x-circle')}<div class="pf-alert__title">${esc(message)}</div>` : '';
  },
  info(message) {
    $('#loginInfo').hidden = !message;
    $('#loginInfo').innerHTML = message ? `${icon('info')}<div class="pf-alert__title">${esc(message)}</div>` : '';
  },
  async submit(event) {
    event.preventDefault();
    const username = $('#loginUser').value.trim(), password = $('#loginPass').value;
    if (!username || !password) return this.error('Enter your username and password.');
    const btn = $('#loginBtn');
    btn.disabled = true;
    btn.classList.add('is-loading');
    this.error('');
    this.info(Session.auth.ad_push ? 'Signing in… With an AD account, approve the Duo Push on your phone now.' : '');
    let leaving = false;
    try {
      const data = await api('/api/login', {username, password});
      localStore.set('portal_user', username);
      $('#loginPass').value = '';
      if (data.redirect) {
        // Duo Universal Prompt: Duo sends the browser back to /auth/duo/callback, which opens the portal.
        leaving = true;
        this.info('Redirecting to Duo…');
        location.assign(data.redirect);
        return;
      }
      const status = await api('/api/session');
      if (!status.user) throw new Error('The sign-in did not start a session. Please try again.');
      Session.enter(status);
    } catch (e) {
      this.info('');
      this.error(e.message);
    } finally {
      if (!leaving) {
        btn.disabled = false;
        btn.classList.remove('is-loading');
      }
    }
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
   Navigation (hash): #/home, #/users, #/credentials
   ========================================================================= */
const ADMIN_PAGES = ['users', 'credentials'];
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
    const [, section = 'home'] = (location.hash.match(/^#\/([a-z]+)/) || []);
    const page = ADMIN_PAGES.includes(section) ? section : 'home';
    if (ADMIN_PAGES.includes(page) && !Session.isAdmin()) return location.replace('#/home');
    $$('[data-page]').forEach(el => { el.hidden = el.dataset.page !== page; });
    $$('.pf-nav__link[data-route]').forEach(a => a.classList.toggle('is-current', a.dataset.route === page));
    $('#portalLauncher').dataset.current = page;
    document.title = page === 'home' ? BASE_TITLE : `${page === 'users' ? 'Users' : 'Credentials'} · ${BASE_TITLE}`;
    if (page === 'home') Session.refresh();
    if (page === 'users') run(null, () => Users.load());
    if (page === 'credentials') Credentials.enter();
    window.scrollTo(0, 0);
  },
};

/* =========================================================================
   Home: the modules of this account (PatternFly card view)
   ========================================================================= */
const Home = {
  render(status) {
    const user = status.user;
    const modules = status.modules || [];
    $('#homeTitle').textContent = `Welcome, ${user.display_name || user.username}`;
    $('#navModules').innerHTML = modules.filter(m => m.allowed).map(m => `<li><a class="pf-nav__link" href="${esc(m.url)}">`
      + `${icon(MODULE_ICONS[m.icon] || 'checklist')}${esc(m.title)}</a></li>`).join('')
      || '<li><span class="pf-nav__link pf-text-secondary">No modules</span></li>';
    // A module this account may not use stays visible (so the operator knows it exists) but cannot be opened.
    $('#moduleGallery').innerHTML = modules.map(m => {
      const labels = [];
      if (!m.allowed) labels.push(`<span class="pf-label">${icon('lock')}No access</span>`);
      if (m.running) labels.push(`<span class="pf-label pf-m-blue">${icon('in-progress')}${m.running} running</span>`);
      const body = `<div class="pf-card__header"><div class="pf-card__header-main"><span class="pf-card__icon">${icon(MODULE_ICONS[m.icon] || 'checklist')}</span>`
        + `<h2 class="pf-card__title">${esc(m.title)}</h2></div></div>`
        + `<div class="pf-card__body"><p class="pf-text-secondary">${esc(m.description)}</p></div>`
        + `<div class="pf-card__footer">${labels.join('') || `<span class="pf-btn pf-m-link pf-m-inline">Open ${icon('angle-right')}</span>`}</div>`;
      return m.allowed
        ? `<a class="pf-card pf-m-clickable" role="listitem" href="${esc(m.url)}">${body}</a>`
        : `<div class="pf-card pf-m-disabled" role="listitem" aria-disabled="true" title="Ask an administrator for access">${body}</div>`;
    }).join('') || `<div class="pf-card"><div class="pf-empty-state">${icon('cubes')}<h2 class="pf-title">No modules</h2></div></div>`;
  },
};

/* =========================================================================
   Administration: Users (role and module access) and the activity log
   ========================================================================= */
const EVENT_LABELS = {
  'login.success': 'Signed in', 'login.failed': 'Sign-in failed', 'login.denied': 'Sign-in denied', logout: 'Signed out',
  'login.duo_failed': 'Duo failed', 'login.duo_unavailable': 'Duo unreachable', 'login.duo_bypassed': 'Duo bypassed',
  'login.sso_failed': 'Duo SSO failed',
  'user.add': 'User added', 'user.update': 'User changed', 'user.remove': 'User removed',
  'local.add': 'Local account added', 'local.passwd': 'Local password changed', 'local.enable': 'Local account enabled',
  'local.disable': 'Local account disabled', 'local.remove': 'Local account removed', 'local.duo': 'Local account Duo changed',
  'local.modules': 'Local account modules changed',
  'credential.set': 'Credential set', 'credential.remove': 'Credential removed',
  'wi.run': 'Operation check started', 'wi.ok': 'Operation check: OK', 'wi.warn': 'Operation check: warning', 'wi.fail': 'Operation check: problem found',
  'wi.error': 'Operation check could not run',
  'restore.start': 'Restore started', 'restore.done': 'Restore finished', 'restore.partial': 'Restore finished, action failed',
  'restore.failed': 'Restore failed', 'restore.unknown': 'Restore interrupted',
  'restore.group_start': 'Group restore started', 'restore.group_done': 'Group restore finished',
  'restore.group_partial': 'Group restore finished, an action failed', 'restore.group_failed': 'Group restore stopped',
  'deletion.schedule': 'Deletion scheduled', 'deletion.approve': 'Deletion approved', 'deletion.done': 'Original volume deleted',
  'deletion.failed': 'Deletion failed', 'deletion.keep': 'Original volume kept', 'deletion.postpone': 'Deletion postponed',
  'static_port.applied': 'Static port applied', 'static_port.failed': 'Static port failed', 'static_port.unknown': 'Static port unknown',
  'static_port.undone': 'Static port undone', 'provisioning.applied': 'Provisioning applied', 'provisioning.failed': 'Provisioning failed',
  'provisioning.unknown': 'Provisioning unknown',
  'static_port.template_saved': 'ACI template saved', 'static_port.template_reset': 'ACI template reset',
  'static_port.product_added': 'ACI product added', 'static_port.product_changed': 'ACI product changed',
  'static_port.product_deleted': 'ACI product deleted',
};
const EVENT_COLORS = {'login.failed': 'red', 'login.denied': 'red', 'login.duo_failed': 'red', 'login.duo_unavailable': 'red', 'login.duo_bypassed': 'gold',
  'login.sso_failed': 'red', 'wi.run': 'blue', 'wi.ok': 'green', 'wi.warn': 'gold', 'wi.fail': 'red', 'wi.error': 'red',
  'deletion.approve': 'gold', 'deletion.done': 'red', 'deletion.failed': 'red',
  'restore.start': 'blue', 'restore.done': 'green', 'restore.partial': 'gold', 'restore.failed': 'red', 'restore.unknown': 'gold',
  'restore.group_start': 'blue', 'restore.group_done': 'green', 'restore.group_partial': 'gold', 'restore.group_failed': 'red',
  'static_port.applied': 'green', 'static_port.failed': 'red', 'static_port.unknown': 'gold', 'static_port.undone': 'gold',
  'provisioning.applied': 'green', 'provisioning.failed': 'red', 'provisioning.unknown': 'gold',
  'static_port.template_saved': 'blue', 'static_port.template_reset': 'blue', 'static_port.product_added': 'blue',
  'static_port.product_changed': 'blue', 'static_port.product_deleted': 'gold'};

// Module checkboxes of the Add user and Module access dialogs.
// A permission inside a module (e.g. running fixes) is indented under its module and only counts with that module.
function moduleChecks(modules, checked, legend = 'Modules') {
  return `<legend>${esc(legend)}</legend>` + modules.map(m => `<label class="pf-check${m.permission_of ? ' pf-m-sub' : ''}"><input type="checkbox" value="${esc(m.id)}"`
    + `${checked.includes(m.id) ? ' checked' : ''}${m.permission_of ? ` data-permission-of="${esc(m.permission_of)}"` : ''}><span>${esc(m.title)}</span></label>`).join('')
    + '<span class="pf-helper-text">Administrators always use every module and have every permission.</span>';
}
// A permission needs its module: ticking it ticks the module, unticking the module unticks its permissions.
document.addEventListener('change', e => {
  const box = e.target;
  if (!(box instanceof HTMLInputElement) || box.type !== 'checkbox') return;
  const list = box.closest('fieldset, .pf-check-list') || box.form;
  if (!list) return;
  if (box.dataset.permissionOf && box.checked) {
    const parent = list.querySelector(`input[value="${CSS.escape(box.dataset.permissionOf)}"]`);
    if (parent) parent.checked = true;
  }
  if (!box.dataset.permissionOf && !box.checked) {
    list.querySelectorAll(`input[data-permission-of="${CSS.escape(box.value)}"]`).forEach(p => { p.checked = false; });
  }
});

const Users = {
  list: [],
  modules: [],
  me: '',
  editing: null,
  init() {
    $('#addUserBtn').addEventListener('click', () => this.openAdd());
    $('#addUserForm').addEventListener('submit', e => { e.preventDefault(); this.add(); });
    $('#addUserRole').addEventListener('change', () => this.roleChanged());
    $('#modulesForm').addEventListener('submit', e => { e.preventDefault(); this.saveModules(); });
    $('#userList').addEventListener('click', e => {
      const btn = e.target.closest('button[data-act]');
      if (btn) this.act(btn.dataset.user, btn.dataset.act, btn.dataset.value, btn);
    });
    ['#evUser', '#evKind', '#evSince', '#evUntil'].forEach(sel => $(sel).addEventListener('change', () => run(null, () => this.loadEvents())));
    $('#evMoreBtn').addEventListener('click', e => run(e.currentTarget, () => this.loadEvents(true)));
    // Every matching entry (not only the ones on the page), for an audit.
    $('#evExportBtn').addEventListener('click', e => run(e.currentTarget, () => downloadFile(`/export/events.csv?${qs(this.eventFilters())}`, 'activity.csv')));
  },
  async load() {
    const [users] = await Promise.all([api('/api/admin/users'), this.loadEvents()]);
    this.list = users.users;
    this.modules = users.modules || [];
    this.me = users.me;
    this.meSource = users.me_source || 'ad';
    this.render();
  },
  // Activity log: newest first, 50 at a time, optionally one user and one kind of activity.
  events: [],
  eventFilters() {
    return {actor: $('#evUser').value, kinds: $('#evKind').value, since: $('#evSince').value, until: $('#evUntil').value};
  },
  async loadEvents(more = false) {
    const last = this.events[this.events.length - 1];
    const data = await api(`/api/admin/events?${qs({limit: 50, ...this.eventFilters(), before: more && last ? last.id : ''})}`);
    this.events = more ? [...this.events, ...data.events] : data.events;
    const current = $('#evUser').value;
    $('#evUser').innerHTML = '<option value="">All users</option>'
      + data.actors.map(a => `<option${a === current ? ' selected' : ''}>${esc(a)}</option>`).join('');
    $('#evMore').hidden = !data.more;
    this.renderEvents(this.events);
  },
  moduleLabels(u) {
    if (u.role === 'admin' || u.all_modules) return '<span class="pf-label pf-m-blue">All modules</span>';
    const names = this.modules.filter(m => (u.modules || []).includes(m.id)).map(m => `<span class="pf-label">${esc(m.title)}</span>`);
    return names.length ? `<span class="module-labels">${names.join('')}</span>` : '<span class="pf-label pf-m-gold">None</span>';
  },
  // Administrators from auth.yml, local portal accounts (managed on the server) and your own account have no actions.
  render() {
    $('#userCount').textContent = `${this.list.length} ${this.list.length === 1 ? 'user' : 'users'}`;
    $('#userList').innerHTML = this.list.map(u => {
      const local = u.source === 'local';
      const mine = u.username === this.me && (u.source || 'ad') === this.meSource;
      const actions = local ? '<span class="pf-text-secondary pf-text-sm">Managed on the server</span>' : u.builtin || mine ? '' : [
        u.role === 'admin' ? null : ['modules', '', 'Modules'],
        u.role === 'admin' ? ['role', 'operator', 'Make operator'] : ['role', 'admin', 'Make administrator'],
        u.enabled ? ['enabled', 'false', 'Disable'] : ['enabled', 'true', 'Enable'],
        ['remove', '', 'Remove'],
      ].filter(Boolean).map(([act, value, label]) => `<button type="button" class="pf-btn pf-m-link pf-m-inline${act === 'remove' ? ' pf-m-danger' : ''}"`
        + ` data-act="${act}" data-value="${value}" data-user="${esc(u.username)}">${label}</button>`).join('');
      return `<tr><td class="pf-nowrap"><span class="mono">${esc(u.username)}</span>${mine ? ' <span class="pf-label pf-m-blue">You</span>' : ''}</td>`
        + `<td>${esc(u.display_name || '-')}</td>`
        + `<td class="pf-nowrap">${esc(ROLE_LABELS[u.role] || u.role)}${u.builtin ? ' <span class="pf-label">Built-in (auth.yml)</span>' : ''}`
        + (local ? ` <span class="pf-label pf-m-blue">Local account</span> <span class="pf-label${u.mfa === 'duo' ? '' : ' pf-m-gold'}">${u.mfa === 'duo' ? 'Duo' : 'Password only'}</span>` : '') + '</td>'
        + `<td>${this.moduleLabels(u)}</td>`
        + `<td>${u.enabled ? '<span class="pf-label pf-m-green">Enabled</span>' : '<span class="pf-label pf-m-gold">Disabled</span>'}</td>`
        + `<td class="pf-nowrap" title="${esc(u.last_login ? fmtTime(u.last_login) : '')}">${u.last_login ? esc(shortTime(u.last_login)) : 'Never'}</td>`
        + `<td class="pf-nowrap">${esc(u.created_by || '-')}${u.created ? `<span class="pf-table__sub">${esc(shortTime(u.created))}</span>` : ''}</td>`
        + `<td class="pf-table__actions"><div class="user-actions">${actions}</div></td></tr>`;
    }).join('') || `<tr><td colspan="8"><div class="pf-empty-state">${icon('users')}<h2 class="pf-title">No users yet</h2><span>Add the AD accounts that may sign in.</span></div></td></tr>`;
  },
  renderEvents(events) {
    $('#eventCount').textContent = events.length ? `Latest ${events.length}` : '';
    $('#eventList').innerHTML = events.map(ev => {
      const label = esc(EVENT_LABELS[ev.action] || ev.action);
      // "restore #12" opens that ONTAP Restore job, "Operation run #5" (earlier "Troubleshooting run #5") that Operation Automation run, "change #3" that ACI change.
      const detail = esc(ev.detail || '').replace(/\brestore group #(\d+)/g, '<a href="/ontap/#/groups/$1">restore group #$1</a>')
        .replace(/\(group #(\d+)\)/g, '(<a href="/ontap/#/groups/$1">group #$1</a>)').replace(/\brestore #(\d+)/g, '<a href="/ontap/#/jobs/$1">restore #$1</a>')
        .replace(/\b(Troubleshooting|Operation) run #(\d+)/g, '<a href="/wi/#/runs/$2">$1 run #$2</a>').replace(/\bchange #(\d+)/g, '<a href="/aci/#audit">change #$1</a>');
      const [ip, ...rest] = String(ev.client_ip || '').split(' (');
      const extra = rest.join(' (').replace(/\)$/, '').split(', ').filter(Boolean);
      return `<tr><td class="pf-nowrap">${esc(fmtTime(ev.ts))}</td><td class="pf-nowrap mono">${esc(ev.actor)}</td>`
        + `<td class="ev-action">${EVENT_COLORS[ev.action] ? `<span class="pf-label pf-m-${EVENT_COLORS[ev.action]}">${label}</span>` : label}</td>`
        + `<td class="mono ev-target">${esc(ev.target || '')}</td><td class="ev-detail">${detail}</td>`
        + `<td class="mono ev-client"><span class="pf-nowrap">${esc(ip)}</span>${extra.map(x => `<span class="pf-table__sub pf-nowrap">${esc(x)}</span>`).join('')}</td></tr>`;
    }).join('') || `<tr><td colspan="6"><div class="pf-empty-state"><span>${Object.values(this.eventFilters()).some(Boolean)
      ? 'No activity matches these filters.' : 'No activity yet.'}</span></div></td></tr>`;
  },
  async act(username, act, value, btn) {
    const url = `/api/admin/users/${encodeURIComponent(username)}`;
    if (act === 'modules') return this.openModules(this.list.find(u => u.username === username && u.source !== 'local'));
    if (act === 'remove') {
      if (!(await Confirm.ask('Remove user', `Remove ${username}? They can no longer sign in.`))) return;
      return run(btn, async () => {
        await api(url, undefined, 'DELETE');
        toast(`${username} was removed.`, 'success');
        await this.load();
      });
    }
    const body = act === 'role' ? {role: value} : {enabled: value === 'true'};
    const done = act === 'role' ? `${username} is now ${value === 'admin' ? 'an administrator' : 'an operator'}.`
      : body.enabled ? `${username} can sign in again.` : `${username} is disabled and was signed out.`;
    return run(btn, async () => {
      await api(url, body);
      toast(done, 'success');
      await this.load();
    });
  },
  checked(root) { return $$('input[type=checkbox]:checked', root).map(i => i.value); },
  openAdd() {
    $('#addUserName').value = '';
    $('#addUserRole').value = 'operator';
    // A new operator starts with Operation Automation only (read-only); the administrator ticks more when needed.
    $('#addUserModules').innerHTML = moduleChecks(this.modules, this.modules.some(m => m.id === 'wi') ? ['wi'] : []);
    this.roleChanged();
    this.addError('');
    $('#addUserDialog').showModal();
    $('#addUserName').focus();
  },
  roleChanged() {
    const admin = $('#addUserRole').value === 'admin';
    $$('#addUserModules input').forEach(i => { i.disabled = admin; });
  },
  addError(message) {
    $('#addUserError').hidden = !message;
    $('#addUserError').innerHTML = message ? `${icon('x-circle')}<div class="pf-alert__title">${esc(message)}</div>` : '';
  },
  async add() {
    const username = $('#addUserName').value.trim(), role = $('#addUserRole').value;
    const modules = role === 'admin' ? '*' : this.checked($('#addUserModules'));
    if (!username) return this.addError('Enter the AD username.');
    if (role !== 'admin' && !modules.length) return this.addError('Tick at least one module.');
    const btn = $('#addUserSave');
    btn.disabled = true;
    btn.classList.add('is-loading');
    this.addError('');
    try {
      const {user} = await api('/api/admin/users', {username, role, modules});
      $('#addUserDialog').close();
      toast(`${user.username} was added as ${role === 'admin' ? 'administrator' : 'operator'}.`, 'success');
      run(null, () => this.load());
    } catch (e) {
      this.addError(e.message);
    } finally {
      btn.disabled = false;
      btn.classList.remove('is-loading');
    }
  },
  openModules(user) {
    if (!user) return;
    this.editing = user;
    $('#modulesTitle').textContent = `Module access of ${user.username}`;
    $('#modulesList').innerHTML = moduleChecks(this.modules, user.modules || [], 'Modules this operator may use');
    this.modulesError('');
    $('#modulesDialog').showModal();
    $('#modulesList input')?.focus();
  },
  modulesError(message) {
    $('#modulesError').hidden = !message;
    $('#modulesError').innerHTML = message ? `${icon('x-circle')}<div class="pf-alert__title">${esc(message)}</div>` : '';
  },
  async saveModules() {
    const user = this.editing, modules = this.checked($('#modulesList'));
    if (!modules.length) return this.modulesError('Tick at least one module.');
    const btn = $('#modulesSave');
    btn.disabled = true;
    btn.classList.add('is-loading');
    try {
      await api(`/api/admin/users/${encodeURIComponent(user.username)}`, {modules});
      $('#modulesDialog').close();
      toast(`Module access of ${user.username} was changed.`, 'success');
      run(null, () => this.load());
    } catch (e) {
      this.modulesError(e.message);
    } finally {
      btn.disabled = false;
      btn.classList.remove('is-loading');
    }
  },
};

/* =========================================================================
   Administration: Credentials (service accounts of every module, write-only)
   ========================================================================= */
const CREDENTIAL_HELP = {
  apic: 'The account needs the APIC REST API (read and write for the tenants the ACI module changes).',
  ontap: 'The account needs the ONTAP REST API, including the CLI passthrough for volume snapshot restore-file. Operation Automation reads the cluster with it too (GET requests only) and uses it for the ONTAP fixes.',
  'ro-vcenter': 'Read-only vCenter account (role Read-only, propagated from the vCenter root) for Operation Automation: REST API and the inventory read (hosts, VMs, resource pools, clusters).',
  'ro-vcd': 'Read-only vCloud Director provider account (a provider role with View rights only), one for every site (one vCloud Director serves DCB, DCA and DCC): VMs, tasks, cells, Org VDCs, networks, edge gateways. Provider accounts sign in as user@System: @System is added when you leave it out.',
  'ro-nsxt': 'Read-only NSX-T Manager account (role Auditor) for Operation Automation.',
};
const Credentials = {
  items: [],
  target: null,
  siteColors: {},
  init() {
    $('#credForm').addEventListener('submit', e => { e.preventDefault(); this.save(); });
    $('#credDialog').addEventListener('close', () => { $('#credPass').value = ''; });
    $('#credList').addEventListener('click', e => {
      const btn = e.target.closest('button[data-act]');
      if (btn) this.act(btn.dataset.name, btn.dataset.act, btn);
    });
  },
  enter() {
    this.notice('');
    run(null, () => this.load());
  },
  async load() {
    this.items = (await api('/api/admin/credentials')).credentials;
    const sites = [...new Set(this.items.map(c => c.site).filter(Boolean))];
    this.siteColors = Object.fromEntries(sites.map((s, i) => [s, SITE_COLORS[i % SITE_COLORS.length]]));
    this.render();
  },
  // One group per module (like the grouped rows of the Cinder pool table), in module order.
  render() {
    const button = (c, act, label, extra = '') => `<button type="button" class="pf-btn pf-m-link pf-m-inline${extra}" data-act="${act}" data-name="${esc(c.name)}">${label}</button>`;
    let group = '';
    $('#credList').innerHTML = this.items.map(c => {
      const head = c.module_title !== group ? `<tr class="pf-table__group"><td colspan="6">${esc(c.module_title || 'Portal')}</td></tr>` : '';
      group = c.module_title;
      return head + `<tr>`
        + `<td class="pf-nowrap"><span class="site-dot" style="--site-color:${this.siteColors[c.site] || '#8a8d90'}"></span> ${esc(c.label)}</td>`
        + `<td class="mono">${esc(c.host || '-')}${c.address ? `<span class="pf-table__sub">${c.address_set ? 'set here' : c.host ? 'from sites.yml' : 'not set'}</span>` : ''}</td><td class="mono">${esc(c.username || '-')}</td>`
        + `<td class="pf-nowrap">${c.updated ? `${esc(fmtTime(c.updated))}<span class="pf-table__sub">by ${esc(c.updated_by)}</span>` : '-'}</td>`
        + `<td>${c.configured ? `<span class="pf-label pf-m-green">${icon('check-circle')}Configured</span>` : `<span class="pf-label pf-m-gold">${icon('alert')}Not set</span>`}</td>`
        + `<td class="pf-table__actions">${button(c, 'set', c.configured ? 'Change' : 'Set')}`
        + (c.configured ? button(c, 'test', 'Test') + button(c, 'remove', 'Remove', ' pf-m-danger') : '') + '</td></tr>';
    }).join('')
      || `<tr><td colspan="6"><div class="pf-empty-state">${icon('key')}<h2 class="pf-title">No sites</h2><span>Add the sites to sites.yml on the server first.</span></div></td></tr>`;
  },
  // Result of a save or a connection test; stays above the table until the next action.
  notice(kind, text = '', c = null) {
    $('#credNotice').innerHTML = kind ? alertBox(kind, esc(text), c ? esc(`${c.label} · ${c.host}`) : '') : '';
  },
  async act(name, act, btn) {
    const c = this.items.find(x => x.name === name);
    if (!c) return;
    if (act === 'set') return this.open(c);
    if (act === 'test') {
      return run(btn, async () => {
        const {test} = await api(`/api/admin/credentials/${encodeURIComponent(name)}/test`, {});
        if (test.ok === false) this.notice('warning', `Connection test failed: ${test.message}`, c);
        else this.notice('success', `Connection test: ${test.message}`, c);
      });
    }
    if (act === 'remove') {
      if (!(await Confirm.ask('Remove credentials', `Remove the ${c.label} service account? ${c.module_title} cannot reach it on ${c.site ? `site ${c.site}` : 'any site'} until it is set again.`))) return;
      return run(btn, async () => {
        await api(`/api/admin/credentials/${encodeURIComponent(name)}`, undefined, 'DELETE');
        this.notice('');
        toast(`The ${c.label} service account was removed.`, 'success');
        await this.load();
      });
    }
  },
  open(c) {
    this.target = c;
    $('#credTitle').textContent = `Set credentials for ${c.label}`;
    $('#credInfo').textContent = `${c.module_title}, ${c.site ? `site ${c.site}` : 'every site'}${c.address ? '' : `, host ${c.host || '(no host in sites.yml)'}`}. ${CREDENTIAL_HELP[c.kind] || ''}`;
    $('#credAddrGroup').hidden = !c.address;
    $('#credAddr').value = c.address ? (c.address_set ? c.host : '') : '';
    $('#credAddr').placeholder = c.host_default ? `${c.host_default} (sites.yml)` : 'IP address or DNS name, e.g. 172.26.8.20';
    $('#credAddrReq').hidden = !!c.host_default;
    $('#credAddrHelp').textContent = 'HTTPS, optionally with :port. You can paste the address bar of its console: only the host is kept.' + (c.host_default ? ' Leave empty to use the address in sites.yml.' : '')
      + (c.configured ? ' When the address changes, enter the password again.' : '');
    $('#credUser').value = c.username || '';
    $('#credPass').value = '';
    $('#credPassReq').hidden = c.configured;
    $('#credPassHelp').textContent = c.configured ? 'Leave empty to keep the stored password. It is never shown again.'
      : 'The password is stored encrypted and is never shown again.';
    this.error('');
    $('#credDialog').showModal();
    (c.address && !c.host ? $('#credAddr') : $('#credUser').value ? $('#credPass') : $('#credUser')).focus();
  },
  error(message) {
    $('#credError').hidden = !message;
    $('#credError').innerHTML = message ? `${icon('x-circle')}<div class="pf-alert__title">${esc(message)}</div>` : '';
  },
  async save() {
    const c = this.target, username = $('#credUser').value.trim(), password = $('#credPass').value;
    const address = normalizeAddress($('#credAddr').value);
    if (c.address && !address && !c.host_default) return this.error(`Enter the address of ${c.label}.`);
    if (!username || (!password && !c.configured)) return this.error('Enter the service account username and password.');
    const btn = $('#credSave');
    btn.disabled = true;
    btn.classList.add('is-loading');
    this.error('');
    try {
      const {test} = await api(`/api/admin/credentials/${encodeURIComponent(c.name)}`, {username, password, ...(c.address ? {address} : {})});
      $('#credDialog').close();
      const shown = c.address ? {...c, host: address || c.host_default} : c;
      if (test.ok === false) this.notice('warning', `Saved, but the connection test failed: ${test.message}`, shown);
      else this.notice('success', `Saved. Connection test: ${test.message}`, shown);
      run(null, () => this.load());
    } catch (e) {
      this.error(e.message);
    } finally {
      btn.disabled = false;
      btn.classList.remove('is-loading');
    }
  },
};

/* =========================================================================
   Start
   ========================================================================= */
document.addEventListener('DOMContentLoaded', async () => {
  Login.init();
  UserMenu.init();
  Users.init();
  Credentials.init();
  Router.init();
  document.addEventListener('click', e => { const b = e.target.closest('dialog [data-close]'); if (b) b.closest('dialog').close(); });
  Next.remember();
  // Duo sends the browser back to /?auth_error=<reason> when the sign-in was not completed.
  const params = new URLSearchParams(location.search);
  const authError = params.get('auth_error');
  if (authError !== null) {
    params.delete('auth_error');
    const query = params.toString();
    history.replaceState(null, '', `${location.pathname}${query ? `?${query}` : ''}${location.hash}`);
  }
  if (!location.hash) history.replaceState(null, '', '#/home');
  try {
    const status = await (await fetch('/api/session')).json();
    if (status.user) {
      Session.enter(status);
      if (authError) toast(authError);
    } else {
      Session.update(status);
      if (authError) Login.error(authError);
    }
  } catch (e) {
    Session.showLogin();
    toast('Cannot reach the portal server.');
  }
});

'use strict';

/* =========================================================================
   Utilities
   ========================================================================= */
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
const qs = params => Object.entries(params).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v ?? '')}`).join('&');
const icon = (name, cls = '') => `<svg class="icon ${cls}" aria-hidden="true"><use href="#i-${name}"></use></svg>`;
// Ask the modules to recompute button states and context after data changed.
const refreshUi = () => document.dispatchEvent(new Event('ui:refresh'));

function storage(area) {
  return {
    get(key) { try { return window[area].getItem(key); } catch (e) { return null; } },
    set(key, value) { try { window[area].setItem(key, value); } catch (e) { /* storage not available */ } },
  };
}
const tabStore = storage('sessionStorage');   // per browser tab: last site & page
const localStore = storage('localStorage');   // per browser: defaults for new rows

// Every request of this page goes to the ACI module of the portal (/aci/...); sign-in and sign-out are the portal's.
const BASE = '/aci';
const BASE_TITLE = document.title;
const UI_VERSION = document.querySelector('meta[name="ui-version"]')?.content || '';
// PatternFly palette (dark enough for white text on the site markers): blue, green, purple, orange, red, cyan.
const SITE_COLORS = ['#0066cc', '#3e8635', '#6753ac', '#8f4700', '#a30000', '#005f60'];
const MODES = [['regular', 'Trunk'], ['native', 'Access (802.1P)'], ['untagged', 'Access (Untagged)']];
const IMMEDIACY = [['immediate', 'Immediate'], ['lazy', 'On Demand']];
const SCOPES = [['public', 'Public'], ['private', 'Private'], ['public,shared', 'Public + Shared'], ['private,shared', 'Private + Shared']];
const MODE_LABEL = Object.fromEntries(MODES);
const IMMEDIACY_LABEL = Object.fromEntries(IMMEDIACY);
const MODE_ALIASES = {trunk: 'regular', regular: 'regular', native: 'native', access_8021p: 'native', '802.1p': 'native',
  untagged: 'untagged', access: 'untagged', access_untagged: 'untagged'};
const PATH_TDN = /^topology\/pod-\d+\/(?:paths-\d+(?:\/extpaths-\d+)?|protpaths-\d+-\d+(?:\/extprotpaths-\d+-\d+)?)\/pathep-\[[^[\]]+\]$/;
const SIMPLE_PHYSICAL = /^topology\/pod-(\d+)\/paths-(\d+)\/pathep-\[([^[\]]+)\]$/;
const SUBNET = /^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]*:[0-9a-f:.]*)\/\d{1,3}$/i;

function rgba(hex, alpha) {
  const n = parseInt(hex.slice(1), 16);
  return `rgba(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255}, ${alpha})`;
}
function alertBox(kind, html) {
  const name = {danger: 'alert', warning: 'alert', success: 'check', info: 'info'}[kind];
  return `<div class="alert alert-${kind}"${kind === 'danger' ? ' role="alert"' : ''}>${icon(name)}<div>${html}</div></div>`;
}
// Hint under a VLAN field: in use by another EPG (red), free (green), checking, or the normal text.
function vlanHint(el, check, normal = '') {
  if (!el) return;
  el.classList.toggle('hint-error', !!check.blocked);
  el.classList.toggle('hint-ok', !!check.free);
  el.textContent = check.text || normal;
}
function crumbs(parts) {
  return parts.filter(Boolean).map((p, i, all) => (i === all.length - 1 ? `<b>${esc(p)}</b>` : esc(p))).join(icon('chevron-right'));
}
const int = v => /^\d+$/.test(String(v ?? '').trim());
const validVlan = v => int(v) && Number(v) >= 1 && Number(v) <= 4094;
// Number + English noun: plural(1, 'path') = "1 path", plural(3, 'path') = "3 paths".
const plural = (n, word, many = `${word}s`) => `${n} ${Number(n) === 1 ? word : many}`;

/* =========================================================================
   Requests, notifications, busy state
   ========================================================================= */
const Busy = {
  count: 0,
  start() { this.count += 1; document.body.classList.add('is-busy'); },
  stop() { this.count = Math.max(0, this.count - 1); if (!this.count) document.body.classList.remove('is-busy'); },
};

async function request(url, init = {}) {
  Busy.start();
  try { return await fetch(url, init); } finally { Busy.stop(); }
}

function withSite(url) { return url + (url.includes('?') ? '&' : '?') + 'site=' + encodeURIComponent(Site.current); }

// JSON request to the module (url without the /aci prefix). 401 = the sign-in has ended (the portal sign-in opens,
// without an extra toast); 403 = the role or the module access may have changed (the session is reloaded, so the
// menu matches the role, or the page shows that the account has no access to ACI any more).
async function callApi(url, {method, body} = {}) {
  const init = {method: method || (body === undefined ? 'GET' : 'POST')};
  if (body !== undefined) {
    init.headers = {'Content-Type': 'application/json'};
    init.body = JSON.stringify(body);
  }
  const res = await request(BASE + url, init);
  let data;
  try { data = await res.json(); } catch (e) { throw new Error(`Web UI server error (HTTP ${res.status})`); }
  if (!data.ok) {
    const error = new Error(data.error || `HTTP ${res.status}`);
    if (res.status === 401) {
      error.signedOut = true;
      Session.ended(data.error, data.session);
    } else if (res.status === 403) {
      Session.refresh().catch(() => {});
    }
    throw error;
  }
  return data;
}

// Every data request carries the selected site; the server keeps no "active site".
const api = (url, body) => callApi(withSite(url), {body});

// Error toast, except when the sign-in ended: the page goes to the portal sign-in.
function notifyError(e) {
  if (!e.signedOut) toast(e.message);
}

// Toast (PatternFly alert group). With action {label, fn} it stays until closed or until the action is clicked.
function toast(message, kind = 'error', action = null) {
  const el = document.createElement('div');
  el.className = `toast toast-${kind}`;
  el.setAttribute('role', kind === 'error' ? 'alert' : 'status');
  el.innerHTML = `${icon({error: 'alert', success: 'check', info: 'info'}[kind])}<div class="toast-text"></div>`
    + `<button type="button" class="btn-icon" aria-label="Close notification">${icon('x')}</button>`;
  $('.toast-text', el).textContent = message;
  $('.btn-icon', el).addEventListener('click', () => el.remove());
  if (action) {
    const link = document.createElement('button');
    link.type = 'button';
    link.className = 'btn btn-link-inline toast-action';
    link.textContent = action.label;
    link.addEventListener('click', action.fn);
    $('.toast-text', el).appendChild(link);
  }
  $('#toasts').appendChild(el);
  if (!action) setTimeout(() => el.remove(), kind === 'error' ? 10000 : 5000);
}

// Confirmation in a PatternFly modal (instead of the browser's confirm()). Resolves to true when confirmed.
function confirmDialog({title, body, confirmLabel, danger = false}) {
  const dialog = $('#confirmDialog');
  $('#confirmTitle').textContent = title;
  $('#confirmBody').textContent = body;
  const ok = $('#confirmOk');
  ok.textContent = confirmLabel;
  ok.className = `btn ${danger ? 'btn-danger' : 'btn-primary'}`;
  return new Promise(resolve => {
    const done = value => {
      ok.removeEventListener('click', yes);
      dialog.removeEventListener('close', no);
      if (dialog.open) dialog.close();
      resolve(value);
    };
    const yes = () => done(true);
    const no = () => done(false);
    ok.addEventListener('click', yes);
    dialog.addEventListener('close', no);
    dialog.showModal();
    $('#confirmCancel').focus();
  });
}

// Run an async action with the button in loading state; errors are shown as a toast.
async function run(button, fn) {
  if (button) {
    button.disabled = true;
    button.classList.add('is-loading');
    button.setAttribute('aria-busy', 'true');
  }
  try {
    return await fn();
  } catch (e) {
    notifyError(e);
  } finally {
    if (button) {
      button.disabled = false;
      button.classList.remove('is-loading');
      button.removeAttribute('aria-busy');
    }
    refreshUi();
  }
}

/* =========================================================================
   Form components
   ========================================================================= */
function fill(select, items, placeholder, value = x => x, label = x => x) {
  select.innerHTML = (placeholder === null ? '' : `<option value="">${esc(placeholder)}</option>`)
    + items.map(x => `<option value="${esc(value(x))}">${esc(label(x))}</option>`).join('');
  if (placeholder !== null) select.disabled = !items.length;
  if (select._combo) select._combo.sync();
}
function choose(select, value) {
  const found = !!value && [...select.options].some(o => o.value === value);
  if (found) select.value = value;
  if (select._combo) select._combo.sync();
  return found;
}
const radioValue = name => $(`input[name="${name}"]:checked`)?.value || '';
function setRadio(name, value) {
  const el = $(`input[name="${name}"][value="${value}"]`);
  if (el) el.checked = true;
}
const checkedValues = container => $$('input[type="checkbox"]:checked', container).map(i => i.value);

function highlight(text, query) {
  const i = query ? text.toLowerCase().indexOf(query) : -1;
  if (i < 0) return esc(text);
  return `${esc(text.slice(0, i))}<mark>${esc(text.slice(i, i + query.length))}</mark>${esc(text.slice(i + query.length))}`;
}

// Searchable combobox on top of a native <select>. The select stays the source of the value and of "change" events.
function combo(select) {
  const wrap = document.createElement('div');
  wrap.className = 'combo';
  select.before(wrap);
  wrap.appendChild(select);
  select.classList.add('combo-native');
  select.tabIndex = -1;
  select.setAttribute('aria-hidden', 'true');
  const input = document.createElement('input');
  Object.assign(input, {type: 'text', id: `${select.id}Combo`, className: 'input combo-input', autocomplete: 'off', spellcheck: false});
  input.setAttribute('role', 'combobox');
  input.setAttribute('aria-autocomplete', 'list');
  input.setAttribute('aria-expanded', 'false');
  const list = document.createElement('ul');
  Object.assign(list, {id: `${select.id}List`, className: 'combo-list', hidden: true});
  list.setAttribute('role', 'listbox');
  input.setAttribute('aria-controls', list.id);
  const caret = document.createElement('span');
  caret.className = 'combo-caret';
  caret.innerHTML = icon('chevron');
  wrap.append(input, caret, list);
  const label = $(`label[for="${select.id}"]`);
  if (label) label.htmlFor = input.id;
  const LIMIT = 200;

  const c = {
    matches: [],
    active: -1,
    selectedLabel() {
      const o = select.selectedOptions[0];
      return o && o.value ? o.textContent : '';
    },
    sync() {
      if (select.disabled && !list.hidden) c.close();
      input.disabled = select.disabled;
      const first = select.options[0];
      input.placeholder = first && !first.value ? first.textContent : '';
      if (list.hidden) input.value = c.selectedLabel();
      else c.render(input.value === c.selectedLabel() ? '' : input.value);
    },
    open(selectText = true) {
      if (input.disabled || !list.hidden) return;
      list.hidden = false;
      wrap.classList.add('is-open');
      input.setAttribute('aria-expanded', 'true');
      c.render('');
      if (selectText) input.select();
    },
    close() {
      list.hidden = true;
      wrap.classList.remove('is-open');
      input.setAttribute('aria-expanded', 'false');
      input.removeAttribute('aria-activedescendant');
      input.value = c.selectedLabel();
    },
    render(text) {
      const query = text.trim().toLowerCase();
      const all = [...select.options].map(o => ({value: o.value, label: o.textContent}));
      c.matches = query ? all.filter(o => o.value && o.label.toLowerCase().includes(query)) : all;
      const shown = c.matches.slice(0, LIMIT);
      list.innerHTML = shown.map((o, i) => `<li id="${list.id}-${i}" role="option" data-i="${i}" aria-selected="${o.value === select.value}"`
          + ` class="combo-option${o.value ? '' : ' is-placeholder'}">${highlight(o.label, query)}</li>`).join('')
        + (c.matches.length > shown.length ? `<li class="combo-note">${c.matches.length - shown.length} more — type to narrow the list</li>` : '')
        + (shown.length ? '' : '<li class="combo-note">No results found</li>');
      const current = shown.findIndex(o => o.value === select.value && o.value);
      c.move(query ? 0 : Math.max(current, 0));
    },
    move(i) {
      const items = $$('[role="option"]', list);
      if (!items.length) { c.active = -1; return; }
      c.active = (i + items.length) % items.length;
      items.forEach((el, n) => el.classList.toggle('is-active', n === c.active));
      input.setAttribute('aria-activedescendant', items[c.active].id);
      items[c.active].scrollIntoView({block: 'nearest'});
    },
    pick(i) {
      const option = c.matches[i];
      if (!option) return;
      const changed = select.value !== option.value;
      select.value = option.value;
      c.close();
      if (changed) select.dispatchEvent(new Event('change', {bubbles: true}));
    },
  };
  input.addEventListener('focus', () => c.open());
  input.addEventListener('click', () => c.open());
  input.addEventListener('blur', () => c.close());
  input.addEventListener('input', () => {
    c.open(false);
    c.render(input.value);
  });
  input.addEventListener('keydown', e => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      if (list.hidden) c.open();
      else c.move(c.active + (e.key === 'ArrowDown' ? 1 : -1));
    } else if (e.key === 'Enter' && !list.hidden) {
      e.preventDefault();
      c.pick(c.active);
    } else if (e.key === 'Escape' && !list.hidden) {
      e.preventDefault();
      c.close();
    }
  });
  // mousedown (not click), so the input does not blur before the choice is recorded.
  list.addEventListener('mousedown', e => {
    e.preventDefault();
    const li = e.target.closest('[data-i]');
    if (li) c.pick(Number(li.dataset.i));
  });
  select._combo = c;
  c.sync();
  return c;
}

/* =========================================================================
   Site, session, sign-in, user menu, navigation
   ========================================================================= */
const ROLE_LABEL = {admin: 'Administrator', operator: 'Operator'};
const initials = name => (/\s/.test(name.trim()) ? name.trim().split(/\s+/).slice(0, 2).map(w => w[0]).join('') : name.slice(0, 2));

const Site = {
  current: '',
  list: [],
  set(status) { this.list = (status.sites || []).map((x, i) => ({...x, color: SITE_COLORS[i % SITE_COLORS.length]})); },
  info(name) { return this.list.find(x => x.name === name) || {name, host: '', configured: false, error: '', color: SITE_COLORS[0]}; },
  style(name) { const color = this.info(name).color; return `--opt:${color};--opt-soft:${rgba(color, 0.08)}`; },
  label(name = this.current) { const x = this.info(name); return x.host ? `${x.name} (${x.host})` : name; },
  // Tooltip of a site: its APIC, or why it cannot be used.
  state(x) {
    if (!x.configured) return `${x.host} · No service account`;
    return x.error ? `${x.host} · Last connection failed: ${x.error}` : x.host;
  },
  // Every site can be selected; a site without a service account is marked and its pages explain what to do.
  render(locked = false) {
    const box = $('#siteSwitch');
    box.classList.toggle('is-locked', locked);
    box.innerHTML = this.list.map(x => `<label class="site-opt" style="--opt:${x.color}" title="${esc(this.state(x))}">`
      + `<input type="radio" name="site" value="${esc(x.name)}"${x.name === this.current ? ' checked' : ''}${locked ? ' disabled' : ''}>`
      + `<span class="site-chip${x.configured ? '' : ' is-unset'}"><span class="site-dot"></span>${esc(x.name)}`
      + (x.configured ? (x.error ? icon('alert') : '') : `${icon('alert', 'site-chip-icon')}<span class="site-chip-label">No service account</span>`)
      + '</span></label>').join('');
    $('#navSites').innerHTML = this.list.map(x => `<div title="${esc(this.state(x))}"><span class="site-dot" style="--opt:${x.color}"></span>`
      + `<span>${esc(x.name)}</span><span class="mono">${esc(x.host)}</span>`
      + (x.configured ? (x.error ? icon('alert') : '') : '<span class="nav-label">No service account</span>') + '</div>').join('');
  },
  activate(name) {
    this.current = name;
    tabStore.set('aci_site', name);
    const color = this.info(name).color;
    document.documentElement.style.setProperty('--site', color);
    document.documentElement.style.setProperty('--site-soft', rgba(color, 0.14));
    document.title = `[${name}] ${BASE_TITLE}`;
    $$('.site-name-current').forEach(el => { el.textContent = name; });
  },
  // The fabric pages (Static Port, Provisioning, Report) of a site without a service account show a warning
  // instead of their forms, and APIC is not called.
  notice() {
    const x = this.info(this.current);
    const blocked = !!this.current && !x.configured;
    const how = Session.isAdmin() ? '<a href="/#/credentials">Set it in Credentials.</a>'
      : 'Ask an administrator to set it in Administration → Credentials.';
    $$('[data-site-page]').forEach(panel => {
      panel.classList.toggle('is-blocked', blocked);
      $('.site-blocked', panel).innerHTML = blocked ? alertBox('warning', `<b>No service account for ${esc(x.name)}.</b> ${how}`) : '';
    });
  },
};

async function changeSite(name) {
  Site.activate(name);
  Site.notice();
  if (!Site.info(name).configured) {
    Site.render();
    refreshUi();
    return;
  }
  Site.render(true);
  try {
    const tenants = (await api('/api/discover?kind=tenants')).items;
    await Promise.all([StaticPort.onSite(tenants).finally(() => Templates.onSite()), Provision.onSite(tenants), Report.onSite(tenants),
      IpUsage.onSite(tenants)]);
  } catch (e) {
    notifyError(e);
    // Show the connection problem of the site (for example a wrong service account password) in the site switch.
    if (!e.signedOut) Session.refresh().catch(() => {});
  } finally {
    Site.render();
    refreshUi();
  }
}

const Session = {
  user: null,
  outdated: false,
  // The server already runs a newer Web UI (for example after install.sh) than this page.
  checkVersion(status) {
    if (this.outdated || !status.ui_version || !UI_VERSION || status.ui_version === UI_VERSION) return;
    this.outdated = true;
    toast('The Web UI on the server has been updated. Reload this page; anything not yet applied will be lost.', 'info',
      {label: 'Reload', fn: () => location.reload()});
  },
  isAdmin() { return this.user?.role === 'admin'; },
  // A status from /aci/api/session, /aci/api/keepalive, or a 401 answer.
  update(status) {
    this.checkVersion(status);
    if (!status.user) return this.signIn();
    if (!status.allowed) return this.noAccess(status);
    if (this.blocked) return location.reload();   // access to ACI was given meanwhile: start the page
    const wasAdmin = this.isAdmin();
    const before = Site.info(Site.current).configured;
    this.user = status.user;
    Site.set(status);
    Templates.setAccess(!!status.can_edit_templates);
    if ($('#appView').hidden) return;
    UserMenu.render(status.user, status.client);
    Site.render();
    Site.notice();
    if (wasAdmin !== this.isAdmin()) Tabs.applyRole();
    // A service account was set or removed for the selected site: load its data, or show the warning.
    if (Site.current && before !== Site.info(Site.current).configured) changeSite(Site.current);
  },
  async refresh() {
    const status = await (await request(BASE + '/api/session')).json();
    this.update(status);
    return status;
  },
  // The sign-in ended (idle or maximum time, access removed, or signed out in another tab).
  ended() {
    this.signIn();
  },
  // No (more) portal session: the portal sign-in opens and comes back to this page afterwards.
  signIn() {
    this.user = null;
    UserMenu.close();
    if (window.PortalLauncher) window.PortalLauncher.signIn();
    else location.assign('/');
  },
  // Signed in, but this account may not use ACI: the masthead (application launcher, user menu) and an empty state.
  blocked: false,
  noAccess(status) {
    this.blocked = true;
    this.user = status.user;
    $$('dialog[open]').forEach(d => d.close());
    UserMenu.render(status.user, status.client);
    const page = $('#appView');
    page.hidden = false;
    page.classList.remove('is-nav-open');
    page.classList.add('is-nav-collapsed');
    $('#sidebar').inert = true;
    $('#navToggle').hidden = true;
    $('#siteSwitch').hidden = true;
    $$('.tabpanel').forEach(p => { p.hidden = p.id !== 'tab-noaccess'; });
    document.title = BASE_TITLE;
  },
  async enter(status) {
    this.checkVersion(status);
    if (!status.allowed) return this.noAccess(status);
    this.user = status.user;
    Site.set(status);
    Templates.setAccess(!!status.can_edit_templates);
    const saved = tabStore.get('aci_site');
    const first = Site.list.find(x => x.configured) || Site.list[0];
    Site.current = Site.list.some(x => x.name === saved) ? saved : (first ? first.name : '');
    $('#appView').hidden = false;
    UserMenu.render(status.user, status.client);
    Tabs.applyRole();
    Tabs.show(location.hash.slice(1) || tabStore.get('aci_tab'));
    await changeSite(Site.current);
  },
  // Sign out of the portal (every module); the portal home then shows its sign-in.
  async logout() {
    try { await request('/api/logout', {method: 'POST'}); } finally { location.assign('/'); }
  },
};

// Keeps the sign-in (and the APIC tokens) alive while someone works in this page without server requests, for
// example while typing a long binding table. A page left alone is signed out after the idle time set in auth.yml.
const Activity = {
  active: false,
  init() {
    ['pointerdown', 'keydown', 'wheel'].forEach(type => document.addEventListener(type, () => { this.active = true; }, {capture: true, passive: true}));
    setInterval(() => this.tick(), 120000);
  },
  async tick() {
    if (!this.active || $('#appView').hidden) return;
    this.active = false;
    try {
      const status = await (await request(BASE + '/api/keepalive', {method: 'POST'})).json();
      Session.update(status);   // without a session: the portal sign-in
    } catch (e) { /* the network may be down for a moment: try again at the next interval */ }
  },
};

// User menu in the masthead: name, role, and Sign out.
const UserMenu = {
  init() {
    const toggle = $('#userMenuToggle');
    toggle.addEventListener('click', () => (this.isOpen() ? this.close() : this.open()));
    document.addEventListener('click', e => { if (this.isOpen() && !e.target.closest('#userMenu')) this.close(); });
    $('#userMenu').addEventListener('keydown', e => {
      if (e.key === 'Escape' && this.isOpen()) {
        this.close();
        toggle.focus();
      }
    });
    $('#logoutBtn').addEventListener('click', () => Session.logout());
  },
  isOpen() { return !$('#userMenuList').hidden; },
  open() {
    $('#userMenuList').hidden = false;
    $('#userMenuToggle').setAttribute('aria-expanded', 'true');
    $('#logoutBtn').focus();
  },
  close() {
    $('#userMenuList').hidden = true;
    $('#userMenuToggle').setAttribute('aria-expanded', 'false');
  },
  // client: the address the portal sees for this browser (logged with every change), e.g. "10.252.2.3" or
  // "172.26.0.100 (RDP 10.252.2.3, INTRANET\\jdoe)" for a browser on the bastion itself.
  render(user, client = '') {
    const name = user.display_name || user.username;
    const role = ROLE_LABEL[user.role] || user.role;
    $('#userName').textContent = name;
    $('#userRole').textContent = role;
    $('#userAvatar').textContent = initials(name);
    $('#userMenuToggle').title = `${name} · ${role}`;
    $('#userMenuName').textContent = name;
    $('#userMenuMeta').textContent = `${user.username} · ${role}${user.source === 'local' ? ' · local account' : user.mfa === 'sso' ? ' · Duo SSO' : ''}`;
    $('#userMenuClient').textContent = client ? `From ${client}` : '';
  },
};

// Sidebar menu (PatternFly navigation). The URL hash (#static, #provision, ...) follows the open page.
// Administration (Users, Credentials) is on the portal: links to /#/users and /#/credentials.
const Tabs = {
  names: ['static', 'templates', 'provision', 'report', 'ips', 'audit'],
  current: '',
  init() {
    // Menu links of this page (links to the portal, such as Users and "Set it in Credentials.", are normal links).
    $('#appView').addEventListener('click', e => {
      const link = e.target.closest('a[data-tab]');
      if (!link) return;
      e.preventDefault();
      this.show(link.dataset.tab);
    });
    const narrow = () => matchMedia('(max-width: 1000px)').matches;
    $('#navToggle').setAttribute('aria-expanded', String(!narrow()));
    $('#navToggle').addEventListener('click', () => {
      const page = $('#appView');
      page.classList.toggle(narrow() ? 'is-nav-open' : 'is-nav-collapsed');
      $('#navToggle').setAttribute('aria-expanded', String(narrow() ? page.classList.contains('is-nav-open') : !page.classList.contains('is-nav-collapsed')));
    });
  },
  // The Administration menu is only for administrators.
  applyRole() {
    const admin = Session.isAdmin();
    $$('[data-admin-only]').forEach(el => { el.hidden = !admin; });
  },
  show(name) {
    if (!this.names.includes(name)) name = 'static';
    this.current = name;
    $$('#tabs [data-tab]').forEach(link => {
      const on = link.dataset.tab === name;
      link.classList.toggle('is-current', on);
      if (on) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current');
    });
    $$('.tabpanel').forEach(p => { p.hidden = p.id !== `tab-${name}`; });
    tabStore.set('aci_tab', name);
    history.replaceState(null, '', `#${name}`);
    window.scrollTo(0, 0);
    if (name === 'audit') Audit.onShow();
    if (name === 'templates') Templates.onShow();
  },
};

/* =========================================================================
   Review dialog & history details
   ========================================================================= */
function siteBanner(site, detailHtml) {
  const x = Site.info(site);
  return `<div class="site-banner" style="${Site.style(site)}"><span class="site-banner-name">${esc(site)}</span>`
    + `<div class="site-banner-detail"><b>Site ${esc(site)}</b> <span class="muted mono">${esc(x.host)}</span><div>${detailHtml}</div></div></div>`;
}

const Review = {
  busy: false,
  confirmFn: null,
  labels: {busy: 'Applying…', fail: 'Apply failed.'},
  init() {
    const dialog = $('#reviewDialog');
    const close = () => { if (!this.busy) dialog.close(); };
    $('#reviewCancel').addEventListener('click', close);
    $('#reviewClose').addEventListener('click', close);
    $('#reviewConfirm').addEventListener('click', () => this.confirm());
    $('#confirmCancel').addEventListener('click', () => $('#confirmDialog').close());
    dialog.addEventListener('cancel', e => { if (this.busy) e.preventDefault(); });
  },
  // danger: red confirm button; busyLabel / failLabel: button text while it runs and the heading of an error.
  open({title, body, confirmLabel, canConfirm, onConfirm, danger = false, busyLabel = 'Applying…', failLabel = 'Apply failed.'}) {
    $('#reviewTitle').textContent = title;
    $('#reviewBody').innerHTML = body;
    $('#reviewBody').scrollTop = 0;
    $('#reviewConfirmLabel').textContent = confirmLabel;
    $('#reviewConfirm').className = `btn ${danger ? 'btn-danger' : 'btn-primary'}`;
    this.labels = {busy: busyLabel, fail: failLabel};
    $('#reviewConfirm').hidden = false;
    $('#reviewConfirm').disabled = !canConfirm;
    $('#reviewCancel').textContent = 'Cancel';
    this.confirmFn = onConfirm;
    $('#reviewDialog').showModal();
    // Initial focus on Cancel: Enter does not apply the change right away.
    $('#reviewCancel').focus();
  },
  async confirm() {
    const btn = $('#reviewConfirm'), cancel = $('#reviewCancel');
    this.busy = true;
    btn.disabled = true;
    cancel.disabled = true;
    btn.classList.add('is-loading');
    $('#reviewConfirmLabel').dataset.label = $('#reviewConfirmLabel').textContent;
    $('#reviewConfirmLabel').textContent = this.labels.busy;
    try {
      $('#reviewBody').innerHTML = await this.confirmFn();
      $('#reviewBody').scrollTop = 0;
      btn.hidden = true;
      cancel.textContent = 'Close';
    } catch (e) {
      $('#reviewBody .alert-danger')?.remove();
      $('#reviewBody').insertAdjacentHTML('afterbegin', alertBox('danger', `<b>${esc(this.labels.fail)}</b> ${esc(e.message)}`));
      $('#reviewBody').scrollTop = 0;
      $('#reviewConfirmLabel').textContent = $('#reviewConfirmLabel').dataset.label;
      btn.disabled = false;
    } finally {
      this.busy = false;
      btn.classList.remove('is-loading');
      cancel.disabled = false;
      cancel.focus();
    }
  },
};

// Tables shared by the Review screen and the history details.
// "delete": a path removed by an undo (its values are in Before).
const BINDING_STATUS = {new: 'New', change: 'Changed', same: 'Unchanged', delete: 'Deleted'};
const BINDING_BADGE = {delete: 'badge-danger'};
// Encap · mode · immediacy of a binding as APIC names it ({encap, mode, instrImedcy}) or as a plan does ({encap, mode, immediacy}).
const bindingValues = b => (b ? `${b.encap} · ${MODE_LABEL[b.mode] || b.mode} · ${IMMEDIACY_LABEL[b.instrImedcy ?? b.immediacy] || (b.instrImedcy ?? b.immediacy)}` : '');
function bindingTable(items) {
  const dash = v => (v === undefined || v === null || v === '' ? '—' : v);
  return '<div class="table-wrap"><table class="table table-data"><thead><tr><th>Status</th><th>Path</th><th>Encap</th><th>Mode</th><th>Immediacy</th><th>Before</th></tr></thead><tbody>'
    + items.map(i => `<tr${i.conflict ? ' class="is-conflict"' : ''}><td><span class="badge ${BINDING_BADGE[i.status] || `badge-${esc(i.status)}`}">${esc(BINDING_STATUS[i.status] || i.status)}</span>`
      + `${i.conflict ? ' <span class="badge badge-conflict">VLAN in use</span>' : ''}</td><td class="mono">${esc(i.tdn)}</td><td>${esc(dash(i.encap))}</td>`
      + `<td>${esc(dash(MODE_LABEL[i.mode] || i.mode))}</td><td>${esc(dash(IMMEDIACY_LABEL[i.immediacy] || i.immediacy))}</td><td class="muted">${esc(bindingValues(i.before))}</td></tr>`).join('')
    + '</tbody></table></div>';
}
// A VLAN already used by another EPG or an L3Out on this site: the restore cannot continue until the VLAN ID is changed.
// lead: the first sentence and the advice (an undo cannot choose another VLAN).
function conflictHtml(conflicts, lead = '') {
  if (!conflicts || !conflicts.length) return '';
  const where = u => `${esc(u.kind)} <b>${esc(u.tenant)}${u.app ? ` / ${esc(u.app)}` : ''} / ${esc(u.name)}</b>`
    + ` <span class="muted">${esc(u.binding)}${u.path ? ` <span class="mono">${esc(u.path)}</span>` : ''}${u.same_leaf ? ' · same leaf' : ''}</span>`;
  return alertBox('danger', (lead || `<b>${plural(conflicts.length, 'VLAN')} already used by another EPG. Nothing can be applied.</b>`
    + ' Use a new VLAN ID that no other EPG uses, then review again.')
    + conflicts.map(c => `<div class="conflict-vlan"><b>VLAN ${esc(c.vlan)}</b> — in this change on ${plural(c.paths.length, 'path')}; already used by:`
      + `<ul>${c.used_by.slice(0, 8).map(u => `<li>${where(u)}</li>`).join('')}`
      + `${c.used_by.length > 8 ? `<li class="muted">and ${c.used_by.length - 8} more</li>` : ''}</ul></div>`).join(''));
}
function stepsTable(steps) {
  return '<div class="table-wrap"><table class="table table-data"><thead><tr><th>Object</th><th>Name / target</th><th>Action</th></tr></thead><tbody>'
    + steps.map(s => `<tr><td>${esc(s.object)}</td><td class="mono">${esc(s.name)}</td><td><span class="badge badge-${esc(s.kind)}">${esc(s.action)}</span></td></tr>`).join('')
    + '</tbody></table></div>';
}
// A file of the module (url without the /aci prefix). Errors come back as JSON, like the API.
async function downloadFile(url, fallbackName) {
  const res = await request(BASE + url);
  if (!res.ok) {
    let data = {};
    try { data = await res.json(); } catch (e) { /* not JSON */ }
    const error = new Error(data.error || `HTTP ${res.status}`);
    if (res.status === 401) {
      error.signedOut = true;
      Session.ended(data.error, data.session);
    }
    throw error;
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

/* =========================================================================
   Change history (audit from the server: all users, all sites)
   ========================================================================= */
const ACTION_LABEL = {'static-port': 'Static Port', provisioning: 'Provisioning', template: 'Product template'};
const AUDIT_STATUS = {success: ['badge-new', 'Successful'], failed: ['badge-danger', 'Failed'], unknown: ['badge-change', 'Unknown'],
  pending: ['badge-change', 'Incomplete']};
// Browser local time, en-GB 24 h: "25 Sep 2026, 08:48:19". Newer ICU writes September as "Sept"; it is shown as "Sep".
const fmtTime = ts => (ts ? new Date(ts).toLocaleString('en-GB', {day: '2-digit', month: 'short', year: 'numeric',
  hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23'}).replace('Sept', 'Sep') : '');

const Audit = {
  items: [],
  total: 0,
  stale: true,
  init() {
    combo($('#auUser'));
    fill($('#auUser'), [], 'All users');
    fill($('#auSite'), [], 'All sites');
    ['#auUser', '#auSite', '#auAction', '#auStatus', '#auSince', '#auUntil'].forEach(id => $(id).addEventListener('change', () => run(null, () => this.load())));
    let timer = null;
    $('#auQ').addEventListener('input', () => {
      clearTimeout(timer);
      timer = setTimeout(() => run(null, () => this.load()), 300);
    });
    $('#auMoreBtn').addEventListener('click', e => run(e.currentTarget, () => this.load(true)));
    $('#auExportBtn').addEventListener('click', e => run(e.currentTarget, () => downloadFile('/export/audit.csv?' + qs(this.filters()), 'change-history.csv')));
    const open = tr => run(null, () => this.open(Number(tr.dataset.id)));
    $('#auTable tbody').addEventListener('click', e => {
      const tr = e.target.closest('tr[data-id]');
      if (tr) open(tr);
    });
    $('#auTable tbody').addEventListener('keydown', e => {
      const tr = e.target.closest('tr[data-id]');
      if (tr && e.key === 'Enter') open(tr);
    });
    $('#auditClose').addEventListener('click', () => $('#auditDialog').close());
    // In the details: "change #12" (Undo of / Undone by) opens that change; "Undo this change…" opens the undo review.
    $('#auditBody').addEventListener('click', e => {
      const link = e.target.closest('a[data-audit]');
      const undo = e.target.closest('button[data-act="undo"]');
      if (link) {
        e.preventDefault();
        run(null, () => this.open(Number(link.dataset.audit)));
      } else if (undo) {
        run(undo, () => Undo.review(Number(undo.dataset.id)));
      }
    });
    this.render();
  },
  onShow() {
    if (this.stale) run(null, () => this.load());
  },
  // Called after an apply: the history must be reloaded.
  markStale() {
    this.stale = true;
    if (!$('#tab-audit').hidden) run(null, () => this.load());
  },
  filters() {
    return {user: $('#auUser').value, site: $('#auSite').value, action: $('#auAction').value, status: $('#auStatus').value,
      q: $('#auQ').value.trim(), since: $('#auSince').value, until: $('#auUntil').value};
  },
  async load(more = false) {
    if (!more) $('#auTable tbody').innerHTML = '<tr class="empty-row"><td colspan="8"><div class="loading">Loading history…</div></td></tr>';
    let d;
    try {
      d = await api('/api/audit?' + qs({...this.filters(), limit: 100, offset: more ? this.items.length : 0}));
    } catch (e) {
      this.render();
      throw e;
    }
    this.items = more ? [...this.items, ...d.items] : d.items;
    this.total = d.total;
    this.stale = false;
    const keep = {user: $('#auUser').value, site: $('#auSite').value};
    fill($('#auUser'), d.users, 'All users');
    choose($('#auUser'), keep.user);
    fill($('#auSite'), [...new Set([...Site.list.map(x => x.name), ...d.sites])], 'All sites');
    choose($('#auSite'), keep.site);
    this.render();
  },
  render() {
    const filtered = Object.values(this.filters()).some(Boolean);
    $('#auTable tbody').innerHTML = this.items.map(x => {
      const [cls, label] = AUDIT_STATUS[x.status] || ['badge', x.status];
      return `<tr data-id="${Number(x.id)}" tabindex="0"><td>${esc(fmtTime(x.ts))}</td><td><span class="badge ${cls}">${esc(label)}</span>`
        + `${x.undone_by ? ` <span class="badge badge-info" title="Undone by change #${Number(x.undone_by)}">Undone</span>` : ''}</td>`
        + `<td><b>${esc(x.username)}</b></td><td>${x.site ? `<span class="site-pill" style="${Site.style(x.site)}">${esc(x.site)}</span>` : '<span class="muted">All sites</span>'}</td>`
        + `<td>${esc(ACTION_LABEL[x.action] || x.action)}</td><td>${esc(x.product || '—')}</td>`
        + `<td class="mono wrap">${esc(x.target.replace(/^uni\//, ''))}</td><td class="wrap">${esc(x.summary)}</td></tr>`;
    }).join('') || `<tr class="empty-row"><td colspan="8"><div class="empty">${icon('clock')}<div><b>${filtered ? 'No results found' : 'No changes yet'}</b>`
      + `<p>${filtered ? 'Change the filters or search terms.' : 'Every change applied from this Web UI is recorded here.'}</p></div></div></td></tr>`;
    $('#auShown').textContent = this.items.length ? `Showing ${this.items.length} of ${plural(this.total, 'change')}` : '';
    $('#auMoreBtn').hidden = this.items.length >= this.total;
  },
  async open(id) {
    const x = (await api(`/api/audit/${id}`)).item;
    const [cls, label] = AUDIT_STATUS[x.status] || ['badge', x.status];
    const meta = [['Time', fmtTime(x.ts) + (x.finished ? ` (finished ${fmtTime(x.finished)})` : '')], ['User', x.username],
      ['APIC account', x.apic_user || '—'], ['Site', x.site ? `${x.site} · ${x.apic}` : 'All sites'], ['Action', ACTION_LABEL[x.action] || x.action], ['Product', x.product || '—'],
      ['Target', x.target], ['Summary', x.summary], ['Client IP', x.client_ip || '—']];
    const details = x.details || {};
    const link = n => `<a href="#audit" data-audit="${Number(n)}">change #${Number(n)}</a>`;
    $('#auditTitle').textContent = `Change #${x.id}`;
    $('#auditBody').innerHTML = `<dl class="meta-grid">${meta.map(([k, v]) => `<dt>${k}</dt><dd>${esc(v)}</dd>`).join('')}`
        + `<dt>Status</dt><dd><span class="badge ${cls}">${esc(label)}</span></dd>`
        + (x.undo_of ? `<dt>Undo of</dt><dd>${link(x.undo_of)}</dd>` : '')
        + (x.undone_by ? `<dt>Undone by</dt><dd>${link(x.undone_by)}</dd>` : '') + '</dl>'
      + (x.error ? alertBox('danger', `<b>APIC error:</b> ${esc(x.error)}`) : '')
      + (x.status === 'unknown' ? alertBox('warning', 'The connection to APIC was lost before a response arrived, so the change may or may not have been applied. Check this object directly on APIC.') : '')
      + (x.status === 'pending' ? alertBox('warning', 'The Web UI process stopped before the APIC result was received. Check the state of this object directly on APIC.') : '')
      + Undo.detailHtml(x)
      + (x.action === 'template' ? Templates.historyHtml(details) : '')
      + (details.items ? `<h3 class="detail-title">Bindings sent (${details.items.length})</h3>${bindingTable(details.items)}` : '')
      + (details.skipped?.length ? `<h3 class="detail-title">Skipped by the undo (${details.skipped.length})</h3>`
        + '<div class="table-wrap"><table class="table table-data"><thead><tr><th>Path</th><th>Reason</th></tr></thead><tbody>'
        + details.skipped.map(s => `<tr><td class="mono">${esc(s.tdn)}</td><td class="wrap">${esc(s.reason)}</td></tr>`).join('') + '</tbody></table></div>' : '')
      + (details.warnings?.length ? alertBox('warning', `<b>Warnings at the time</b><ul>${details.warnings.map(w => `<li>${esc(w)}</li>`).join('')}</ul>`) : '')
      + (details.steps ? `<h3 class="detail-title">Provisioning steps</h3>${stepsTable(details.steps)}`
        + `<details class="payload"><summary>JSON payload sent</summary><pre>${esc(JSON.stringify(details.payload, null, 2))}</pre></details>` : '');
    // Already open when a linked change (Undo of / Undone by) is opened, or after an undo.
    if (!$('#auditDialog').open) $('#auditDialog').showModal();
    $('#auditBody').scrollTop = 0;
  },
};

/* =========================================================================
   Undo of a static-port change (from its History details)
   ========================================================================= */
const UNDO_ACTION = {delete: ['badge-danger', 'Delete'], restore: ['badge-change', 'Restore'], skip: ['', 'Skipped']};

const Undo = {
  // Administrators, and the user who made the change; the server checks the same.
  allowed(x) { return Session.isAdmin() || x.username === Session.user?.username; },
  // Part of the History details: the Undo button, or why there is none.
  detailHtml(x) {
    const note = text => `<p class="undo-note">${icon('info')}<span>${text}</span></p>`;
    if (x.action === 'provisioning') return note('Provisioning changes cannot be undone here, because the portal never deletes objects.');
    if (x.action === 'template') return note('A product template change never touches APIC, so there is nothing to undo there. '
      + 'Edit the template again, or reset it to the default, on Fabric → Templates.');
    if (x.action !== 'static-port' || x.status !== 'success' || x.undone_by) return '';
    if (x.undo_of) return note('This change is an undo, so it cannot be undone itself.');
    if (!this.allowed(x)) return note(`Only administrators and ${esc(x.username)}, who made this change, can undo it.`);
    return `<div class="undo-bar"><button type="button" class="btn btn-secondary" data-act="undo" data-id="${Number(x.id)}">${icon('undo')}Undo this change…</button>`
      + `<span class="muted">Deletes the paths it added and puts back the values it changed, on site <b>${esc(x.site)}</b>. `
      + 'Paths changed since are left alone. You review everything before it is sent.</span></div>';
  },
  table(items) {
    const after = i => (i.action === 'delete' ? '<span class="muted">— (deleted)</span>'
      : i.action === 'restore' ? esc(bindingValues(i)) : '<span class="muted">Unchanged</span>');
    // Why a path is skipped: under the path, so the table needs no extra column.
    return '<div class="table-wrap"><table class="table table-data"><thead><tr><th>Action</th><th>Path</th><th>Before (APIC now)</th>'
      + '<th>After the undo</th></tr></thead><tbody>'
      + items.map(i => {
        const [cls, label] = UNDO_ACTION[i.action] || ['', i.action];
        return `<tr${i.conflict ? ' class="is-conflict"' : ''}><td><span class="badge ${cls}">${esc(label)}</span>`
          + `${i.conflict ? ' <span class="badge badge-conflict">VLAN in use</span>' : ''}</td>`
          + `<td class="wrap"><span class="mono">${esc(i.tdn)}</span>${i.reason ? `<div class="muted cell-note">${esc(i.reason)}</div>` : ''}</td>`
          + `<td>${i.before ? esc(bindingValues(i.before)) : '<span class="muted">Not on APIC</span>'}</td><td>${after(i)}</td></tr>`;
      }).join('') + '</tbody></table></div>';
  },
  planHtml(d) {
    const s = d.summary, n = s.delete + s.restore, id = Number(d.undo_of);
    const lead = `<b>${plural(d.conflicts.length, 'VLAN')} of this undo already used by another EPG or L3Out. The undo cannot be applied.</b>`
      + ` Change #${id} replaced these VLANs, and another EPG or L3Out has taken them since.`;
    return (d.applied ? `<div class="success-state"><span class="success-icon">${icon('check')}</span><div><b>Change #${id} undone on ${esc(d.site)}.</b>`
        + `<div class="muted">Recorded in History as change #${Number(d.audit_id)}.</div></div></div>` : '')
      + siteBanner(d.site, `EPG <code>${esc(d.epg_dn)}</code> · undo of change #${id}`)
      + (!d.applied && d.site !== Site.current ? alertBox('info', `Change #${id} was made on <b>${esc(d.site)}</b>, so the undo runs there, `
        + `not on the site selected at the top (${esc(Site.current)}).`) : '')
      + `<div class="pills"><span class="pill pill-danger">${s.delete} ${d.applied ? 'deleted' : 'to delete'}</span>`
      + `<span class="pill pill-change">${s.restore} ${d.applied ? 'restored' : 'to restore'}</span><span class="pill">${s.skip} skipped</span></div>`
      + (d.applied ? '' : conflictHtml(d.conflicts, lead))
      + (!d.applied && s.skip && n ? alertBox('warning', `<b>${plural(s.skip, 'path')} skipped.</b> They were changed or removed after change #${id}; `
        + 'the undo never overwrites a later change.') : '')
      + (!d.applied && !n ? alertBox('info', `<b>Nothing to undo.</b> Every path of change #${id} was changed or removed since.`) : '')
      + this.table(d.items)
      + (d.payload ? `<details class="payload"><summary>JSON payload for APIC</summary><pre>${esc(JSON.stringify(d.payload, null, 2))}</pre></details>` : '');
  },
  async review(id) {
    const d = await callApi(`/api/audit/${id}/undo/preview`, {body: {}});
    const n = d.summary.delete + d.summary.restore;
    Review.open({
      title: `Undo change #${id}`,
      body: this.planHtml(d),
      confirmLabel: d.blocked ? 'Blocked: VLAN already in use' : n ? `Undo ${plural(n, 'change')} on ${d.site}` : 'Nothing to undo',
      canConfirm: n > 0 && !d.blocked,
      danger: true,
      busyLabel: 'Undoing…',
      failLabel: 'Undo failed.',
      onConfirm: async () => {
        const r = await callApi(`/api/audit/${id}/undo`, {body: {confirm: true}});
        toast(`Change undone. Recorded in History as change #${r.audit_id}.`, 'success');
        Audit.markStale();
        if ($('#auditDialog').open) run(null, () => Audit.open(id));
        return this.planHtml(r);
      },
    });
  },
};

/* =========================================================================
   Dropdown Tenant → App Profile → EPG
   ========================================================================= */
// The choices are kept when the site changes, if the names also exist on the new site.
function cascade(ids, text) {
  const [tenant, app, epg] = ids.map(id => $(id));
  [tenant, app, epg].forEach(combo);
  const c = {
    async onSite(tenants) {
      const keep = [tenant.value, app.value, epg.value];
      fill(tenant, tenants, tenants.length ? text.tenant : 'No tenants');
      fill(app, [], text.appWait);
      fill(epg, [], text.epgWait);
      if (choose(tenant, keep[0])) {
        await c.loadApps();
        if (choose(app, keep[1])) {
          await c.loadEpgs();
          choose(epg, keep[2]);
        }
      }
    },
    async loadApps() {
      fill(epg, [], text.epgWait);
      if (!tenant.value) return fill(app, [], text.appWait);
      fill(app, [], 'Loading…');
      try {
        const items = (await api('/api/discover?' + qs({kind: 'apps', tenant: tenant.value}))).items;
        fill(app, items, items.length ? text.app : 'This tenant has no app profiles');
      } catch (e) {
        fill(app, [], 'Failed to load');
        throw e;
      }
    },
    async loadEpgs() {
      if (!tenant.value || !app.value) return fill(epg, [], text.epgWait);
      fill(epg, [], 'Loading…');
      try {
        const items = (await api('/api/discover?' + qs({kind: 'epgs', tenant: tenant.value, app: app.value}))).items;
        fill(epg, items, items.length ? text.epg : 'This app profile has no EPGs');
      } catch (e) {
        fill(epg, [], 'Failed to load');
        throw e;
      }
    },
    values() { return {tenant: tenant.value, app: app.value, epg: epg.value}; },
  };
  tenant.addEventListener('change', () => run(null, c.loadApps));
  app.addEventListener('change', () => run(null, c.loadEpgs));
  epg.addEventListener('change', refreshUi);
  return c;
}

/* =========================================================================
   Static Port
   ========================================================================= */
// VLAN check while typing: is the VLAN already used on this site by ANOTHER EPG (static path / static leaf) or an L3Out?
// Asked to APIC as soon as a VLAN is filled in (table rows, product template, Search APIC, Interface range), per site
// and EPG, and kept for a minute. A VLAN in use makes the row invalid, so the change cannot be reviewed; the server
// checks again at Review and Apply.
const VlanCheck = {
  cache: new Map(),      // `${site}|${tenant}/${app}/${epg}|${vlan}` -> {users, at}
  pending: new Set(),
  timer: null,
  toolTimer: null,
  error: '',
  TTL: 60000,
  context() {
    const v = StaticPort.target ? StaticPort.target.values() : {};
    return v.tenant && v.app && v.epg ? {tenant: v.tenant, app: v.app, epg: v.epg, key: `${Site.current}|${v.tenant}/${v.app}/${v.epg}`} : null;
  },
  vlanOf(value) {
    const v = String(value ?? '').trim().replace(/^vlan[-_ =]?/i, '');
    return validVlan(v) ? String(Number(v)) : '';
  },
  // [] = free, [..] = used by another EPG / L3Out, undefined = not known yet (not checked, checking, or no EPG selected).
  users(vlan) {
    const c = this.context(), v = this.vlanOf(vlan);
    if (!c || !v) return undefined;
    const hit = this.cache.get(`${c.key}|${v}`);
    return hit && Date.now() - hit.at < this.TTL ? hit.users : undefined;
  },
  checking(vlan) {
    const c = this.context(), v = this.vlanOf(vlan);
    return Boolean(c && v && this.pending.has(`${c.key}|${v}`));
  },
  owners(users) {
    return [...new Set(users.map(u => `${u.kind} ${u.tenant}${u.app ? `/${u.app}` : ''}/${u.name}`))];
  },
  message(vlan, users) {
    const owners = this.owners(users);
    return `VLAN ${this.vlanOf(vlan)} is already used by ${owners.slice(0, 3).join(', ')}${owners.length > 3 ? ` and ${owners.length - 3} more` : ''}. Use a new VLAN ID.`;
  },
  async lookup(vlans) {
    const c = this.context();
    if (!c) return this.render();
    const todo = [...new Set(vlans.map(v => this.vlanOf(v)).filter(Boolean))]
      .filter(v => this.users(v) === undefined && !this.pending.has(`${c.key}|${v}`));
    if (!todo.length) return this.render();
    todo.forEach(v => this.pending.add(`${c.key}|${v}`));
    this.render();
    try {
      for (let i = 0; i < todo.length; i += 100) {
        const part = todo.slice(i, i + 100);
        const data = await api('/api/vlan-usage?' + qs({tenant: c.tenant, app: c.app, epg: c.epg, vlans: part.join(',')}));
        part.forEach(v => this.cache.set(`${c.key}|${v}`, {users: data.usage[v] || [], at: Date.now()}));
      }
      this.error = '';
    } catch (e) {
      this.error = e.message;
    } finally {
      todo.forEach(v => this.pending.delete(`${c.key}|${v}`));
    }
    this.refresh();
  },
  // Rows of the table changed (typed, added from a tool or a template, EPG or site changed).
  schedule() {
    clearTimeout(this.timer);
    this.timer = setTimeout(() => this.lookup([...Bindings.physical, ...Bindings.paths].map(r => r.vlan)), 300);
  },
  // One of the VLAN fields of the tools changed.
  scheduleTools() {
    clearTimeout(this.toolTimer);
    this.toolTimer = setTimeout(() => this.lookup([$('#productVlan').value, $('#searchVlan').value, $('#rgVlan').value]), 300);
  },
  refresh() {
    Bindings.validate();
    StaticPort.update();
    StaticPort.updateSearchAdd();
    StaticPort.rangePreview();
    Products.vlanHint();
    this.render();
  },
  // Notice above the table: checking, VLANs in use (with where), or the check itself failed.
  render() {
    const box = $('#spVlanNotice');
    if (!box) return;
    const rows = [...Bindings.physical, ...Bindings.paths];
    const inUse = new Map();
    rows.forEach(r => {
      const users = this.users(r.vlan);
      if (users && users.length) inUse.set(this.vlanOf(r.vlan), users);
    });
    const busy = rows.some(r => this.checking(r.vlan));
    let html = '';
    if (inUse.size) {
      html = alertBox('danger', `<b>${plural(inUse.size, 'VLAN')} already used by another EPG on ${esc(Site.current)}.</b> `
        + 'Change the VLAN ID in the red rows; the change cannot be reviewed until then.'
        + [...inUse].map(([vlan, users]) => `<div class="conflict-vlan"><b>VLAN ${esc(vlan)}</b> is used by:<ul>`
          + users.slice(0, 6).map(u => `<li>${esc(u.kind)} <b>${esc(u.tenant)}${u.app ? ` / ${esc(u.app)}` : ''} / ${esc(u.name)}</b>`
            + ` <span class="muted">${esc(u.binding)}${u.path ? ` <span class="mono">${esc(u.path)}</span>` : ''}</span></li>`).join('')
          + (users.length > 6 ? `<li class="muted">and ${users.length - 6} more</li>` : '') + '</ul></div>').join(''));
    } else if (busy) {
      html = `<p class="hint vlan-checking">${icon('search')} Checking on APIC whether the VLANs are used by another EPG…</p>`;
    } else if (this.error && rows.length) {
      html = alertBox('warning', `<b>The VLANs could not be checked on APIC:</b> ${esc(this.error)} They are checked again at Review.`);
    }
    if (box.dataset.html !== html) {
      box.dataset.html = html;
      box.innerHTML = html;
    }
  },
  // Text and state for a single VLAN field of a tool: {blocked, text}.
  field(value) {
    const v = this.vlanOf(value);
    if (!v || !this.context()) return {blocked: false, text: ''};
    const users = this.users(v);
    if (users && users.length) return {blocked: true, text: this.message(v, users)};
    if (users) return {blocked: false, text: `VLAN ${v} is not used by another EPG on ${Site.current}.`, free: true};
    return {blocked: false, text: this.checking(v) ? `Checking VLAN ${v} on APIC…` : ''};
  },
};

// "Suggest free VLAN" next to a VLAN field (template, Search APIC, Interface range): a popover with the VLANs the EPG
// already uses and the VLANs of its static pool ranges that nothing uses on this site. A click on a VLAN fills the
// field, and the usual live check runs on it.
const VlanSuggest = {
  el: null,
  button: null,
  seq: 0,
  init() {
    const el = document.createElement('div');
    Object.assign(el, {id: 'vlanSuggest', className: 'popover', hidden: true});
    el.setAttribute('role', 'dialog');
    el.setAttribute('aria-label', 'Suggested VLANs');
    this.el = el;
    $$('[data-suggest]').forEach(b => b.addEventListener('click', () => (this.button === b ? this.close() : this.open(b))));
    el.addEventListener('click', e => {
      const chip = e.target.closest('[data-vlan]');
      if (chip) this.pick(chip.dataset.vlan);
      else if (e.target.closest('[data-act="close"]')) this.close(true);
    });
    document.addEventListener('click', e => {
      if (this.button && !el.contains(e.target) && !e.target.closest('[data-suggest]')) this.close();
    });
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape' && this.button) this.close(true);
    });
  },
  async open(button) {
    this.close();
    this.button = button;
    button.setAttribute('aria-expanded', 'true');
    button.parentElement.appendChild(this.el);   // the .suggest-anchor next to the field
    this.el.hidden = false;
    const v = StaticPort.target.values();
    if (!v.epg) {
      this.render('<p class="muted">Select the EPG first.</p>');
      return;
    }
    const seq = ++this.seq;
    this.render(`<div class="loading">Reading the VLAN pools of ${esc(v.epg)} on ${esc(Site.current)}…</div>`);
    let html;
    try {
      html = this.html(await api('/api/vlan-suggest?' + qs({...v, count: 10})), v.epg);
    } catch (e) {
      html = alertBox('danger', `<b>No suggestions.</b> ${esc(e.message)}`);   // shown here instead of a toast
    }
    if (seq === this.seq) this.render(html);
  },
  close(focus = false) {
    this.seq += 1;   // an answer still on its way is ignored
    if (this.el) this.el.hidden = true;
    if (!this.button) return;
    this.button.setAttribute('aria-expanded', 'false');
    if (focus) this.button.focus();
    this.button = null;
  },
  render(body) {
    this.el.innerHTML = `<div class="popover-head"><b>Suggested VLANs</b><button type="button" class="btn-icon" data-act="close" aria-label="Close">${icon('x')}</button></div>${body}`;
  },
  html(d, epg) {
    const chips = (vlans, cls, what) => `<div class="chips">${vlans.map(v => `<button type="button" class="chip ${cls}" data-vlan="${Number(v)}"`
      + ` aria-label="Use VLAN ${Number(v)} (${what})">${Number(v)}</button>`).join('')}</div>`;
    return `<p class="muted">EPG <b>${esc(epg)}</b> on ${esc(Site.current)}</p>`
      + (d.own.length ? `<div class="suggest-section"><div class="suggest-label">Already used by this EPG</div>${chips(d.own, 'chip-own', 'this EPG')}</div>` : '')
      + `<div class="suggest-section"><div class="suggest-label">Free in the static VLAN ranges${d.free_total > d.free.length ? ` · first ${d.free.length} of ${d.free_total}` : ''}</div>`
      + (d.free.length ? chips(d.free, 'chip-free', 'free') : '<p class="muted">No free VLAN.</p>') + '</div>'
      + (d.pools.length ? `<ul class="suggest-pools">${d.pools.map(p => `<li><b class="mono">${esc(p.ranges)}</b> <span class="muted">pool ${esc(p.name)}`
        + ` (${esc(p.domain)}) · ${p.free_count} free</span></li>`).join('')}</ul>` : '')
      + (d.note ? `<p class="hint">${esc(d.note)}</p>` : '')
      + '<p class="hint">Click a VLAN to use it; it is checked on APIC as usual.</p>';
  },
  pick(vlan) {
    const input = $(`#${this.button.dataset.suggest}`);
    this.close();
    input.value = vlan;
    input.dispatchEvent(new Event('input', {bubbles: true}));   // the field's own handlers and the live VLAN check
    input.focus();
  },
};

const Bindings = {
  physical: [],
  paths: [],
  kind: 'physical',
  invalid: 0,
  labels: {pod: 'Pod', node: 'Node', interface: 'Interface', vlan: 'VLAN', tdn: 'Path TDN', mode: 'Mode', immediacy: 'Immediacy'},
  init() {
    ['physical', 'paths'].forEach(kind => {
      const tbody = $(`#${kind}Table tbody`);
      const edit = e => {
        const tr = e.target.closest('tr[data-i]');
        if (!tr || !e.target.dataset.k) return;
        this[kind][tr.dataset.i][e.target.dataset.k] = e.target.value;
        this.validate();
        StaticPort.update();
        if (e.target.dataset.k === 'vlan') VlanCheck.schedule();
      };
      tbody.addEventListener('input', edit);
      tbody.addEventListener('change', edit);
      tbody.addEventListener('click', e => {
        const btn = e.target.closest('button[data-act]');
        if (!btn) return;
        const i = Number(btn.closest('tr').dataset.i);
        if (btn.dataset.act === 'del') this[kind].splice(i, 1);
        else this[kind].splice(i + 1, 0, {...this[kind][i]});
        this.render(kind);
      });
      this.render(kind);
    });
    $$('#bindingKind [role="tab"]').forEach(b => b.addEventListener('click', () => this.show(b.dataset.kind)));
  },
  newRow(kind, init = {}) {
    const base = {vlan: '', mode: $('#spDefMode').value || 'regular', immediacy: $('#spDefImm').value || 'immediate'};
    const given = Object.fromEntries(Object.entries(init).filter(([, v]) => v !== undefined));
    return kind === 'physical' ? {pod: '1', node: '', interface: '', ...base, ...given} : {tdn: '', ...base, ...given};
  },
  add(kind, rows) {
    this[kind].push(...rows);
    this.render(kind);
  },
  clearAll() {
    this.physical = [];
    this.paths = [];
    this.render('physical');
    this.render('paths');
  },
  show(kind) {
    this.kind = kind;
    $$('#bindingKind [role="tab"]').forEach(b => b.setAttribute('aria-selected', String(b.dataset.kind === kind)));
    $('#physicalTable').hidden = kind !== 'physical';
    $('#pathsTable').hidden = kind !== 'paths';
    $$('[data-only="physical"]').forEach(el => { el.hidden = kind !== 'physical'; });
    StaticPort.onKind();
  },
  render(kind) {
    const rows = this[kind];
    const cols = kind === 'physical' ? 8 : 6;
    $(`#${kind}Table tbody`).innerHTML = rows.length ? rows.map((r, i) => this.rowHtml(kind, r, i)).join('')
      : `<tr class="empty-row"><td colspan="${cols}"><div class="empty">${icon(kind === 'physical' ? 'plug' : 'server')}<div>`
        + `<b>No ${kind === 'physical' ? 'physical / port-channel' : 'vPC / path TDN'} bindings yet</b>`
        + `<p>Add them with Search APIC${kind === 'physical' ? ', Interface range' : ''}, Bulk text, or Blank row.</p></div></div></td></tr>`;
    $(`#${kind}Count`).textContent = rows.length;
    this.validate();
    StaticPort.update();
    VlanCheck.schedule();
  },
  rowHtml(kind, r, i) {
    const cell = (key, attrs = '') => `<td><input class="input${key === 'tdn' ? ' mono' : ''}" data-k="${key}" value="${esc(r[key])}"`
      + ` aria-label="${this.labels[key]}, row ${i + 1}" autocomplete="off" spellcheck="false"${attrs}></td>`;
    const select = (key, options) => `<td><select class="input" data-k="${key}" aria-label="${this.labels[key]}, row ${i + 1}">`
      + options.map(([v, l]) => `<option value="${v}"${v === r[key] ? ' selected' : ''}>${l}</option>`).join('') + '</select></td>';
    const cells = kind === 'physical'
      ? cell('pod', ' inputmode="numeric"') + cell('node', ' inputmode="numeric" placeholder="101"') + cell('interface', ' placeholder="eth1/1 or PC name"')
        + cell('vlan', ' inputmode="numeric" placeholder="1-4094"')
      : cell('tdn', ' placeholder="topology/pod-1/protpaths-101-102/pathep-[PG]"') + cell('vlan', ' inputmode="numeric" placeholder="1-4094"');
    return `<tr data-i="${i}"><td class="row-num">${i + 1}</td>${cells}${select('mode', MODES)}${select('immediacy', IMMEDIACY)}`
      + `<td class="row-actions"><button type="button" class="btn-icon" data-act="dup" title="Duplicate row" aria-label="Duplicate row ${i + 1}">${icon('copy')}</button>`
      + `<button type="button" class="btn-icon danger" data-act="del" title="Remove row" aria-label="Remove row ${i + 1}">${icon('trash')}</button></td></tr>`;
  },
  tdnOf(kind, r) {
    if (kind === 'paths') return String(r.tdn).trim();
    const iface = String(r.interface).trim().replace(/^eth/i, 'eth');
    return `topology/pod-${String(r.pod).trim()}/paths-${String(r.node).trim()}/pathep-[${iface}]`;
  },
  issues(kind, r) {
    const e = {};
    if (!validVlan(String(r.vlan).trim().replace(/^vlan[-_ =]?/i, ''))) e.vlan = 'VLAN must be a number from 1 to 4094';
    else {
      const users = VlanCheck.users(r.vlan);
      if (users && users.length) e.vlan = VlanCheck.message(r.vlan, users);
    }
    if (kind === 'physical') {
      if (!int(r.pod) || Number(r.pod) < 1) e.pod = 'Pod must be a number, usually 1';
      if (!int(r.node) || Number(r.node) < 1) e.node = 'Node must be a number, e.g. 101';
      if (!/^[A-Za-z0-9_./:-]{1,64}$/.test(String(r.interface).trim())) e.interface = 'Enter an interface (e.g. eth1/1) or a port-channel name';
    } else if (!PATH_TDN.test(String(r.tdn).trim())) {
      e.tdn = 'Format: topology/pod-1/protpaths-101-102/pathep-[PG-name]';
    }
    return e;
  },
  // Validation in the browser for immediate feedback; the server validates again on preview/apply.
  validate() {
    const results = [], seen = new Map();
    ['physical', 'paths'].forEach(kind => this[kind].forEach((r, i) => {
      const item = {kind, i, e: this.issues(kind, r)};
      results.push(item);
      const tdn = this.tdnOf(kind, r);
      seen.set(tdn, [...(seen.get(tdn) || []), item]);
    }));
    seen.forEach(items => {
      if (items.length > 1) items.forEach(item => { item.e[item.kind === 'physical' ? 'interface' : 'tdn'] = 'This path is entered more than once'; });
    });
    this.invalid = 0;
    results.forEach(({kind, i, e}) => {
      const tr = $(`#${kind}Table tbody tr[data-i="${i}"]`);
      if (Object.keys(e).length) this.invalid += 1;
      if (!tr) return;
      $$('[data-k]', tr).forEach(el => {
        const message = e[el.dataset.k];
        el.classList.toggle('is-invalid', !!message);
        if (message) el.setAttribute('aria-invalid', 'true');
        else el.removeAttribute('aria-invalid');
        el.title = message || '';
      });
    });
    return this.invalid;
  },
  focusFirstInvalid() {
    for (const kind of ['physical', 'paths']) {
      const el = $(`#${kind}Table .is-invalid`);
      if (el) {
        this.show(kind);
        // Scroll to the middle, so the row is not hidden behind the sticky action bar.
        el.focus({preventScroll: true});
        el.scrollIntoView({block: 'center'});
        return;
      }
    }
  },
};

// Bulk text: physical "pod,node,interface,vlan[,mode][,immediacy]", vPC/TDN "tdn | vlan | mode | immediacy".
const Bulk = {
  value(v) { v = String(v ?? '').trim(); const i = v.indexOf('='); return i >= 0 ? v.slice(i + 1).trim() : v; },
  vlan(v) { return this.value(v).replace(/^vlan[-_ ]?/i, ''); },
  split(line) { return (line.includes('|') ? line.split('|') : line.split(',')).map(s => s.trim()); },
  parse(kind, text) {
    const rows = [], warnings = [];
    const start = kind === 'physical' ? 4 : 2;
    text.split(/\r?\n/).forEach((raw, n) => {
      const line = raw.trim();
      if (!line || line.startsWith('#')) return;
      const parts = this.split(line);
      if (parts.length < start) {
        warnings.push(`Line ${n + 1} skipped (needs at least ${start} columns): ${line}`);
        return;
      }
      let mode = '', immediacy = '';
      parts.slice(start).forEach(p => {
        const kv = p.match(/^([a-z_]+)\s*=\s*(.*)$/i);
        const key = kv ? kv[1].toLowerCase() : '';
        const val = (kv ? kv[2] : p).trim().toLowerCase();
        if (key === 'mode' || (!kv && val && !['immediate', 'lazy'].includes(val))) mode = val;
        else if (['immediacy', 'deployment', 'deployment_immediacy'].includes(key) || (!kv && val)) immediacy = val;
      });
      const row = Bindings.newRow(kind, kind === 'physical'
        ? {pod: this.value(parts[0]).replace(/^pod[-_]?/i, ''), node: this.value(parts[1]).replace(/^(node|paths)[-_]?/i, ''), interface: this.value(parts[2]), vlan: this.vlan(parts[3])}
        : {tdn: this.value(parts[0]), vlan: this.vlan(parts[1])});
      if (mode) {
        if (MODE_ALIASES[mode]) row.mode = MODE_ALIASES[mode];
        else warnings.push(`Line ${n + 1}: unknown mode '${mode}', using ${MODE_LABEL[row.mode]}`);
      }
      if (immediacy) {
        if (['immediate', 'lazy'].includes(immediacy)) row.immediacy = immediacy;
        else warnings.push(`Line ${n + 1}: unknown immediacy '${immediacy}', using ${IMMEDIACY_LABEL[row.immediacy]}`);
      }
      rows.push(row);
    });
    return {rows, warnings};
  },
  text(kind) {
    return Bindings[kind].map(r => (kind === 'physical'
      ? [r.pod, r.node, r.interface, r.vlan, r.mode, r.immediacy].join(',')
      : [r.tdn, `vlan-${r.vlan}`, r.mode, r.immediacy].join(' | '))).join('\n');
  },
};

// Icon of a product card: VMware, Red Hat OpenStack (RHOSO), OpenStack, or a product users added for another platform.
const productGlyph = p => (/vmware/i.test(p.platform) ? 'cpu' : /red hat|rhoso/i.test(`${p.platform} ${p.label}`) ? 'server'
  : /openstack/i.test(p.platform) || !p.custom ? 'cloud' : 'layers');

// Product templates: pick Acme Flex / Acme Prime / RHOSO, enter the VLAN once, and the binding table is filled for the site.
const Products = {
  list: [],
  current: '',
  vlanAuto: true,
  lastEpg: null,
  init() {
    $('#productPicker').addEventListener('change', e => {
      if (e.target.name === 'product') this.select(e.target.value);
    });
    $('#productVlan').addEventListener('input', () => {
      this.vlanAuto = false;
      this.applyVlan();
    });
    $('#productGroups').addEventListener('change', e => {
      if (e.target.matches('input[data-group]')) this.fillTable();
    });
    $('#spTemplatesBtn').addEventListener('click', () => {
      Tabs.show('templates');
      run(null, () => Templates.open(this.current));
    });
    $('#productGroups').addEventListener('click', e => {
      const btn = e.target.closest('[data-toggle]');
      if (!btn) return;
      const open = btn.getAttribute('aria-expanded') !== 'true';
      btn.setAttribute('aria-expanded', String(open));
      $(`#tplPaths${btn.dataset.toggle}`).hidden = !open;
    });
    this.render();
  },
  product() { return this.list.find(p => p.id === this.current); },
  count(p) {
    const paths = p.groups.filter(g => g.default).flatMap(g => g.paths).filter(x => x.exists);
    const ports = paths.filter(x => !x.tdn.includes('/protpaths-')).length;
    return [ports && plural(ports, 'port'), paths.length - ports && plural(paths.length - ports, 'vPC')].filter(Boolean).join(' + ') || 'empty';
  },
  async onSite() {
    this.list = [];
    this.render(true);
    try {
      this.list = (await api('/api/templates')).products;
    } finally {
      this.render();
    }
    this.syncEpg(true);
    const p = this.product();
    if (!this.current) return;
    if (p && p.groups.length) {
      this.renderGroups();
      this.fillTable();
      toast(`${p.label} template updated for site ${Site.current}.`, 'info');
    } else {
      toast(`No template for site ${Site.current} yet; the binding table was cleared.`);
      this.current = '';
      Bindings.clearAll();
      this.render();
    }
  },
  // After a template or product was changed on Fabric → Templates: the cards show the new templates, and a binding table
  // filled from the changed product is filled again (the VLAN is kept).
  async reload(changedId) {
    this.list = (await api('/api/templates')).products;
    const p = this.product();
    if (this.current && (!p || !p.groups.length)) {
      this.current = '';
      Bindings.clearAll();
      toast(`Static Port: the product of the binding table has no template on ${Site.current} any more; the table was cleared.`, 'info');
    }
    this.render();
    if (p && p.groups.length && this.current === changedId) {
      this.renderGroups();
      this.fillTable();
      toast(`Static Port: the binding table was filled again from the new ${p.label} template.`, 'info');
    }
  },
  render(loading = false) {
    if (loading) {
      $('#productPicker').innerHTML = '<div class="loading">Loading product templates…</div>';
      $('#productBody').hidden = true;
      return;
    }
    const cards = this.list.map(p => {
      const ready = p.groups.length > 0;
      const glyph = productGlyph(p);
      const sub = ready ? `${p.platform} · ${this.count(p)}` : `No template for ${Site.current} yet`;
      return `<label class="product-opt"><input type="radio" name="product" value="${esc(p.id)}"${this.current === p.id ? ' checked' : ''}${ready ? '' : ' disabled'}>`
        + `<span class="product-card"><span class="product-icon">${icon(glyph)}</span><span class="product-text"><b>${esc(p.label)}</b><span class="muted">${esc(sub)}</span></span></span></label>`;
    });
    cards.push(`<label class="product-opt"><input type="radio" name="product" value=""${this.current ? '' : ' checked'}>`
      + `<span class="product-card"><span class="product-icon">${icon('edit')}</span><span class="product-text"><b>Manual</b><span class="muted">Add your own paths</span></span></span></label>`);
    $('#productPicker').innerHTML = cards.join('');
    $('#productBody').hidden = !this.current;
    if (!this.current) {
      $('#productInfo').textContent = 'Select a product to fill in all paths at once';
      $('#bindingSource').textContent = '';
    }
  },
  renderGroups() {
    const p = this.product();
    $('#productGroups').innerHTML = p.groups.map((g, i) => {
      const ok = g.paths.filter(x => x.exists).length, missing = g.paths.length - ok;
      const ports = g.paths.filter(x => !x.tdn.includes('/protpaths-')).length, vpcs = g.paths.length - ports;
      return '<div class="tpl-group"><div class="tpl-head">'
        + `<label class="tpl-check"><input type="checkbox" data-group="${i}"${g.default && ok ? ' checked' : ''}${ok ? '' : ' disabled'}><span class="tpl-name">${esc(g.name)}</span></label>`
        + (g.default ? '' : '<span class="badge">Optional</span>')
        + (missing ? `<span class="badge badge-danger" title="Not found in the ${esc(Site.current)} fabric; will not be bound">${missing} missing on APIC</span>` : '')
        + `<span class="tpl-count">${[ports && plural(ports, 'port'), vpcs && plural(vpcs, 'vPC')].filter(Boolean).join(' + ')}</span>`
        + `<button type="button" class="btn-icon" data-toggle="${i}" aria-expanded="false" aria-controls="tplPaths${i}" aria-label="Show paths for ${esc(g.name)}">${icon('chevron')}</button></div>`
        + `<div class="tpl-paths" id="tplPaths${i}" hidden>`
        + (missing ? `<p class="tpl-note">Struck-through paths do not currently exist in the ${esc(Site.current)} fabric (their policy group was deleted or is not attached to a port), so they will not be bound.</p>` : '')
        + `${g.paths.map(x => `<span class="mono${x.exists ? '' : ' is-missing'}">${esc(x.tdn)}</span>`).join('')}</div></div>`;
    }).join('');
  },
  async select(id) {
    const manualRows = Bindings.physical.length + Bindings.paths.length;
    if (id && !this.current && manualRows && !await confirmDialog({title: 'Replace table contents?',
      body: `The ${plural(manualRows, 'manually entered row')} in the table will be replaced by the ${this.list.find(p => p.id === id)?.label} template.`,
      confirmLabel: 'Replace with template'})) {
      this.render();
      return;
    }
    this.current = id;
    this.render();
    if (!id) return;
    this.renderGroups();
    this.syncEpg(true);
    this.fillTable();
    if (!$('#productVlan').value.trim()) $('#productVlan').focus();
  },
  // VLAN suggestion from the number at the end of the EPG name, for example "Acme-Flex-1841" or "2019009535-1210".
  syncEpg(force = false) {
    const epg = $('#spEpg').value;
    const changed = epg !== this.lastEpg;
    if (!force && !changed) return;
    this.lastEpg = epg;
    const match = epg.match(/(?:^|\D)(\d{1,4})$/);
    const suggestion = match && validVlan(match[1]) ? String(Number(match[1])) : '';
    const current = $('#productVlan').value.trim();
    if (suggestion && (this.vlanAuto || changed)) {
      // Another EPG: the VLAN from its name is more likely right than the VLAN of the previous EPG.
      $('#productVlan').value = suggestion;
      this.vlanAuto = true;
      $('#productVlanHint').textContent = `Suggested from the EPG name "${epg}". Change it if it differs.`;
    } else if (this.vlanAuto || !current) {
      $('#productVlan').value = '';
      this.vlanAuto = true;
      $('#productVlanHint').textContent = 'Enter the VLAN encap for this EPG.';
    } else if (changed && epg) {
      $('#productVlanHint').textContent = `EPG changed to "${epg}": make sure VLAN ${current} is still correct.`;
    }
    this.applyVlan(false);
  },
  applyVlan(userTyped = true) {
    const vlan = $('#productVlan').value.trim();
    $('#productVlan').classList.toggle('is-invalid', !!vlan && !validVlan(vlan));
    if (userTyped) $('#productVlanHint').textContent = vlan && !validVlan(vlan) ? 'VLAN must be a number from 1 to 4094.' : 'Used for all paths in the table.';
    this.hintText = $('#productVlanHint').textContent;
    VlanCheck.scheduleTools();
    this.vlanHint();
    if (!this.current) return;
    [...Bindings.physical, ...Bindings.paths].forEach(r => { r.vlan = vlan; });
    Bindings.render('physical');
    Bindings.render('paths');
  },
  // The template VLAN is checked on APIC as soon as it is filled in: in use by another EPG = red, with where.
  vlanHint() {
    const vlan = $('#productVlan').value.trim();
    if (!vlan || !validVlan(vlan)) return;
    const check = VlanCheck.field(vlan);
    $('#productVlan').classList.toggle('is-invalid', check.blocked);
    vlanHint($('#productVlanHint'), check, this.hintText);
  },
  fillTable() {
    const p = this.product();
    if (!p) return;
    const vlan = $('#productVlan').value.trim();
    const checked = new Set($$('#productGroups input[data-group]:checked').map(i => Number(i.dataset.group)));
    const seen = new Set(), physical = [], paths = [];
    p.groups.forEach((g, i) => {
      if (!checked.has(i)) return;
      g.paths.forEach(({tdn, exists}) => {
        if (!exists || seen.has(tdn)) return;
        seen.add(tdn);
        const base = {vlan, mode: p.mode, immediacy: p.immediacy};
        const m = tdn.match(SIMPLE_PHYSICAL);
        if (m) physical.push(Bindings.newRow('physical', {pod: m[1], node: m[2], interface: m[3], ...base}));
        else paths.push(Bindings.newRow('paths', {tdn, ...base}));
      });
    });
    Bindings.physical = physical;
    Bindings.paths = paths;
    Bindings.render('physical');
    Bindings.render('paths');
    Bindings.show(physical.length ? 'physical' : 'paths');
    $('#bindingSource').textContent = `· ${p.label} template · ${Site.current}`;
    $('#productInfo').textContent = `${plural(physical.length + paths.length, 'path')} will be bound (${plural(physical.length, 'port')}, ${plural(paths.length, 'vPC')})`;
  },
};

const StaticPort = {
  target: null,
  tool: null,
  searchItems: [],
  existingItems: [],
  init() {
    this.target = cascade(['#spTenant', '#spApp', '#spEpg'],
      {tenant: 'Select a tenant', app: 'Select an app profile', epg: 'Select an EPG', appWait: 'Select a tenant first', epgWait: 'Select an app profile first'});
    fill($('#spDefMode'), MODES, null, x => x[0], x => x[1]);
    fill($('#spDefImm'), IMMEDIACY, null, x => x[0], x => x[1]);
    choose($('#spDefMode'), localStore.get('aci_def_mode'));
    choose($('#spDefImm'), localStore.get('aci_def_imm'));
    $('#spDefMode').addEventListener('change', e => localStore.set('aci_def_mode', e.target.value));
    $('#spDefImm').addEventListener('change', e => localStore.set('aci_def_imm', e.target.value));
    Bindings.init();
    Products.init();
    VlanSuggest.init();

    $$('[data-tool]').forEach(b => b.addEventListener('click', () => this.openTool(b.dataset.tool)));
    $('#addRowBtn').addEventListener('click', () => {
      Bindings.add(Bindings.kind, [Bindings.newRow(Bindings.kind)]);
      $(`#${Bindings.kind}Table tbody tr:last-child input`)?.focus();
    });
    $('#searchBtn').addEventListener('click', e => run(e.currentTarget, () => this.search()));
    $('#searchQ').addEventListener('keydown', e => {
      if (e.key === 'Enter') { e.preventDefault(); $('#searchBtn').click(); }
    });
    $('#searchAll').addEventListener('change', e => {
      $$('#searchResults input').forEach(i => { i.checked = e.target.checked; });
      this.updateSearchAdd();
    });
    $('#searchResults').addEventListener('change', () => this.updateSearchAdd());
    $('#searchVlan').addEventListener('input', () => { this.updateSearchAdd(); VlanCheck.scheduleTools(); });
    $('#searchAdd').addEventListener('click', () => this.addSearched());
    ['#rgPod', '#rgNode', '#rgFrom', '#rgTo', '#rgVlan'].forEach(id => $(id).addEventListener('input', () => this.rangePreview()));
    $('#rgVlan').addEventListener('input', () => VlanCheck.scheduleTools());
    $('#rgAdd').addEventListener('click', () => this.addRange());
    $('#bulkAdd').addEventListener('click', () => this.addBulk());
    $('#bulkCopy').addEventListener('click', () => {
      $('#bulkText').value = Bulk.text(Bindings.kind);
      $('#bulkText').focus();
    });
    $('#spExistingBtn').addEventListener('click', e => run(e.currentTarget, () => this.existing()));
    $('#spExisting').addEventListener('click', e => {
      const act = e.target.closest('[data-act]')?.dataset.act;
      if (act === 'copy-existing') this.copyExisting();
      if (act === 'close-existing') $('#spExisting').hidden = true;
    });
    ['#spTenant', '#spApp', '#spEpg'].forEach(id => $(id).addEventListener('change', () => {
      $('#spExisting').hidden = true;
      VlanSuggest.close();   // its VLANs were for the previous EPG
      VlanCheck.refresh();   // another EPG: its own VLANs are allowed, the others are checked again
      VlanCheck.schedule();
      VlanCheck.scheduleTools();
    }));
    $('#clearRows').addEventListener('click', async () => {
      const total = Bindings.physical.length + Bindings.paths.length;
      if (total && await confirmDialog({title: 'Remove all rows?', body: `${plural(total, 'binding row')} will be removed from the table. Nothing has been sent to APIC yet.`,
        confirmLabel: 'Remove all rows', danger: true})) Bindings.clearAll();
    });
    $('#spReviewBtn').addEventListener('click', e => run(e.currentTarget, () => this.review()));
    Bindings.show('physical');
    this.rangePreview();
  },
  async onSite(tenants) {
    $('#spExisting').hidden = true;
    VlanSuggest.close();
    this.searchItems = [];
    this.renderSearch();
    await this.target.onSite(tenants);
    await Products.onSite();
  },
  onKind() {
    const physical = Bindings.kind === 'physical';
    if (!physical && this.tool === 'range') this.openTool('range');
    $('#searchLabel').textContent = physical ? 'Search interface / port-channel / FEX' : 'Search vPC';
    $('#searchQ').placeholder = physical ? 'e.g. eth1/13, paths-101, PC-SERVER' : 'e.g. Openstack-Traffic, protpaths-103-104';
    $('#bulkHint').innerHTML = physical
      ? 'Format <code>pod,node,interface,vlan[,mode][,immediacy]</code>, e.g. <code>1,106,eth1/17,25,trunk,immediate</code>'
      : 'Format <code>path_tdn | vlan | mode | immediacy</code>, e.g. <code>topology/pod-1/protpaths-103-104/pathep-[PG-A] | vlan-11 | trunk</code>';
    $('#bulkText').placeholder = physical ? '1,106,eth1/17,25,trunk,immediate\n1,106,eth1/18,25' : 'topology/pod-1/protpaths-103-104/pathep-[PG-A] | vlan-11 | trunk | immediate';
    $('#bulkWarnings').innerHTML = '';
    this.searchItems = [];
    this.renderSearch();
  },
  openTool(name) {
    VlanSuggest.close();
    this.tool = this.tool === name ? null : name;
    $$('.tool-panel').forEach(p => { p.hidden = p.id !== `tool-${this.tool}`; });
    $$('[data-tool]').forEach(b => {
      const on = b.dataset.tool === this.tool;
      b.setAttribute('aria-expanded', String(on));
      b.classList.toggle('is-active', on);
    });
    const focus = {search: '#searchQ', range: '#rgNode', bulk: '#bulkText'}[this.tool];
    if (focus) $(focus).focus();
  },
  renderSearch(loading = false) {
    const items = this.searchItems;
    $('#searchResults').innerHTML = loading ? `<div class="loading">Searching ${esc(Site.current)}…</div>`
      : items.length ? items.map((x, i) => `<label class="check-item"><input type="checkbox" value="${i}"><span class="mono">${esc(x.dn)}</span>`
        + (x.descr ? `<span class="muted">${esc(x.descr)}</span>` : '') + '</label>').join('')
        : `<div class="empty-inline">${this.searched ? `No matching paths on ${esc(Site.current)}.` : 'Enter a keyword, then click Search. Leave it empty to list all paths.'}</div>`;
    $('#searchInfo').textContent = items.length ? `${plural(items.length, 'path')} found${items.length >= 300 ? ', limited to 300 — narrow the keyword' : ''}` : '';
    $('#searchAll').checked = false;
    $('#searchAll').disabled = !items.length;
    this.updateSearchAdd();
  },
  async search() {
    const kind = Bindings.kind === 'physical' ? 'physical' : 'vpc';
    this.searched = true;
    this.searchItems = [];
    this.renderSearch(true);
    try {
      this.searchItems = (await api('/api/paths?' + qs({kind, q: $('#searchQ').value}))).items;
    } finally {
      this.renderSearch();
    }
  },
  updateSearchAdd() {
    const count = $$('#searchResults input:checked').length;
    const vlan = $('#searchVlan').value.trim();
    const check = VlanCheck.field(vlan);
    $('#searchVlan').classList.toggle('is-invalid', (!!vlan && !validVlan(vlan)) || check.blocked);
    $('#searchAdd').disabled = !count || !validVlan(vlan) || check.blocked;
    $('#searchAddLabel').textContent = count ? `Add ${plural(count, 'path')}` : 'Add';
    vlanHint($('#searchVlanHint'), check);
  },
  // Plain physical paths go to the Physical/PC table; FEX and vPC paths go to the Path TDN table.
  addRows(entries) {
    const physical = [], paths = [];
    entries.forEach(({dn, ...rest}) => {
      const m = dn.match(SIMPLE_PHYSICAL);
      if (m) physical.push(Bindings.newRow('physical', {pod: m[1], node: m[2], interface: m[3], ...rest}));
      else paths.push(Bindings.newRow('paths', {tdn: dn, ...rest}));
    });
    if (physical.length) Bindings.add('physical', physical);
    if (paths.length) Bindings.add('paths', paths);
    const where = [];
    if (physical.length) where.push(`${physical.length} to Physical / Port-Channel`);
    if (paths.length) where.push(`${paths.length} to vPC / Path TDN`);
    return where.join(', ');
  },
  addSearched() {
    const vlan = $('#searchVlan').value.trim();
    const picked = $$('#searchResults input:checked').map(i => ({dn: this.searchItems[Number(i.value)].dn, vlan}));
    const where = this.addRows(picked);
    $$('#searchResults input:checked').forEach(i => { i.checked = false; });
    $('#searchAll').checked = false;
    this.updateSearchAdd();
    toast(`${plural(picked.length, 'path')} added (${where}).`, 'success');
  },
  rangeRows() {
    const pod = $('#rgPod').value.trim() || '1', node = $('#rgNode').value.trim(), vlan = $('#rgVlan').value.trim();
    const from = $('#rgFrom').value.trim().match(/^(.*\/)(\d+)$/), to = $('#rgTo').value.trim().match(/^(.*\/)(\d+)$/);
    if (!node || !from || !to) return {error: 'Enter the node, first interface, and last interface. Example: node 106, eth1/17 to eth1/35.'};
    if (!int(node)) return {error: 'Node must be a number.'};
    if (from[1] !== to[1]) return {error: `Both interfaces must use the same prefix (${from[1]} and ${to[1]}).`};
    if (!validVlan(vlan)) return {error: 'Enter a VLAN from 1 to 4094.'};
    const [a, b] = [Number(from[2]), Number(to[2])].sort((x, y) => x - y);
    if (b - a >= 200) return {error: 'At most 200 interfaces at a time.'};
    const rows = [];
    for (let i = a; i <= b; i++) rows.push({pod, node, interface: `${from[1]}${i}`, vlan});
    return {rows};
  },
  rangePreview() {
    const r = this.rangeRows();
    const check = VlanCheck.field($('#rgVlan').value);
    $('#rgVlan').classList.toggle('is-invalid', check.blocked);
    $('#rgAdd').disabled = !r.rows || check.blocked;
    $('#rgPreview').classList.toggle('hint-error', check.blocked);
    $('#rgPreview').textContent = check.blocked ? check.text : r.rows
      ? `Will add ${plural(r.rows.length, 'interface')}: ${r.rows[0].interface}${r.rows.length > 1 ? ` to ${r.rows[r.rows.length - 1].interface}` : ''} on node ${r.rows[0].node}, VLAN ${r.rows[0].vlan}.`
        + (check.text && !check.blocked ? ` ${check.text}` : '')
      : r.error;
  },
  addRange() {
    const r = this.rangeRows();
    if (!r.rows) return;
    Bindings.add('physical', r.rows.map(x => Bindings.newRow('physical', x)));
    toast(`${plural(r.rows.length, 'interface')} added to the table.`, 'success');
  },
  addBulk() {
    const kind = Bindings.kind;
    const {rows, warnings} = Bulk.parse(kind, $('#bulkText').value);
    if (rows.length) Bindings.add(kind, rows);
    $('#bulkWarnings').innerHTML = warnings.length
      ? alertBox('warning', `<b>${plural(warnings.length, 'line')} to check</b><ul>${warnings.map(w => `<li>${esc(w)}</li>`).join('')}</ul>`) : '';
    if (rows.length) toast(`${plural(rows.length, 'row')} added from bulk text.`, 'success');
    else if (!warnings.length) toast('Bulk text is empty.', 'info');
  },
  async existing() {
    const v = this.target.values();
    const items = (await api('/api/static-port/existing?' + qs(v))).items;
    this.existingItems = items;
    const panel = $('#spExisting');
    panel.innerHTML = `<div class="subpanel-head"><div><b>Existing bindings</b> <span class="muted">${esc(v.epg)} · ${plural(items.length, 'path')} · site ${esc(Site.current)}</span></div>`
      + '<div class="subpanel-actions">'
      + (items.length ? `<button type="button" class="btn btn-secondary btn-sm" data-act="copy-existing">${icon('copy')}Copy to table for editing</button>` : '')
      + `<button type="button" class="btn-icon" data-act="close-existing" aria-label="Close existing bindings">${icon('x')}</button></div></div>`
      + (items.length
        ? '<div class="table-wrap table-scroll-sm"><table class="table table-data"><thead><tr><th>Path</th><th>Encap</th><th>Mode</th><th>Immediacy</th></tr></thead><tbody>'
          + items.map(b => `<tr><td class="mono">${esc(b.tDn)}</td><td>${esc(b.encap)}</td><td>${esc(MODE_LABEL[b.mode] || b.mode)}</td>`
            + `<td>${esc(IMMEDIACY_LABEL[b.instrImedcy] || b.instrImedcy)}</td></tr>`).join('') + '</tbody></table></div>'
        : `<div class="empty-inline">This EPG has no static bindings on ${esc(Site.current)}.</div>`);
    panel.hidden = false;
  },
  copyExisting() {
    const vlanOf = encap => (String(encap).match(/^vlan-(\d+)$/) || [])[1] || '';
    const where = this.addRows(this.existingItems.map(b => ({dn: b.tDn, vlan: vlanOf(b.encap), mode: b.mode, immediacy: b.instrImedcy})));
    toast(`${plural(this.existingItems.length, 'binding')} copied (${where}). Edit as needed, then click Review & apply.`, 'success');
  },
  request() { return {...this.target.values(), product: Products.current, physical: Bindings.physical, paths: Bindings.paths}; },
  update() {
    const v = this.target ? this.target.values() : {};
    const total = Bindings.physical.length + Bindings.paths.length;
    $('#spContext').innerHTML = v.epg ? crumbs([v.tenant, v.app, v.epg]) : '<span class="muted">Select a tenant, app profile, and EPG</span>';
    $('#spCount').textContent = `${plural(total, 'binding')}${Bindings.invalid ? ` · ${Bindings.invalid} to fix` : ''}`;
    $('#spCount').classList.toggle('is-warning', Bindings.invalid > 0);
    $('#spReviewBtn').disabled = !v.epg || !total;
    $('#spExistingBtn').disabled = !v.epg;
  },
  planHtml(d) {
    const s = d.summary, changes = s.new + s.change;
    return (d.applied ? `<div class="success-state"><span class="success-icon">${icon('check')}</span><div><b>${plural(changes, 'change')} applied to ${esc(d.site)}.</b>`
        + `<div class="muted">${d.audit_id ? `Recorded in History as change #${Number(d.audit_id)}.` : 'Nothing was sent.'}</div></div></div>` : '')
      + siteBanner(d.site, `EPG <code>${esc(d.epg_dn)}</code>`)
      + `<div class="pills"><span class="pill pill-new">${s.new} new</span><span class="pill pill-change">${s.change} changed</span><span class="pill">${s.same} unchanged, skipped</span></div>`
      + (d.applied ? '' : conflictHtml(d.conflicts))
      + (!d.applied && !d.blocked && s.change ? alertBox('warning', `<b>${plural(s.change, 'existing binding')} will be changed.</b> Check the Before column.`) : '')
      + (!d.applied && !changes ? alertBox('info', 'All bindings already match APIC exactly. Nothing needs to be sent.') : '')
      + bindingTable(d.items);
  },
  async review() {
    if (Bindings.validate()) {
      Bindings.focusFirstInvalid();
      throw new Error(`Fix the ${plural(Bindings.invalid, 'invalid row')} marked in red. Hover over a red field to see why.`);
    }
    const d = await api('/api/static-port/preview', this.request());
    const changes = d.summary.new + d.summary.change;
    Review.open({
      title: 'Review static port',
      body: this.planHtml(d),
      confirmLabel: d.blocked ? 'Blocked: VLAN already in use' : changes ? `Apply ${plural(changes, 'change')} to ${d.site}` : 'No changes',
      canConfirm: changes > 0 && !d.blocked,
      onConfirm: async () => {
        const r = await api('/api/static-port/apply', this.request());
        Audit.markStale();
        toast(`Static port bindings applied to ${r.site}.`, 'success');
        return this.planHtml(r);
      },
    });
  },
};

/* =========================================================================
   Product templates (Fabric → Templates): the paths of each product per site
   ========================================================================= */
// The editor works on a copy of a product from Products.list (/api/templates of the site). Rows point to their group by
// a key, so renaming or removing a group never mixes rows up; the groups are sent by position. A template change only
// changes the portal database: Static Port then fills its binding table with the new paths.
const TEMPLATE_STATUS = {new: ['badge-new', 'Added'], delete: ['badge-danger', 'Removed'], moved: ['badge-change', 'Moved'], same: ['', 'Unchanged']};
const GROUP_STATUS = {new: ['badge-new', 'Added'], delete: ['badge-danger', 'Removed'], change: ['badge-change', 'Changed']};
const VPC_TDN = /\/protpaths-/;

const Templates = {
  canEdit: false,
  productId: '',
  groups: [],          // [{key, name, default}]
  physical: [],        // [{group: key, pod, node, interface}]
  paths: [],           // [{group: key, tdn}]
  saved: new Set(),    // paths of the saved template (a missing one there is only flagged, a missing new one blocks)
  baseline: '',
  version: 0,
  nextKey: 1,
  defGroup: 0,
  kind: 'physical',
  tool: null,
  searchItems: [],
  searched: false,
  invalid: 0,
  exists: new Map(),   // `${site}|${tdn}` -> true / false, from APIC
  pending: new Set(),
  checkError: '',
  timer: null,
  labels: {pod: 'Pod', node: 'Node', interface: 'Interface', tdn: 'Path TDN', group: 'Group', name: 'Group name'},
  init() {
    $('#tpPicker').addEventListener('change', e => {
      if (e.target.name === 'tpProduct') run(null, () => this.open(e.target.value));
    });
    const groups = $('#tpGroupsTable tbody');
    const editGroup = e => {
      const tr = e.target.closest('tr[data-key]');
      if (!tr || !e.target.dataset.k) return;
      const g = this.group(Number(tr.dataset.key));
      if (e.target.dataset.k === 'default') g.default = e.target.checked;
      else g.name = e.target.value;
      this.renderGroupSelects();
      this.validate();
      this.update();
    };
    groups.addEventListener('input', editGroup);
    groups.addEventListener('change', editGroup);
    groups.addEventListener('click', e => {
      const btn = e.target.closest('button[data-act="del"]');
      if (btn) run(null, () => this.removeGroup(Number(btn.closest('tr').dataset.key)));
    });
    $('#tpAddGroup').addEventListener('click', () => {
      const g = this.addGroup('', true);
      this.defGroup = g.key;
      this.renderAll();
      $(`#tpGroupsTable tr[data-key="${g.key}"] input[data-k="name"]`)?.focus();
    });
    $('#tpDefGroup').addEventListener('change', e => { this.defGroup = Number(e.target.value); });
    $$('#tpKind [role="tab"]').forEach(b => b.addEventListener('click', () => this.show(b.dataset.kind)));
    ['physical', 'paths'].forEach(kind => {
      const tbody = $(`#tp${kind === 'physical' ? 'Physical' : 'Paths'}Table tbody`);
      const edit = e => {
        const tr = e.target.closest('tr[data-i]');
        if (!tr || !e.target.dataset.k) return;
        const row = this[kind][tr.dataset.i];
        row[e.target.dataset.k] = e.target.dataset.k === 'group' ? Number(e.target.value) : e.target.value;
        if (e.target.dataset.k === 'group') this.renderGroups();
        this.changed();
      };
      tbody.addEventListener('input', edit);
      tbody.addEventListener('change', edit);
      tbody.addEventListener('click', e => {
        const btn = e.target.closest('button[data-act="del"]');
        if (!btn) return;
        this[kind].splice(Number(btn.closest('tr').dataset.i), 1);
        this.renderAll();
      });
    });
    $$('[data-tp-tool]').forEach(b => b.addEventListener('click', () => this.openTool(b.dataset.tpTool)));
    $('#tpAddRow').addEventListener('click', () => {
      this.addRows(this.kind, [this.kind === 'physical' ? {pod: '1', node: '', interface: ''} : {tdn: ''}]);
      $(`#tp${this.kind === 'physical' ? 'Physical' : 'Paths'}Table tbody tr:last-child input`)?.focus();
    });
    $('#tpSearchBtn').addEventListener('click', e => run(e.currentTarget, () => this.search()));
    $('#tpSearchQ').addEventListener('keydown', e => {
      if (e.key === 'Enter') { e.preventDefault(); $('#tpSearchBtn').click(); }
    });
    $('#tpSearchAll').addEventListener('change', e => {
      $$('#tpSearchResults input:not(:disabled)').forEach(i => { i.checked = e.target.checked; });
      this.updateSearchAdd();
    });
    $('#tpSearchResults').addEventListener('change', () => this.updateSearchAdd());
    $('#tpSearchAdd').addEventListener('click', () => this.addSearched());
    ['#tpRgPod', '#tpRgNode', '#tpRgFrom', '#tpRgTo'].forEach(id => $(id).addEventListener('input', () => this.rangePreview()));
    $('#tpRgAdd').addEventListener('click', () => this.addRange());
    $('#tpBulkAdd').addEventListener('click', () => this.addBulk());
    $('#tpBulkCopy').addEventListener('click', () => {
      $('#tpBulkText').value = this.text(this.kind);
      $('#tpBulkText').focus();
    });
    $('#tpClearRows').addEventListener('click', async () => {
      const total = this.physical.length + this.paths.length;
      if (total && await confirmDialog({title: 'Remove all rows?', body: `${plural(total, 'path')} will be removed from the template. Nothing is saved until you review and save.`,
        confirmLabel: 'Remove all rows', danger: true})) {
        this.physical = [];
        this.paths = [];
        this.renderAll();
      }
    });
    $('#tpReviewBtn').addEventListener('click', e => run(e.currentTarget, () => this.review()));
    $('#tpResetBtn').addEventListener('click', e => run(e.currentTarget, () => this.review(true)));
    $('#tpDiscardBtn').addEventListener('click', async () => {
      if (await this.confirmDiscard()) this.load(this.product());
    });
    $('#tpNewProduct').addEventListener('click', async () => {
      if (await this.confirmDiscard('A new product opens empty.')) ProductDialog.open();
    });
    $('#tpSettingsBtn').addEventListener('click', () => ProductDialog.open(this.product()));
    this.show('physical');
    this.rangePreview();
    this.setAccess(false);
  },
  // Administrators, and accounts with the permission "ACI: edit product templates"; everyone else can look.
  setAccess(canEdit) {
    if (this.canEdit === canEdit && this.accessSet) return;
    this.accessSet = true;
    this.canEdit = canEdit;
    $$('[data-tp-edit]').forEach(el => { el.hidden = !canEdit; });
    if (!canEdit && this.tool) this.openTool(this.tool);
    $('#spTemplatesLabel').textContent = canEdit ? 'Edit templates' : 'View templates';
    $('#tpNotice').innerHTML = canEdit ? '' : alertBox('info', 'You can view the templates. Only administrators and accounts with the permission '
      + '<b>ACI: edit product templates</b> (ticked by an administrator on the Users page) can change them.');
    if (this.productId) this.renderAll();
  },
  product() { return Products.list.find(p => p.id === this.productId); },
  group(key) { return this.groups.find(g => g.key === key); },
  addGroup(name, isDefault) {
    const g = {key: this.nextKey++, name, default: isDefault};
    this.groups.push(g);
    return g;
  },
  rowsOf(key) { return [...this.physical, ...this.paths].filter(r => r.group === key).length; },
  key(tdn) { return `${Site.current}|${tdn}`; },
  tdnOf(kind, r) {
    if (kind === 'paths') return String(r.tdn).trim();
    const iface = String(r.interface).trim().replace(/^eth/i, 'eth');
    return `topology/pod-${String(r.pod).trim() || '1'}/paths-${String(r.node).trim()}/pathep-[${iface}]`;
  },
  allTdns() { return [...this.physical.map(r => this.tdnOf('physical', r)), ...this.paths.map(r => this.tdnOf('paths', r))]; },
  groupOfTdn(tdn) {
    const row = [...this.physical.map(r => [this.tdnOf('physical', r), r]), ...this.paths.map(r => [this.tdnOf('paths', r), r])].find(([t]) => t === tdn);
    return row ? this.group(row[1].group) : null;
  },
  // Unsaved changes: the editor differs from the template as it was loaded.
  serialize() { const {version, ...rest} = this.request(); return JSON.stringify(rest); },
  dirty() { return Boolean(this.canEdit && this.productId && this.baseline && this.serialize() !== this.baseline); },
  async confirmDiscard(what = '') {
    if (!this.dirty()) return true;
    const p = this.product();
    return confirmDialog({title: 'Discard unsaved changes?', body: `The changes to the ${p ? p.label : ''} template on ${Site.current} have not been saved. ${what}`.trim(),
      confirmLabel: 'Discard changes', danger: true});
  },
  // The site changed (after Products.list was loaded for it): the same product, as saved on that site.
  onSite() {
    // The same site loaded again (e.g. after a provisioning apply): unsaved template changes stay as they are.
    if (this.dirty() && this.loadedSite === Site.current && this.product()) {
      this.renderPicker();
      this.update();
      return;
    }
    this.searchItems = [];
    this.searched = false;
    this.renderSearch();
    if (!Products.list.some(p => p.id === this.productId)) this.productId = '';
    if (!this.productId && !$('#tab-templates').hidden) this.productId = Products.list[0]?.id || '';
    this.load(this.product());
  },
  onShow() {
    if (!this.productId && Products.list.length) {
      this.productId = Products.list[0].id;
      this.load(this.product());
    }
    this.renderPicker();
    this.update();
  },
  async open(id) {
    id = id || this.productId || Products.list[0]?.id || '';
    if (id === this.productId && this.baseline) return this.renderPicker();
    if (!await this.confirmDiscard('Opening another product loads its saved template.')) return this.renderPicker();
    this.productId = id;
    this.load(this.product());
  },
  load(p) {
    this.loadedSite = Site.current;
    this.groups = [];
    this.physical = [];
    this.paths = [];
    this.saved = new Set();
    this.baseline = '';
    this.version = 0;
    if (p) {
      this.version = p.version;
      p.groups.forEach(g => {
        const group = this.addGroup(g.name, g.default);
        g.paths.forEach(({tdn, exists}) => {
          this.saved.add(tdn);
          this.exists.set(this.key(tdn), exists);
          const m = tdn.match(SIMPLE_PHYSICAL);
          if (m) this.physical.push({group: group.key, pod: m[1], node: m[2], interface: m[3]});
          else this.paths.push({group: group.key, tdn});
        });
      });
      // An empty template starts with one group, so rows can be added at once.
      if (!this.groups.length) this.addGroup(p.label, true);
      this.defGroup = this.groups[0].key;
      this.baseline = this.serialize();
    }
    this.renderAll();
    if (p) this.show(this.physical.length || !this.paths.length ? 'physical' : 'paths');
  },
  changed() {
    this.validate();
    this.renderStatus();
    this.update();
    this.scheduleCheck();
  },
  addRows(kind, rows) {
    if (!this.groups.length) this.defGroup = this.addGroup(this.product()?.label || 'Paths', true).key;
    if (!this.group(this.defGroup)) this.defGroup = this.groups[0].key;
    this[kind].push(...rows.map(r => ({group: this.defGroup, ...r})));
    this.renderAll();
  },
  async removeGroup(key) {
    const g = this.group(key), n = this.rowsOf(key);
    if (n && !await confirmDialog({title: 'Remove group?', body: `Group "${g.name || 'unnamed'}" and its ${plural(n, 'path')} will be removed from the template. Nothing is saved until you review and save.`,
      confirmLabel: 'Remove group', danger: true})) return;
    this.groups = this.groups.filter(x => x.key !== key);
    this.physical = this.physical.filter(r => r.group !== key);
    this.paths = this.paths.filter(r => r.group !== key);
    if (this.defGroup === key) this.defGroup = this.groups[0]?.key || 0;
    this.renderAll();
  },
  show(kind) {
    this.kind = kind;
    $$('#tpKind [role="tab"]').forEach(b => b.setAttribute('aria-selected', String(b.dataset.kind === kind)));
    $('#tpPhysicalTable').hidden = kind !== 'physical';
    $('#tpPathsTable').hidden = kind !== 'paths';
    $$('[data-tp-only="physical"]').forEach(el => { el.hidden = !this.canEdit || kind !== 'physical'; });
    if (kind !== 'physical' && this.tool === 'range') this.openTool('range');
    const physical = kind === 'physical';
    $('#tpSearchLabel').textContent = physical ? 'Search interface / port-channel / FEX' : 'Search vPC';
    $('#tpSearchQ').placeholder = physical ? 'e.g. eth1/45, paths-118, Po-' : 'e.g. Openstack-Traffic, protpaths-118-119';
    $('#tpBulkHint').innerHTML = physical
      ? 'Format <code>pod,node,interface</code>; an interface range is allowed, e.g. <code>1,118,eth1/17-18</code>'
      : 'Format <code>path_tdn</code>, or <code>pod,node-node,policy_group</code> for a vPC, e.g. <code>1,109-110,VPC-10G-CLOUD-PG</code>';
    $('#tpBulkText').placeholder = physical ? '1,118,eth1/45\n1,119,eth1/45-46' : '1,109-110,VPC-10G-CLOUD-PG\ntopology/pod-1/protpaths-118-119/pathep-[VPC-25G-CLOUD-A-PG]';
    $('#tpBulkWarnings').innerHTML = '';
    this.searchItems = [];
    this.searched = false;
    this.renderSearch();
  },
  openTool(name) {
    this.tool = this.tool === name ? null : name;
    $$('#tpPathsCard .tool-panel').forEach(p => { p.hidden = p.id !== `tp-tool-${this.tool}`; });
    $$('[data-tp-tool]').forEach(b => {
      const on = b.dataset.tpTool === this.tool;
      b.setAttribute('aria-expanded', String(on));
      b.classList.toggle('is-active', on);
    });
    const focus = {search: '#tpSearchQ', range: '#tpRgNode', bulk: '#tpBulkText'}[this.tool];
    if (focus) $(focus).focus();
  },

  // ---- rendering ----
  renderAll() {
    this.renderPicker();
    $('#tpEditor').hidden = !this.productId;
    $('#tpPathsCard').hidden = !this.productId;
    this.renderGroups();
    this.renderRows('physical');
    this.renderRows('paths');
    this.renderGroupSelects();
    this.validate();
    this.renderStatus();
    this.update();
    this.scheduleCheck();
  },
  renderPicker() {
    const total = p => p.groups.reduce((n, g) => n + g.paths.length, 0);
    $('#tpPicker').innerHTML = Products.list.map(p => {
      const n = total(p);
      const sub = [p.platform, n ? plural(n, 'path') : `No paths on ${Site.current} yet`, p.custom ? 'added product' : p.edited ? 'edited' : 'default'].filter(Boolean).join(' · ');
      return `<label class="product-opt"><input type="radio" name="tpProduct" value="${esc(p.id)}"${this.productId === p.id ? ' checked' : ''}>`
        + `<span class="product-card"><span class="product-icon">${icon(productGlyph(p))}</span><span class="product-text"><b>${esc(p.label)}</b><span class="muted">${esc(sub)}</span></span></span></label>`;
    }).join('') || '<div class="empty-inline">No products. Product templates load with the site.</div>';
    const p = this.product();
    $('#tpProductInfo').textContent = !p ? '' : p.edited ? `Saved by ${p.updated_by}, ${fmtTime(p.updated)}`
      : p.custom ? `Added by ${p.created_by}, ${fmtTime(p.created)}` : 'Default template (product_templates.json)';
    $('#tpSettingsBtn').hidden = !this.canEdit || !p || !p.custom;
  },
  renderGroups() {
    const ro = this.canEdit ? '' : ' disabled';
    $('#tpGroupsTable tbody').innerHTML = this.groups.map((g, i) => `<tr data-key="${g.key}"><td class="row-num">${i + 1}</td>`
      + `<td><input class="input" data-k="name" value="${esc(g.name)}" maxlength="80" aria-label="${this.labels.name}, row ${i + 1}" autocomplete="off" spellcheck="false"${ro}></td>`
      + `<td><label class="check"><input type="checkbox" data-k="default"${g.default ? ' checked' : ''}${ro}> Selected by default</label></td>`
      + `<td>${this.rowsOf(g.key)}</td><td class="row-actions">`
      + (this.canEdit ? `<button type="button" class="btn-icon danger" data-act="del" title="Remove group" aria-label="Remove group ${i + 1}">${icon('trash')}</button>` : '')
      + '</td></tr>').join('')
      || `<tr class="empty-row"><td colspan="5"><div class="empty-inline">No groups. ${this.canEdit ? 'Add a group, then add its paths.' : ''}</div></td></tr>`;
  },
  groupOptions(selected) {
    return this.groups.map((g, i) => `<option value="${g.key}"${g.key === selected ? ' selected' : ''}>${esc(g.name.trim() || `Group ${i + 1}`)}</option>`).join('');
  },
  // A group was renamed, added, or removed: the group choices of the rows and of "Group for new rows".
  renderGroupSelects() {
    $('#tpDefGroup').innerHTML = this.groupOptions(this.defGroup);
    $$('#tpPathsCard select[data-k="group"]').forEach(sel => {
      const kind = sel.closest('table').id === 'tpPhysicalTable' ? 'physical' : 'paths';
      const row = this[kind][sel.closest('tr').dataset.i];
      if (row) sel.innerHTML = this.groupOptions(row.group);
    });
  },
  renderRows(kind) {
    const rows = this[kind];
    const id = kind === 'physical' ? 'Physical' : 'Paths';
    const ro = this.canEdit ? '' : ' disabled';
    const cell = (r, i, key, attrs = '') => `<td><input class="input${key === 'tdn' ? ' mono' : ''}" data-k="${key}" value="${esc(r[key])}"`
      + ` aria-label="${this.labels[key]}, row ${i + 1}" autocomplete="off" spellcheck="false"${attrs}${ro}></td>`;
    $(`#tp${id}Table tbody`).innerHTML = rows.map((r, i) => `<tr data-i="${i}"><td class="row-num">${i + 1}</td>`
      + `<td><select class="input" data-k="group" aria-label="${this.labels.group}, row ${i + 1}"${ro}>${this.groupOptions(r.group)}</select></td>`
      + (kind === 'physical' ? cell(r, i, 'pod', ' inputmode="numeric"') + cell(r, i, 'node', ' inputmode="numeric" placeholder="101"')
        + cell(r, i, 'interface', ' placeholder="eth1/1 or PC name"') : cell(r, i, 'tdn', ' placeholder="topology/pod-1/protpaths-101-102/pathep-[PG]"'))
      + '<td class="tp-apic"></td><td class="row-actions">'
      + (this.canEdit ? `<button type="button" class="btn-icon danger" data-act="del" title="Remove row" aria-label="Remove row ${i + 1}">${icon('trash')}</button>` : '')
      + '</td></tr>').join('')
      || `<tr class="empty-row"><td colspan="${kind === 'physical' ? 7 : 5}"><div class="empty">${icon(kind === 'physical' ? 'plug' : 'server')}<div>`
        + `<b>No ${kind === 'physical' ? 'physical / port-channel' : 'vPC / path TDN'} paths in this template</b>`
        + (this.canEdit ? `<p>Add them with Search APIC${kind === 'physical' ? ', Interface range' : ''}, Bulk text, or Blank row.</p>` : '') + '</div></div></td></tr>';
    $(`#tp${id}Count`).textContent = rows.length;
  },
  // APIC column: is the path in this site's fabric? A missing new path blocks the save; a missing saved one is flagged.
  apicState(tdn) {
    const known = this.exists.get(this.key(tdn));
    if (known === true) return '';
    if (this.pending.has(this.key(tdn))) return '<span class="muted">Checking…</span>';
    if (known === false) {
      return this.saved.has(tdn) ? `<span class="badge badge-change" title="Already in the saved template; not bound on Static Port">Not on APIC</span>`
        : `<span class="badge badge-danger" title="Not found in the ${esc(Site.current)} fabric">Not on APIC</span>`;
    }
    return '';
  },
  renderStatus() {
    ['physical', 'paths'].forEach(kind => this[kind].forEach((r, i) => {
      const td = $(`#tp${kind === 'physical' ? 'Physical' : 'Paths'}Table tbody tr[data-i="${i}"] .tp-apic`);
      if (td) td.innerHTML = this.apicState(this.tdnOf(kind, r));
    }));
    const tdns = this.allTdns();
    const missingNew = tdns.filter(t => this.exists.get(this.key(t)) === false && !this.saved.has(t));
    const missingSaved = tdns.filter(t => this.exists.get(this.key(t)) === false && this.saved.has(t));
    let html = '';
    if (missingNew.length) {
      html += alertBox('danger', `<b>${plural(missingNew.length, 'added path')} not in the ${esc(Site.current)} fabric.</b> Fix or remove the red rows; `
        + 'the template cannot be saved until then. Search APIC lists the paths that exist.');
    } else if (tdns.some(t => this.pending.has(this.key(t)))) {
      html += `<p class="hint vlan-checking">${icon('search')} Checking the paths on APIC…</p>`;
    } else if (this.checkError && tdns.length) {
      html += alertBox('warning', `<b>The paths could not be checked on APIC:</b> ${esc(this.checkError)} They are checked again at Review.`);
    }
    if (missingSaved.length) {
      html += alertBox('warning', `<b>${plural(missingSaved.length, 'path')} of the saved template ${missingSaved.length === 1 ? 'is' : 'are'} not in the ${esc(Site.current)} fabric any more.</b> `
        + 'Static Port strikes them through and never binds them. Remove them if they are gone for good.');
    }
    if ($('#tpApicNotice').dataset.html !== html) {
      $('#tpApicNotice').dataset.html = html;
      $('#tpApicNotice').innerHTML = html;
    }
  },
  scheduleCheck() {
    clearTimeout(this.timer);
    this.timer = setTimeout(() => this.check(), 400);
  },
  // New paths (typed, from a range or bulk text) are looked up on APIC, like Search APIC; the server checks again at Review.
  async check() {
    if (!this.productId || !Site.info(Site.current).configured) return;
    const todo = [...new Set(this.allTdns())].filter(t => PATH_TDN.test(t) && !this.exists.has(this.key(t)) && !this.pending.has(this.key(t)));
    if (!todo.length) return;
    todo.forEach(t => this.pending.add(this.key(t)));
    this.renderStatus();
    const site = Site.current;
    try {
      for (let i = 0; i < todo.length; i += 500) {
        const d = await api('/api/paths/check', {tdns: todo.slice(i, i + 500)});
        Object.entries(d.exists).forEach(([t, found]) => this.exists.set(`${site}|${t}`, found));
      }
      this.checkError = '';
    } catch (e) {
      this.checkError = e.message;
    } finally {
      todo.forEach(t => this.pending.delete(`${site}|${t}`));
    }
    this.validate();
    this.renderStatus();
    this.update();
  },
  // Validation in the browser for immediate feedback; the server validates again at Review and Save.
  issues(kind, r) {
    const e = {};
    if (!this.group(r.group)) e.group = 'Choose a group';
    if (kind === 'physical') {
      if (!int(r.pod) || Number(r.pod) < 1) e.pod = 'Pod must be a number, usually 1';
      if (!int(r.node) || Number(r.node) < 1) e.node = 'Node must be a number, e.g. 101';
      if (!/^[A-Za-z0-9_./:-]{1,64}$/.test(String(r.interface).trim())) e.interface = 'Enter an interface (e.g. eth1/1) or a port-channel name';
    } else if (!PATH_TDN.test(String(r.tdn).trim())) {
      e.tdn = 'Format: topology/pod-1/protpaths-101-102/pathep-[PG-name]';
    }
    const tdn = this.tdnOf(kind, r), field = kind === 'physical' ? 'interface' : 'tdn';
    if (!e[field] && this.exists.get(this.key(tdn)) === false && !this.saved.has(tdn)) {
      e[field] = `Not found in the ${Site.current} fabric. Search APIC lists the paths that exist.`;
    }
    return e;
  },
  validate() {
    const results = [], seen = new Map();
    ['physical', 'paths'].forEach(kind => this[kind].forEach((r, i) => {
      const item = {kind, i, e: this.issues(kind, r)};
      results.push(item);
      const tdn = this.tdnOf(kind, r);
      seen.set(tdn, [...(seen.get(tdn) || []), item]);
    }));
    seen.forEach(items => {
      if (items.length > 1) items.forEach(item => { item.e[item.kind === 'physical' ? 'interface' : 'tdn'] = 'This path is in the template more than once'; });
    });
    this.invalid = 0;
    results.forEach(({kind, i, e}) => {
      if (Object.keys(e).length) this.invalid += 1;
      const tr = $(`#tp${kind === 'physical' ? 'Physical' : 'Paths'}Table tbody tr[data-i="${i}"]`);
      if (tr) this.mark(tr, e);
    });
    const names = this.groups.map(g => g.name.trim().toLowerCase());
    this.groups.forEach(g => {
      const e = {};
      if (!g.name.trim()) e.name = 'Enter a group name';
      else if (names.filter(n => n === g.name.trim().toLowerCase()).length > 1) e.name = 'Two groups have this name';
      else if (!this.rowsOf(g.key)) e.name = 'This group has no paths: add paths to it or remove the group';
      if (e.name) this.invalid += 1;
      const tr = $(`#tpGroupsTable tbody tr[data-key="${g.key}"]`);
      if (tr) this.mark(tr, e);
    });
    return this.invalid;
  },
  mark(tr, e) {
    $$('[data-k]', tr).forEach(el => {
      const message = e[el.dataset.k];
      el.classList.toggle('is-invalid', !!message);
      if (message) el.setAttribute('aria-invalid', 'true');
      else el.removeAttribute('aria-invalid');
      el.title = message || '';
    });
  },
  focusFirstInvalid() {
    const group = $('#tpGroupsTable .is-invalid');
    if (group) {
      group.focus({preventScroll: true});
      group.scrollIntoView({block: 'center'});
      return;
    }
    for (const kind of ['physical', 'paths']) {
      const el = $(`#tp${kind === 'physical' ? 'Physical' : 'Paths'}Table .is-invalid`);
      if (el) {
        this.show(kind);
        el.focus({preventScroll: true});
        el.scrollIntoView({block: 'center'});
        return;
      }
    }
  },
  update() {
    const p = this.product();
    if (!p) {
      $('#tpContext').innerHTML = '<span class="muted">Select a product</span>';
      $('#tpCount').textContent = '';
      $('#tpReviewBtn').disabled = true;
      $('#tpDiscardBtn').disabled = true;
      $('#tpResetBtn').hidden = true;
      return;
    }
    const tdns = this.allTdns(), vpcs = tdns.filter(t => VPC_TDN.test(t)).length;
    const dirty = this.dirty();
    $('#tpContext').innerHTML = `<b>${esc(p.label)}</b> · ${plural(tdns.length, 'path')} (${plural(tdns.length - vpcs, 'port')}, ${plural(vpcs, 'vPC')})`;
    $('#tpCount').textContent = (dirty ? 'Unsaved changes' : 'Saved') + (this.invalid ? ` · ${this.invalid} to fix` : '');
    $('#tpCount').classList.toggle('is-warning', this.invalid > 0);
    $('#tpReviewBtn').disabled = !dirty;
    $('#tpDiscardBtn').disabled = !dirty;
    $('#tpResetBtn').hidden = !this.canEdit || p.custom || !p.edited;
  },

  // ---- adding paths ----
  renderSearch(loading = false) {
    const items = this.searchItems;
    $('#tpSearchResults').innerHTML = loading ? `<div class="loading">Searching ${esc(Site.current)}…</div>`
      : items.length ? items.map((x, i) => {
        const g = this.groupOfTdn(x.dn);
        return `<label class="check-item"><input type="checkbox" value="${i}"${g ? ' disabled' : ''}><span class="mono">${esc(x.dn)}</span>`
          + (g ? `<span class="muted">In group ${esc(g.name)}</span>` : x.descr ? `<span class="muted">${esc(x.descr)}</span>` : '') + '</label>';
      }).join('')
        : `<div class="empty-inline">${this.searched ? `No matching paths on ${esc(Site.current)}.` : 'Enter a keyword, then click Search. Leave it empty to list all paths.'}</div>`;
    $('#tpSearchInfo').textContent = items.length ? `${plural(items.length, 'path')} found${items.length >= 300 ? ', limited to 300 — narrow the keyword' : ''}` : '';
    $('#tpSearchAll').checked = false;
    $('#tpSearchAll').disabled = !items.length;
    this.updateSearchAdd();
  },
  async search() {
    this.searched = true;
    this.searchItems = [];
    this.renderSearch(true);
    try {
      this.searchItems = (await api('/api/paths?' + qs({kind: this.kind === 'physical' ? 'physical' : 'vpc', q: $('#tpSearchQ').value}))).items;
    } finally {
      this.renderSearch();
    }
  },
  updateSearchAdd() {
    const count = $$('#tpSearchResults input:checked').length;
    $('#tpSearchAdd').disabled = !count;
    $('#tpSearchAddLabel').textContent = count ? `Add ${plural(count, 'path')}` : 'Add';
  },
  // Plain physical paths go to the Physical / Port-Channel table; FEX and vPC paths go to the Path TDN table.
  addTdns(tdns) {
    const physical = [], paths = [];
    tdns.forEach(tdn => {
      const m = tdn.match(SIMPLE_PHYSICAL);
      if (m) physical.push({pod: m[1], node: m[2], interface: m[3]});
      else paths.push({tdn});
    });
    if (physical.length) this.addRows('physical', physical);
    if (paths.length) this.addRows('paths', paths);
    return [physical.length && `${physical.length} to Physical / Port-Channel`, paths.length && `${paths.length} to vPC / Path TDN`].filter(Boolean).join(', ');
  },
  addSearched() {
    const picked = $$('#tpSearchResults input:checked').map(i => this.searchItems[Number(i.value)].dn);
    picked.forEach(t => this.exists.set(this.key(t), true));   // from APIC: they exist
    const where = this.addTdns(picked);
    this.renderSearch();
    toast(`${plural(picked.length, 'path')} added to group ${this.group(this.defGroup)?.name || ''} (${where}).`, 'success');
  },
  rangeRows() {
    const pod = $('#tpRgPod').value.trim() || '1', node = $('#tpRgNode').value.trim();
    const from = $('#tpRgFrom').value.trim().match(/^(.*\/)(\d+)$/), to = $('#tpRgTo').value.trim().match(/^(.*\/)(\d+)$/);
    if (!node || !from || !to) return {error: 'Enter the node, first interface, and last interface. Example: node 118, eth1/17 to eth1/24.'};
    if (!int(node)) return {error: 'Node must be a number.'};
    if (from[1] !== to[1]) return {error: `Both interfaces must use the same prefix (${from[1]} and ${to[1]}).`};
    const [a, b] = [Number(from[2]), Number(to[2])].sort((x, y) => x - y);
    if (b - a >= 200) return {error: 'At most 200 interfaces at a time.'};
    const rows = [];
    for (let i = a; i <= b; i++) rows.push({pod, node, interface: `${from[1]}${i}`});
    return {rows};
  },
  rangePreview() {
    const r = this.rangeRows();
    $('#tpRgAdd').disabled = !r.rows;
    $('#tpRgPreview').textContent = r.rows
      ? `Will add ${plural(r.rows.length, 'interface')}: ${r.rows[0].interface}${r.rows.length > 1 ? ` to ${r.rows[r.rows.length - 1].interface}` : ''} on node ${r.rows[0].node}; each is checked on APIC.`
      : r.error;
  },
  addRange() {
    const r = this.rangeRows();
    if (!r.rows) return;
    this.addRows('physical', r.rows);
    toast(`${plural(r.rows.length, 'interface')} added to group ${this.group(this.defGroup)?.name || ''}.`, 'success');
  },
  // Bulk text: physical "pod,node,interface" (an interface range like eth1/17-18 is expanded); vPC / TDN "path_tdn" or
  // "pod,node-node,policy_group".
  parseBulk(kind, text) {
    const rows = [], warnings = [];
    text.split(/\r?\n/).forEach((raw, n) => {
      const line = raw.trim();
      if (!line || line.startsWith('#')) return;
      const parts = Bulk.split(line).map(p => Bulk.value(p));
      if (kind === 'paths') {
        if (PATH_TDN.test(line)) return rows.push({tdn: line});
        const m = parts.length === 3 && int(parts[0].replace(/^pod[-_]?/i, '')) && parts[1].match(/^(?:protpaths-)?(\d+)-(\d+)$/);
        if (m) return rows.push({tdn: `topology/pod-${parts[0].replace(/^pod[-_]?/i, '')}/protpaths-${m[1]}-${m[2]}/pathep-[${parts[2]}]`});
        return warnings.push(`Line ${n + 1} skipped (a path TDN, or pod,node-node,policy_group): ${line}`);
      }
      if (parts.length < 3) return warnings.push(`Line ${n + 1} skipped (needs pod,node,interface): ${line}`);
      const pod = parts[0].replace(/^pod[-_]?/i, ''), node = parts[1].replace(/^(node|paths)[-_]?/i, ''), iface = parts[2];
      const range = iface.match(/^(.*\/)(\d+)-(\d+)$/);
      if (range) {
        const [a, b] = [Number(range[2]), Number(range[3])];
        if (b < a || b - a >= 200) return warnings.push(`Line ${n + 1} skipped (range must go up, at most 200 interfaces): ${line}`);
        for (let i = a; i <= b; i++) rows.push({pod, node, interface: `${range[1]}${i}`});
      } else {
        rows.push({pod, node, interface: iface});
      }
    });
    return {rows, warnings};
  },
  addBulk() {
    const {rows, warnings} = this.parseBulk(this.kind, $('#tpBulkText').value);
    if (rows.length) this.addRows(this.kind, rows);
    $('#tpBulkWarnings').innerHTML = warnings.length
      ? alertBox('warning', `<b>${plural(warnings.length, 'line')} to check</b><ul>${warnings.map(w => `<li>${esc(w)}</li>`).join('')}</ul>`) : '';
    if (rows.length) toast(`${plural(rows.length, 'path')} added from bulk text.`, 'success');
    else if (!warnings.length) toast('Bulk text is empty.', 'info');
  },
  text(kind) {
    return this[kind].map(r => (kind === 'physical' ? [r.pod, r.node, r.interface].join(',') : r.tdn)).join('\n');
  },

  // ---- review & save ----
  request() {
    const index = new Map(this.groups.map((g, i) => [g.key, i]));
    const at = key => (index.has(key) ? index.get(key) : null);
    return {
      version: this.version,
      groups: this.groups.map(g => ({name: g.name.trim(), default: g.default})),
      physical: this.physical.map(r => ({group: at(r.group), pod: String(r.pod).trim(), node: String(r.node).trim(), interface: String(r.interface).trim()})),
      paths: this.paths.map(r => ({group: at(r.group), tdn: String(r.tdn).trim()})),
    };
  },
  planHtml(d) {
    const s = d.summary, label = d.product.label;
    const changes = d.items.filter(i => i.status !== 'same');
    const apic = i => (i.exists ? '<span class="muted">Found</span>' : `<span class="badge ${i.status === 'new' ? 'badge-danger' : 'badge-change'}">Not on APIC</span>`);
    const group = i => (i.status === 'moved' ? `${esc(i.before_group)} → <b>${esc(i.group)}</b>` : esc(i.group));
    return (d.saved ? `<div class="success-state"><span class="success-icon">${icon('check')}</span><div><b>${esc(label)} template ${d.reset ? 'reset to the default' : 'saved'} for ${esc(d.site)}.</b>`
        + `<div class="muted">Recorded in History as change #${Number(d.audit_id)}. Nothing was sent to APIC.</div></div></div>` : '')
      + siteBanner(d.site, `Product <b>${esc(label)}</b> · template only, nothing is sent to APIC`)
      + `<div class="pills"><span class="pill pill-new">${s.new} added</span><span class="pill pill-danger">${s.delete} removed</span>`
      + `<span class="pill pill-change">${s.moved} moved</span><span class="pill">${s.same} unchanged</span></div>`
      + (!d.saved && d.blocked ? alertBox('danger', `<b>${plural(d.missing.length, 'added path')} not in the ${esc(d.site)} fabric. Nothing can be saved.</b> `
        + `Remove them or fix the typing, then review again.<ul>${d.missing.slice(0, 10).map(t => `<li class="mono">${esc(t)}</li>`).join('')}</ul>`) : '')
      + (!d.saved && d.reset ? alertBox('warning', `<b>The edited template is replaced by the default from product_templates.json.</b> `
        + 'The edit stays in History, so it can be entered again.') : '')
      + (!d.saved && !d.changed && !d.reset ? alertBox('info', 'The template is the same as the saved one. Nothing needs to be saved.') : '')
      + (!d.saved && d.changed && !d.blocked ? alertBox('info', `Static Port fills the binding table with the new paths the next time someone picks ${esc(label)} on ${esc(d.site)}. `
        + 'Bindings already on APIC are not changed.') : '')
      + (d.groups.length || d.reordered ? `<h3 class="detail-title">Groups</h3><div class="table-wrap"><table class="table table-data"><thead><tr><th>Status</th><th>Group</th><th>On Static Port</th></tr></thead><tbody>`
        + d.groups.map(g => `<tr><td><span class="badge ${GROUP_STATUS[g.status][0]}">${GROUP_STATUS[g.status][1]}</span></td><td>${esc(g.name)}</td>`
          + `<td>${g.default ? 'Selected by default' : 'Optional'}</td></tr>`).join('')
        + (d.reordered ? '<tr><td><span class="badge badge-change">Changed</span></td><td colspan="2">Order of the groups</td></tr>' : '') + '</tbody></table></div>' : '')
      + (changes.length ? `<h3 class="detail-title">Paths (${changes.length} changed)</h3><div class="table-wrap"><table class="table table-data"><thead><tr><th>Status</th><th>Group</th><th>Path</th><th>APIC</th></tr></thead><tbody>`
        + changes.map(i => `<tr${i.status === 'new' && !i.exists ? ' class="is-conflict"' : ''}><td><span class="badge ${TEMPLATE_STATUS[i.status][0]}">${TEMPLATE_STATUS[i.status][1]}</span></td>`
          + `<td class="wrap">${group(i)}</td><td class="mono">${esc(i.tdn)}</td><td>${apic(i)}</td></tr>`).join('') + '</tbody></table></div>' : '');
  },
  async review(reset = false) {
    const p = this.product();
    if (!reset && this.validate()) {
      this.focusFirstInvalid();
      throw new Error(`Fix the ${plural(this.invalid, 'field')} marked in red. Hover over a red field to see why.`);
    }
    const body = reset ? {version: this.version, reset: true} : this.request();
    const url = `/api/templates/${encodeURIComponent(p.id)}`;
    const d = await api(`${url}/preview`, body);
    Review.open({
      title: reset ? `Reset ${p.label} to the default` : `Review template: ${p.label}`,
      body: this.planHtml(d),
      confirmLabel: d.blocked ? 'Blocked: path not on APIC' : reset ? `Reset template on ${d.site}` : d.changed ? `Save template for ${d.site}` : 'No changes',
      canConfirm: !d.blocked && (reset || d.changed),
      danger: reset,
      busyLabel: 'Saving…',
      failLabel: 'Save failed.',
      onConfirm: async () => {
        const r = await api(`${url}/save`, body);
        toast(`${p.label} template ${reset ? 'reset' : 'saved'} for ${r.site}. Recorded in History as change #${r.audit_id}.`, 'success');
        Audit.markStale();
        await this.reload(p.id);
        return this.planHtml(r);
      },
    });
  },
  // After a save: the saved template from the server, on this page and on Static Port.
  async reload(id) {
    this.baseline = '';
    await Products.reload(id);
    if (id !== undefined) this.productId = Products.list.some(p => p.id === id) ? id : Products.list[0]?.id || '';
    this.load(this.product());
  },

  // ---- History details of a template or product change ----
  historyHtml(d) {
    const meta = p => `<dl class="meta-grid"><dt>Product</dt><dd>${esc(p.label)}</dd><dt>Platform</dt><dd>${esc(p.platform || '—')}</dd>`
      + `<dt>Mode</dt><dd>${esc(MODE_LABEL[p.mode] || p.mode)}</dd><dt>Immediacy</dt><dd>${esc(IMMEDIACY_LABEL[p.immediacy] || p.immediacy)}</dd></dl>`;
    if (d.kind === 'product-add' || d.kind === 'product-change') {
      return `<h3 class="detail-title">Product settings${d.kind === 'product-change' ? ' after the change' : ''}</h3>${meta(d.product)}`
        + (d.before ? `<h3 class="detail-title">Before</h3>${meta({...d.product, ...d.before})}` : '');
    }
    if (d.kind === 'product-delete') {
      return `<h3 class="detail-title">Deleted product</h3>${meta(d.product)}`
        + `<details class="payload"><summary>Its templates per site (JSON)</summary><pre>${esc(JSON.stringify(d.templates, null, 2))}</pre></details>`;
    }
    const paths = d.paths || [];
    return ((d.groups || []).length ? `<h3 class="detail-title">Groups changed (${d.groups.length})</h3><div class="table-wrap"><table class="table table-data"><thead><tr><th>Status</th><th>Group</th><th>On Static Port</th></tr></thead><tbody>`
        + d.groups.map(g => `<tr><td><span class="badge ${GROUP_STATUS[g.status][0]}">${GROUP_STATUS[g.status][1]}</span></td><td>${esc(g.name)}</td><td>${g.default ? 'Selected by default' : 'Optional'}</td></tr>`).join('')
        + '</tbody></table></div>' : '')
      + (paths.length ? `<h3 class="detail-title">Paths changed (${paths.length})</h3><div class="table-wrap"><table class="table table-data"><thead><tr><th>Status</th><th>Group</th><th>Path</th></tr></thead><tbody>`
        + paths.map(i => `<tr><td><span class="badge ${TEMPLATE_STATUS[i.status][0]}">${TEMPLATE_STATUS[i.status][1]}</span></td>`
          + `<td class="wrap">${i.status === 'moved' ? `${esc(i.before_group)} → ${esc(i.group)}` : esc(i.group)}</td><td class="mono">${esc(i.tdn)}</td></tr>`).join('')
        + '</tbody></table></div>' : '')
      + `<details class="payload"><summary>Template after the change (JSON)</summary><pre>${esc(JSON.stringify(d.after, null, 2))}</pre></details>`
      + `<details class="payload"><summary>Template before the change (JSON)</summary><pre>${esc(JSON.stringify(d.before, null, 2))}</pre></details>`;
  },
};

// New product / Product settings (products added by users only; the built-in ones come from product_templates.json).
const ProductDialog = {
  product: null,
  init() {
    fill($('#pdMode'), MODES, null, x => x[0], x => x[1]);
    fill($('#pdImm'), IMMEDIACY, null, x => x[0], x => x[1]);
    $('#productForm').addEventListener('submit', e => {
      e.preventDefault();
      run($('#pdSave'), () => this.save());
    });
    $$('#productDialog [data-close]').forEach(b => b.addEventListener('click', () => $('#productDialog').close()));
    $('#pdDelete').addEventListener('click', e => run(e.currentTarget, () => this.remove()));
  },
  open(p = null) {
    this.product = p;
    $('#productDialogTitle').textContent = p ? 'Product settings' : 'New product';
    $('#pdLabel').value = p ? p.label : '';
    $('#pdPlatform').value = p ? p.platform : '';
    choose($('#pdMode'), p ? p.mode : 'regular');
    choose($('#pdImm'), p ? p.immediacy : 'immediate');
    $('#pdSave').textContent = p ? 'Save' : 'Add product';
    $('#pdDelete').hidden = !p;
    $('#pdHint').textContent = p ? 'Mode and immediacy are the defaults of the rows this product fills in on Static Port, on every site.'
      : 'The product is added to every site with an empty template; add its paths per site. Mode and immediacy are the defaults of its rows on Static Port.';
    $('#productFormError').hidden = true;
    $('#productDialog').showModal();
    $('#pdLabel').focus();
  },
  async save() {
    const body = {label: $('#pdLabel').value, platform: $('#pdPlatform').value, mode: $('#pdMode').value, immediacy: $('#pdImm').value};
    let r;
    try {
      r = this.product ? await api(`/api/products/${encodeURIComponent(this.product.id)}`, body) : await api('/api/products', body);
    } catch (e) {
      $('#productFormError').textContent = e.message;
      $('#productFormError').hidden = false;
      return;
    }
    $('#productDialog').close();
    toast(`${r.product.label} ${this.product ? 'saved' : 'added to every site'}. Recorded in History as change #${r.audit_id}.`, 'success');
    Audit.markStale();
    if (this.product) {
      // Settings only: the paths being edited stay as they are.
      await Products.reload(r.product.id);
      Templates.renderPicker();
      Templates.update();
    } else {
      await Templates.reload(r.product.id);
    }
  },
  async remove() {
    const p = this.product;
    if (!await confirmDialog({title: `Delete ${p.label}?`, body: `${p.label} and its templates on every site are deleted, and Static Port no longer offers it. `
      + 'The templates stay in the History record. Nothing changes on APIC.', confirmLabel: 'Delete product', danger: true})) return;
    const r = await api(`/api/products/${encodeURIComponent(p.id)}/delete`, {confirm: true});
    $('#productDialog').close();
    toast(`${p.label} deleted. Recorded in History as change #${r.audit_id}.`, 'success');
    Audit.markStale();
    await Templates.reload('');
  },
};

/* =========================================================================
   Provisioning
   ========================================================================= */
const Provision = {
  subnets: [],
  init() {
    ['#pvTenant', '#pvVrf', '#pvBd', '#pvApp'].forEach(id => combo($(id)));
    const panel = $('#tab-provision');
    panel.addEventListener('change', e => {
      if (e.target.type === 'radio') this.modes();
      this.update();
    });
    panel.addEventListener('input', () => this.update());
    $$('input[name="pvTenantMode"]').forEach(r => r.addEventListener('change', () => run(null, () => this.loadTenantObjects())));
    $('#pvTenant').addEventListener('change', () => run(null, () => this.loadTenantObjects()));
    $('#pvSubnetAdd').addEventListener('click', () => {
      this.subnets.push({ip: '', scope: 'public', preferred: false, virtual: false});
      this.renderSubnets();
      $$('#pvSubnets [data-k="ip"]').pop()?.focus();
    });
    const editSubnet = e => {
      const row = e.target.closest('[data-i]'), key = e.target.dataset.k;
      if (!row || !key) return;
      this.subnets[row.dataset.i][key] = e.target.type === 'checkbox' ? e.target.checked : e.target.value;
      if (key === 'ip') e.target.classList.toggle('is-invalid', !!e.target.value.trim() && !SUBNET.test(e.target.value.trim()));
    };
    $('#pvSubnets').addEventListener('input', editSubnet);
    $('#pvSubnets').addEventListener('change', editSubnet);
    $('#pvSubnets').addEventListener('click', e => {
      const btn = e.target.closest('[data-act="del"]');
      if (!btn) return;
      this.subnets.splice(Number(btn.closest('[data-i]').dataset.i), 1);
      this.renderSubnets();
    });
    $('#pvReviewBtn').addEventListener('click', e => run(e.currentTarget, () => this.review()));
    $('#pvResetBtn').addEventListener('click', () => this.reset());
    this.modes();
    this.renderSubnets();
    this.update();
  },
  modes() {
    $$('#tab-provision [data-when]').forEach(el => {
      const [name, value] = el.dataset.when.split('=');
      el.hidden = radioValue(name) !== value;
    });
  },
  renderSubnets() {
    $('#pvSubnets').innerHTML = this.subnets.map((s, i) => `<div class="subnet-row" data-i="${i}">`
      + `<input class="input mono${s.ip && !SUBNET.test(s.ip) ? ' is-invalid' : ''}" data-k="ip" value="${esc(s.ip)}" placeholder="10.249.10.1/24" aria-label="Subnet ${i + 1} gateway" autocomplete="off">`
      + `<select class="input" data-k="scope" aria-label="Subnet ${i + 1} scope">${SCOPES.map(([v, l]) => `<option value="${v}"${v === s.scope ? ' selected' : ''}>${l}</option>`).join('')}</select>`
      + `<label class="check"><input type="checkbox" data-k="preferred"${s.preferred ? ' checked' : ''}> Preferred</label>`
      + `<label class="check"><input type="checkbox" data-k="virtual"${s.virtual ? ' checked' : ''}> Virtual IP</label>`
      + `<button type="button" class="btn-icon danger" data-act="del" aria-label="Remove subnet ${i + 1}">${icon('trash')}</button></div>`).join('')
      || '<div class="empty-inline">No subnets yet. The BD can still be created without a subnet (L2 only).</div>';
  },
  renderDomains(items, keep) {
    const groups = {};
    items.forEach(d => {
      const [type, ...name] = d.label.split(' / ');
      (groups[type] = groups[type] || []).push({dn: d.dn, name: name.join(' / ')});
    });
    $('#pvDomains').innerHTML = items.length ? Object.entries(groups).map(([type, list]) => `<div class="check-group"><div class="check-group-title">${esc(type)}</div>`
      + list.map(d => `<label class="check-item"><input type="checkbox" value="${esc(d.dn)}"${keep.includes(d.dn) ? ' checked' : ''}>`
        + `<span>${esc(d.name)}</span><span class="muted mono">${esc(d.dn)}</span></label>`).join('') + '</div>').join('')
      : `<div class="empty-inline">No domains on ${esc(Site.current)}.</div>`;
  },
  async onSite(tenants) {
    const keepTenant = $('#pvTenant').value, keepDomains = checkedValues($('#pvDomains'));
    fill($('#pvTenant'), tenants, tenants.length ? 'Select a tenant' : 'No tenants');
    choose($('#pvTenant'), keepTenant);
    $('#pvDomains').innerHTML = '<div class="loading">Loading domains…</div>';
    try {
      const [domains] = await Promise.all([api('/api/discover?kind=domains'), this.loadTenantObjects()]);
      this.renderDomains(domains.items, keepDomains);
    } catch (e) {
      $('#pvDomains').innerHTML = '<div class="empty-inline">Failed to load domains.</div>';
      throw e;
    }
    this.update();
  },
  async loadTenantObjects() {
    const tenant = radioValue('pvTenantMode') === 'existing' ? $('#pvTenant').value : '';
    const keep = {vrf: $('#pvVrf').value, bd: $('#pvBd').value, app: $('#pvApp').value, l3outs: checkedValues($('#pvL3outs'))};
    const empty = {vrfs: [], bds: [], apps: [], l3outs: []};
    if (tenant) ['#pvVrf', '#pvBd', '#pvApp'].forEach(id => fill($(id), [], 'Loading…'));
    const objs = tenant ? (await api('/api/discover?' + qs({kind: 'tenant_objects', tenant}))).items : empty;
    const text = (items, one, many) => (!tenant ? 'Select an existing tenant first' : items.length ? `Select ${one}` : `This tenant has no ${many}`);
    fill($('#pvVrf'), objs.vrfs, text(objs.vrfs, 'a VRF', 'VRFs'));
    choose($('#pvVrf'), keep.vrf);
    fill($('#pvBd'), objs.bds, text(objs.bds, 'a BD', 'BDs'));
    choose($('#pvBd'), keep.bd);
    fill($('#pvApp'), objs.apps, text(objs.apps, 'an app profile', 'app profiles'));
    choose($('#pvApp'), keep.app);
    $('#pvL3outs').innerHTML = objs.l3outs.length
      ? objs.l3outs.map(o => `<label class="check-item"><input type="checkbox" value="${esc(o)}"${keep.l3outs.includes(o) ? ' checked' : ''}><span>${esc(o)}</span></label>`).join('')
      : `<div class="empty-inline">${tenant ? 'This tenant has no L3Outs.' : 'L3Outs appear after you select an existing tenant.'}</div>`;
    this.update();
  },
  pick(mode, select, input) {
    const m = radioValue(mode);
    return m === 'new' ? $(input).value.trim() : (m === 'existing' ? $(select).value : '');
  },
  request() {
    return {
      tenant: {mode: radioValue('pvTenantMode'), name: this.pick('pvTenantMode', '#pvTenant', '#pvTenantNew'), descr: $('#pvTenantDescr').value},
      vrf: {mode: radioValue('pvVrfMode'), name: this.pick('pvVrfMode', '#pvVrf', '#pvVrfNew'), descr: $('#pvVrfDescr').value},
      bd: {mode: radioValue('pvBdMode'), name: this.pick('pvBdMode', '#pvBd', '#pvBdNew'), descr: $('#pvBdDescr').value,
        unknown_unicast: radioValue('pvUnk'), arp_flood: $('#pvArp').checked, subnets: this.subnets.filter(s => s.ip.trim()), l3outs: checkedValues($('#pvL3outs'))},
      app: {mode: radioValue('pvAppMode'), name: this.pick('pvAppMode', '#pvApp', '#pvAppNew'), descr: $('#pvAppDescr').value},
      epg: {name: $('#pvEpg').value.trim(), descr: $('#pvEpgDescr').value},
      domains: checkedValues($('#pvDomains')),
      deployment: radioValue('pvDeploy'),
      resolution: radioValue('pvResolve'),
    };
  },
  update() {
    const r = this.request();
    const ready = r.tenant.name && r.app.name && r.epg.name;
    $('#pvContext').innerHTML = r.tenant.name || r.app.name || r.epg.name
      ? crumbs([r.tenant.name, r.app.name, r.epg.name]) : '<span class="muted">Enter a tenant, app profile, and EPG name</span>';
    $('#pvReviewBtn').disabled = !ready;
  },
  async reset() {
    if (!await confirmDialog({title: 'Clear form?', body: 'All provisioning form fields will be cleared.', confirmLabel: 'Clear form', danger: true})) return;
    $$('#tab-provision input[type="text"], #tab-provision input:not([type])').forEach(i => { if (!i.classList.contains('combo-input')) i.value = ''; });
    [['pvTenantMode', 'existing'], ['pvVrfMode', 'existing'], ['pvBdMode', 'new'], ['pvAppMode', 'existing'], ['pvUnk', 'proxy'],
      ['pvDeploy', 'immediate'], ['pvResolve', 'immediate']].forEach(([name, value]) => setRadio(name, value));
    $('#pvArp').checked = false;
    $$('#pvDomains input, #pvL3outs input').forEach(i => { i.checked = false; });
    this.subnets = [];
    this.renderSubnets();
    this.modes();
    this.update();
  },
  planHtml(d) {
    const created = d.steps.filter(s => s.kind === 'new').length;
    return (d.applied ? `<div class="success-state"><span class="success-icon">${icon('check')}</span><div><b>Provisioning applied to ${esc(d.site)}.</b>`
        + `<div class="muted">${plural(created, 'new object')} created. Recorded in History as change #${Number(d.audit_id)}.</div></div></div>` : '')
      + siteBanner(d.site, `Tenant <code>${esc(d.tenant_dn)}</code> · sent in a single APIC transaction`)
      + (d.warnings.length ? alertBox('warning', `<b>Warnings</b><ul>${d.warnings.map(w => `<li>${esc(w)}</li>`).join('')}</ul>`) : '')
      + stepsTable(d.steps)
      + `<details class="payload"><summary>JSON payload for APIC</summary><pre>${esc(JSON.stringify(d.payload, null, 2))}</pre></details>`;
  },
  async review() {
    const d = await api('/api/provision/preview', this.request());
    Review.open({
      title: 'Review provisioning',
      body: this.planHtml(d),
      confirmLabel: `Apply to ${d.site}`,
      canConfirm: true,
      onConfirm: async () => {
        const r = await api('/api/provision/apply', this.request());
        Audit.markStale();
        toast(`Provisioning applied to ${r.site}.`, 'success');
        // Reload the lists, so the new objects can be selected on every page at once.
        changeSite(Site.current);
        return this.planHtml(r);
      },
    });
  },
};

/* =========================================================================
   Report
   ========================================================================= */
// Where a binding comes from, by the portal's own record of its static-port changes (row.source from the server).
const SOURCES = [['portal', 'Portal', 'badge-new'], ['outside', 'Outside portal', ''], ['changed', 'Changed outside portal', 'badge-change'],
  ['removed', 'Removed outside portal', 'badge-danger']];
const SOURCE_BADGE = Object.fromEntries(SOURCES.map(([key, , cls]) => [key, cls]));
// APIC modTs such as 2026-09-25T08:48:19.123+07:00, in the browser's time like the other times.
const apicTime = ts => (ts && !Number.isNaN(Date.parse(ts)) ? fmtTime(ts) : ts || '');

const Report = {
  target: null,
  rows: [],
  loaded: false,
  type: '',
  source: '',
  sort: {key: 'Tenant', dir: 1},
  init() {
    this.target = cascade(['#rpTenant', '#rpApp', '#rpEpg'],
      {tenant: 'All tenants', app: 'All app profiles', epg: 'All EPGs', appWait: 'All app profiles', epgWait: 'All EPGs'});
    $('#rpShowBtn').addEventListener('click', e => run(e.currentTarget, () => this.load()));
    $$('[data-export]').forEach(b => b.addEventListener('click', () => run(b, () => this.download(b.dataset.export))));
    $('#rpSearch').addEventListener('input', () => this.render());
    $('#rpSource').addEventListener('change', e => { this.source = e.target.value; this.render(); });
    // "change #12" in the Source column opens that change of History.
    $('#rpTable tbody').addEventListener('click', e => {
      const link = e.target.closest('a[data-audit]');
      if (!link) return;
      e.preventDefault();
      run(null, () => Audit.open(Number(link.dataset.audit)));
    });
    $('#rpKpis').addEventListener('click', e => {
      const b = e.target.closest('[data-type]');
      if (b) { this.type = b.dataset.type; this.render(); }
    });
    $('#rpTable thead').addEventListener('click', e => {
      const b = e.target.closest('[data-sort]');
      if (!b) return;
      this.sort = {key: b.dataset.sort, dir: this.sort.key === b.dataset.sort ? -this.sort.dir : 1};
      this.render();
    });
    this.render();
  },
  async onSite(tenants) {
    this.rows = [];
    this.loaded = false;
    this.type = '';
    this.source = '';
    this.render();
    await this.target.onSite(tenants);
  },
  async load() {
    $('#rpTable tbody').innerHTML = `<tr class="empty-row"><td colspan="12"><div class="loading">Loading report from ${esc(Site.current)}…</div></td></tr>`;
    try {
      this.rows = (await api('/api/report?' + qs(this.target.values()))).items;
      this.loaded = true;
    } finally {
      this.render();
    }
  },
  // Source badge; for a path the portal set, the change as a link, and what it set when APIC differs.
  sourceHtml(r) {
    const p = r.portal;
    const badge = `<span class="badge ${SOURCE_BADGE[r.source] || ''}">${esc(r.Source || '—')}</span>`;
    if (!p) return badge;
    const link = `<a href="#audit" data-audit="${Number(p.change)}">change #${Number(p.change)}</a>`;
    if (r.source === 'portal') return `${badge} ${link}`;
    return `${badge}<div class="muted cell-note">${p.status === 'delete' ? `Deleted by the portal in ${link}`
      : `Portal set ${esc(bindingValues(p))} in ${link}`}</div>`;
  },
  // Search over the visible values (the portal details are an object).
  searchText(r) {
    return Object.values(r).filter(v => v === null || typeof v !== 'object').join(' ').toLowerCase()
      + (r.portal ? ` change #${r.portal.change}` : '');
  },
  render() {
    const query = $('#rpSearch').value.trim().toLowerCase();
    // The type cards count the rows of the selected source; the source list counts all rows.
    const bySource = this.rows.filter(r => !this.source || r.source === this.source);
    const count = type => bySource.filter(r => r['Binding Type'] === type).length;
    $('#rpKpis').innerHTML = [['', 'Total bindings', bySource.length], ['Physical', 'Physical', count('Physical')], ['PC', 'Port-Channel', count('PC')], ['vPC', 'vPC', count('vPC')]]
      .map(([type, label, n]) => `<button type="button" class="kpi${this.type === type ? ' is-active' : ''}" data-type="${type}" aria-pressed="${this.type === type}">`
        + `<span class="kpi-value">${n}</span><span class="kpi-label">${label}</span></button>`).join('');
    const options = `<option value="">All sources (${this.rows.length})</option>` + SOURCES.map(([k, label]) => `<option value="${k}"${this.source === k ? ' selected' : ''}>`
      + `${label} (${this.rows.filter(r => r.source === k).length})</option>`).join('');
    if ($('#rpSource').dataset.html !== options) {   // rebuilt only when a count changed
      $('#rpSource').dataset.html = options;
      $('#rpSource').innerHTML = options;
    }
    $('#rpSource').disabled = !this.loaded;
    const {key, dir} = this.sort;
    const rows = bySource
      .filter(r => (!this.type || r['Binding Type'] === this.type) && (!query || this.searchText(r).includes(query)))
      .sort((a, b) => String(a[key] ?? '').localeCompare(String(b[key] ?? ''), 'en', {numeric: true}) * dir);
    $$('#rpTable th').forEach(th => {
      const k = $('[data-sort]', th)?.dataset.sort;
      th.setAttribute('aria-sort', k === key ? (dir > 0 ? 'ascending' : 'descending') : 'none');
    });
    $('#rpShown').textContent = this.loaded ? `Showing ${rows.length} of ${plural(this.rows.length, 'binding')}` : '';
    const empty = !this.loaded ? ['table', 'No data yet', 'Choose filters (or leave them empty for everything), then click Show.']
      : !this.rows.length ? ['table', 'No static bindings', `No static bindings match these filters on ${Site.current}.`]
        : ['search', 'No results found', 'Change the search terms or select another type or source.'];
    // A binding the portal set that APIC no longer has: its row shows the portal's values, muted.
    $('#rpTable tbody').innerHTML = rows.map(r => `<tr${r.source === 'removed' ? ' class="is-removed"' : ''}><td>${esc(r.Tenant)}</td><td>${esc(r['Application Profile'])}</td><td>${esc(r.EPG)}</td><td>${esc(r.VLAN)}</td>`
      + `<td><span class="badge">${esc(r['Binding Type'])}</span></td><td>${esc(r['Node(s)'])}</td><td>${esc(r['Interface / Policy Group'])}</td>`
      + `<td>${esc(MODE_LABEL[r.Mode] || r.Mode)}</td><td>${esc(IMMEDIACY_LABEL[r['Deployment Immediacy']] || r['Deployment Immediacy'])}</td>`
      + `<td>${this.sourceHtml(r)}</td><td>${esc(apicTime(r['Last Changed (APIC)'])) || '<span class="muted">—</span>'}</td><td class="mono">${esc(r['Path TDN'])}</td></tr>`).join('')
      || `<tr class="empty-row"><td colspan="12"><div class="empty">${icon(empty[0])}<div><b>${esc(empty[1])}</b><p>${esc(empty[2])}</p></div></div></td></tr>`;
  },
  download(fmt) {
    return downloadFile(withSite(`/export/report.${fmt}?` + qs(this.target.values())), `report.${fmt}`);
  },
};

/* =========================================================================
   IP usage: endpoint IPs learned on the EPGs (Client Endpoints) and the free addresses of their subnets
   ========================================================================= */
// Copy to the clipboard; without the Clipboard API (for example plain http) through a hidden text field.
async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch (e) {
    const area = document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', '');
    Object.assign(area.style, {position: 'fixed', top: '0', opacity: '0'});
    document.body.appendChild(area);
    area.select();
    document.execCommand('copy');
    area.remove();
  }
}

const IpUsage = {
  target: null,
  rows: [],
  loaded: false,
  recentDays: 30,
  init() {
    this.target = cascade(['#ipTenant', '#ipApp', '#ipEpg'],
      {tenant: 'All tenants', app: 'All app profiles', epg: 'All EPGs', appWait: 'All app profiles', epgWait: 'All EPGs'});
    $('#ipShowBtn').addEventListener('click', e => run(e.currentTarget, () => this.load()));
    $('#ipExportBtn').addEventListener('click', e => run(e.currentTarget, () => downloadFile(withSite('/export/ip-usage.csv?'
      + qs({...this.target.values(), scope: $('#ipScope').value, learned: $('#ipLearnedOnly').checked ? '1' : ''})), 'ip-usage.csv')));
    $('#ipSearch').addEventListener('input', () => this.render());
    ['#ipScope', '#ipLearnedOnly'].forEach(id => $(id).addEventListener('change', () => this.render()));
    const tbody = $('#ipTable tbody');
    tbody.addEventListener('click', e => {
      const chip = e.target.closest('[data-copy]');
      if (chip) return this.copy(chip.dataset.copy);
      const tr = e.target.closest('tr[data-id]');
      if (tr) this.open(Number(tr.dataset.id));
    });
    tbody.addEventListener('keydown', e => {
      const tr = e.target.closest('tr[data-id]');
      if (tr && e.key === 'Enter' && !e.target.closest('[data-copy]')) this.open(Number(tr.dataset.id));
    });
    $('#ipDialogClose').addEventListener('click', () => $('#ipDialog').close());
    $('#ipDialogBody').addEventListener('click', e => {
      const chip = e.target.closest('[data-copy]');
      if (chip) this.copy(chip.dataset.copy, chip.dataset.label);
    });
    this.render();
  },
  async onSite(tenants) {
    this.rows = [];
    this.loaded = false;
    this.render();
    await this.target.onSite(tenants);
  },
  async load() {
    $('#ipTable tbody').innerHTML = `<tr class="empty-row"><td colspan="6"><div class="loading">Reading the client endpoints of ${esc(Site.current)}…</div></td></tr>`;
    try {
      const d = await api('/api/ip-usage?' + qs(this.target.values()));
      this.rows = d.items;
      this.recentDays = d.recent_days;
      this.loaded = true;
    } finally {
      this.render();
    }
  },
  async copy(text, label = '') {
    await copyText(text);
    toast(`${label || text} copied to the clipboard.`, 'success');
  },
  text(r) {
    return [r.tenant, r.app, r.epg, r.bd, r.subnet, ...r.gateways, ...r.endpoints.flatMap(e => [e.ip, e.mac, e.interface])].join(' ').toLowerCase();
  },
  // Public addresses and subnets with learned IPs by default: EPGs that only see MAC addresses (MPLS, L2) have no row.
  visible() {
    const query = $('#ipSearch').value.trim().toLowerCase(), scope = $('#ipScope').value, learnedOnly = $('#ipLearnedOnly').checked;
    return this.rows.map((r, i) => ({r, i}))
      .filter(({r}) => (!scope || r.scope === scope) && (!learnedOnly || r.learned) && (!query || this.text(r).includes(query)));
  },
  chips(ips, limit = ips.length) {
    return ips.slice(0, limit).map(ip => `<button type="button" class="chip chip-free" data-copy="${esc(ip)}" title="Copy ${esc(ip)}" aria-label="Copy ${esc(ip)}">${esc(ip)}</button>`).join('');
  },
  render() {
    const shown = this.visible();
    const total = key => shown.reduce((n, {r}) => n + (Number(r[key]) || 0), 0);
    $('#ipKpis').innerHTML = [['Subnets', shown.filter(({r}) => r.subnet).length], ['Learned IPs', total('learned')], ['Free IPs', total('free')],
      [`Not learned now, seen in the last ${this.recentDays} days`, shown.reduce((n, {r}) => n + r.seen_recently.length, 0)]]
      .map(([label, n]) => `<div class="kpi kpi-static"><span class="kpi-value">${n}</span><span class="kpi-label">${esc(label)}</span></div>`).join('');
    $('#ipShown').textContent = this.loaded ? `Showing ${shown.length} of ${plural(this.rows.length, 'row')}` : '';
    const empty = !this.loaded ? ['globe', 'No data yet', 'Choose filters (or leave them empty for everything), then click Show.']
      : !this.rows.length ? ['globe', 'No EPG subnets', `No EPG in these filters has a subnet or a learned IP on ${Site.current}.`]
        : ['search', 'No results found', 'Change the search terms, or show all addresses and subnets without learned IPs.'];
    $('#ipTable tbody').innerHTML = shown.map(({r, i}) => `<tr data-id="${i}" tabindex="0"><td>${esc(r.tenant)}<div class="muted cell-note">${esc(r.app)}</div></td>`
      + `<td><b>${esc(r.epg)}</b></td><td>${r.subnet ? `<span class="mono">${esc(r.subnet)}</span>` : '<span class="muted">No subnet on the BD</span>'}`
      + `${r.scope === 'private' ? ' <span class="badge">Private</span>' : ''}`
      + `${r.gateways.length ? `<div class="muted cell-note mono">gateway ${esc(r.gateways.join(', '))}</div>` : ''}</td>`
      + `<td>${r.learned}${r.used_elsewhere ? `<div class="muted cell-note">+${r.used_elsewhere} in other EPGs</div>` : ''}</td>`
      + `<td>${r.free === null ? '—' : `${r.free} <span class="muted">of ${r.size}</span>`}`
      + `${r.seen_recently.length ? `<div class="muted cell-note">${r.seen_recently.length} seen recently, not suggested</div>` : ''}</td>`
      + `<td class="ip-suggest">${r.suggest.length ? `<div class="chips">${this.chips(r.suggest, 2)}${r.free > 2 ? `<span class="muted">+${r.free - 2} more</span>` : ''}</div>`
        : '<span class="muted">—</span>'}</td></tr>`).join('')
      || `<tr class="empty-row"><td colspan="6"><div class="empty">${icon(empty[0])}<div><b>${esc(empty[1])}</b><p>${esc(empty[2])}</p></div></div></td></tr>`;
  },
  open(i) {
    const r = this.rows[i];
    if (!r) return;
    const meta = [['Tenant', r.tenant], ['Application profile', r.app], ['EPG', r.epg], ['Bridge domain', r.bd || '—'],
      ['Subnet', r.subnet || 'No subnet on the bridge domain'], ['Gateway', r.gateways.join(', ') || '—'], ['Scope', r.scope === 'public' ? 'Public' : 'Private'],
      ['Usable addresses', r.size ?? '—'], ['Learned in this EPG', r.learned], ['Learned in other EPGs', r.used_elsewhere || 0], ['Free', r.free ?? '—']];
    const learned = r.endpoints;
    $('#ipDialogTitle').textContent = `${r.epg} · ${r.subnet || 'no subnet'}`;
    $('#ipDialogBody').innerHTML = siteBanner(r.site, `EPG <code>${esc(r.epg_dn)}</code> · addresses of this site's fabric only`)
      + `<dl class="meta-grid">${meta.map(([k, v]) => `<dt>${k}</dt><dd>${esc(v)}</dd>`).join('')}</dl>`
      + (r.suggest.length ? `<h3 class="detail-title">Suggested free IPs</h3><div class="chips">${this.chips(r.suggest)}</div>`
        + `<p class="hint">Not a gateway, not learned on any endpoint of the ${esc(r.site)} fabric, and not seen by the portal in the last ${this.recentDays} days. `
        + 'Click an IP to copy it. A host that never sent traffic is not learned either: check the address before you hand it out.</p>' : '')
      + (r.subnet && r.free === null ? `<p class="undo-note">${icon('info')}<span>Free addresses are counted for IPv4 subnets up to /30 only.</span></p>` : '')
      + `<h3 class="detail-title">Learned IPs (${learned.length})</h3>`
      + (learned.length ? '<div class="table-wrap table-scroll-sm"><table class="table table-data"><thead><tr><th>IP</th><th>MAC</th><th>Encap</th><th>Interface</th>'
          + '<th>Learning source</th><th>Last seen (portal)</th></tr></thead><tbody>'
          + learned.map(e => `<tr><td class="mono">${esc(e.ip)}</td><td class="mono">${esc(e.mac)}</td><td>${esc(e.encap)}</td><td class="mono ip-iface">${e.interface.split('/').map(part => `<span>${esc(part)}</span>`).join('/<wbr>')}</td>`
            + `<td>${esc(e.source)}</td><td>${esc(fmtTime(e.last_seen))}</td></tr>`).join('') + '</tbody></table></div>'
        : '<div class="empty-inline">No endpoint of this EPG has an IP in this subnet right now.</div>')
      + (r.seen_recently.length ? `<h3 class="detail-title">Not learned now, seen in the last ${this.recentDays} days (${r.seen_recently.length})</h3>`
        + `<p class="mono">${esc(r.seen_recently.join(', '))}</p><p class="hint">Probably a host that is switched off or silent; these addresses are not suggested.</p>` : '')
      + (r.free_ranges.length ? `<h3 class="detail-title">Free addresses (${r.free})</h3>`
        + `<details class="payload"><summary>${plural(r.free_ranges.length, 'range')}</summary><pre>${esc(r.free_ranges.join('\n'))}</pre></details>`
        + `<p><button type="button" class="btn btn-secondary btn-sm" data-copy="${esc(r.free_ranges.join('\n'))}" data-label="${plural(r.free, 'free address', 'free addresses')}">`
        + `${icon('copy')}Copy free addresses</button></p>` : '');
    if (!$('#ipDialog').open) $('#ipDialog').showModal();
    $('#ipDialogBody').scrollTop = 0;
  },
};

/* =========================================================================
   Start
   ========================================================================= */
document.addEventListener('DOMContentLoaded', async () => {
  Tabs.init();
  UserMenu.init();
  Review.init();
  Audit.init();
  StaticPort.init();
  Templates.init();
  ProductDialog.init();
  Provision.init();
  Report.init();
  IpUsage.init();
  Activity.init();
  $('#siteSwitch').addEventListener('change', async e => {
    if (e.target.name !== 'site') return;
    if (!await Templates.confirmDiscard(`Switching to ${e.target.value} loads the templates of that site.`)) {
      Site.render();
      return;
    }
    changeSite(e.target.value);
  });
  document.addEventListener('ui:refresh', () => {
    StaticPort.update();
    Templates.update();
    Provision.update();
    Products.syncEpg();
  });
  // Without a portal session: the portal sign-in, which comes back to this page.
  let status;
  try {
    status = await (await request(BASE + '/api/session')).json();
  } catch (e) {
    toast('Cannot reach the Web UI server.');
    return;
  }
  if (status.user) await Session.enter(status);
  else Session.update(status);
});

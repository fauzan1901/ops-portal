'use strict';
/* Shell (portal module /terminal/): SSH terminals in the browser, laid out like Termius / MobaXterm: the host tree of every
   site on the left (favorites, recent, per site and product), browser-like tabs, up to four panes (drag a tab onto a
   pane), a status bar for the active pane, snippets, copy and paste. The terminals are xterm.js (as in the OpenShift
   console); the portal server runs ssh, this page only sends keys and draws output:
     POST /terminal/api/sessions              open a session on a host of the tree (its id only)
     GET  /terminal/api/poll?c=<id>:<offset>  new output of every open session of this page, one request at a time
     POST /terminal/api/sessions/<id>/input   what is typed or pasted;  /resize  the size of the terminal
   Sessions live on the portal server: reloading the page reattaches them (the last 512 KB of output is drawn again). */

const BASE = '/terminal';
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
const qs = params => Object.entries(params).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v ?? '')}`).join('&');
const icon = name => `<svg class="pf-icon" aria-hidden="true"><use href="#i-${name}"></use></svg>`;
const sleep = ms => new Promise(r => setTimeout(r, ms));
const IS_MAC = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
const RIGHT_CLICK = IS_MAC ? 'menu' : 'paste';   // Windows / Linux: like MobaXterm and PuTTY; Mac: a menu, as in Terminal
const MOD = IS_MAC ? '⌘' : 'Ctrl+Shift+';
const UI_VERSION = document.querySelector('meta[name="ui-version"]')?.content || '';
const SITE_COLORS = ['#2b9af3', '#3e8635', '#8476d1', '#ec7a08', '#c9190b', '#009596'];

function storage(area) {
  return {
    get(key, fallback = null) { try { const v = window[area].getItem(key); return v === null ? fallback : JSON.parse(v); } catch (e) { return fallback; } },
    set(key, value) { try { window[area].setItem(key, JSON.stringify(value)); } catch (e) { /* storage not available */ } },
  };
}
const local = storage('localStorage');
const tabStore = storage('sessionStorage');

function fmtTime(iso) {
  if (!iso) return '-';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString('en-GB', {day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23'}).replace('Sept', 'Sep');
}
function fmtShort(d) {
  return d.toLocaleString('en-GB', {day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit', hourCycle: 'h23'}).replace('Sept', 'Sep');
}
function duration(seconds) {
  const s = Math.max(0, Math.round(seconds));
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
  return h ? `${h}h ${String(m).padStart(2, '0')}m` : `${m}m ${String(s % 60).padStart(2, '0')}s`;
}
function alertBox(kind, title, body = '') {
  const name = {success: 'check-circle', danger: 'x-circle', warning: 'alert', info: 'info'}[kind];
  return `<div class="pf-alert pf-m-${kind}"${kind === 'danger' ? ' role="alert"' : ''}>${icon(name)}<div class="pf-alert__title">${title}</div>`
    + (body ? `<div class="pf-alert__body">${body}</div>` : '') + '</div>';
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
  if (!action) setTimeout(() => el.remove(), kind === 'danger' ? 10000 : 4000);
}
async function run(button, fn) {
  if (button) { button.disabled = true; button.classList.add('is-loading'); }
  try { return await fn(); } catch (e) { if (e.name !== 'AbortError') toast(e.message); } finally {
    if (button) { button.disabled = false; button.classList.remove('is-loading'); }
  }
}
async function api(url, body, method, signal, confirmed = false) {
  const init = {method: method || (body === undefined ? 'GET' : 'POST'), signal};
  if (body !== undefined) {
    init.headers = {'Content-Type': 'application/json'};
    init.body = JSON.stringify(body);
  }
  const res = await fetch(BASE + url, init);
  let data;
  try { data = await res.json(); } catch (e) { throw new Error(`Portal server error (HTTP ${res.status})`); }
  if (res.status === 401) window.PortalLauncher?.signIn();
  if (res.status === 403 && data.step_up) {   // confirm with Duo first, then ask once more
    if (!confirmed && await StepUp.confirm(data.error, data.step_up)) return api(url, body, method, signal, true);
    throw new Error(data.error || 'A Duo confirmation is needed');
  }
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
}
const Confirm = {
  ask(title, body, action = 'End', dismiss = 'Cancel', primary = false) {
    const dialog = $('#confirmDialog');
    $('#confirmTitle').textContent = title;
    $('#confirmBody').textContent = body;
    $('#confirmOk').textContent = action;
    $('#confirmOk').classList.toggle('pf-m-danger', !primary);
    $('#confirmOk').classList.toggle('pf-m-primary', primary);
    $('#confirmCancel').textContent = dismiss;
    dialog.returnValue = '';
    dialog.showModal();
    $('#confirmCancel').focus();
    return new Promise(resolve => dialog.addEventListener('close', () => resolve(dialog.returnValue === 'ok'), {once: true}));
  },
};

/* Duo step-up (portal_auth.Portal.step_up): opening a terminal, joining a session and becoming root need a new Duo SSO
   sign-in now and then. The sign-in runs in a popup, so the terminals of this page stay as they are; when the popup is
   blocked, this page goes to Duo and comes back (the sessions reattach). */
const StepUp = {
  pending: null,
  confirm(message, url) {
    if (!this.pending) this.pending = this.run(message, url).finally(() => { this.pending = null; });
    return this.pending;
  },
  async run(message, url) {
    if (!await Confirm.ask('Confirm with Duo', `${message} A Duo window opens: sign in and approve there.`, 'Confirm with Duo',
      'Cancel', true)) return false;
    const next = encodeURIComponent(location.pathname + location.hash);
    const popup = window.open(`${url}?popup=1&next=${next}`, 'portalStepUp', 'popup,width=520,height=720');
    if (!popup) {
      location.href = `${url}?next=${next}`;
      return new Promise(() => {});   // the page leaves
    }
    return new Promise(resolve => {
      let finished = false;
      const done = ok => {
        if (finished) return;
        finished = true;
        clearInterval(timer);
        removeEventListener('message', onMessage);
        try { popup.close(); } catch (e) { /* already closed */ }
        resolve(ok);
      };
      const onMessage = e => {
        if (e.source !== popup || e.data?.type !== 'portal-step-up') return;
        if (!e.data.ok) toast(e.data.error || 'Duo did not confirm.', 'danger');
        done(!!e.data.ok);
      };
      addEventListener('message', onMessage);
      const timer = setInterval(() => { if (popup.closed) setTimeout(() => done(false), 800); }, 500);   // closed by hand
    });
  },
};

/* =========================================================================
   Preferences of this browser and the terminal themes (PatternFly palette)
   ========================================================================= */
const THEMES = {
  dark: {background: '#151515', foreground: '#e0e0e0', cursor: '#73bcf7', cursorAccent: '#151515', selectionBackground: 'rgba(115, 188, 247, .35)',
    black: '#26292d', red: '#fe5142', green: '#5ba352', yellow: '#f4c145', blue: '#2b9af3', magenta: '#a18fff', cyan: '#73c5c5', white: '#d2d2d2',
    brightBlack: '#6a6e73', brightRed: '#ff7468', brightGreen: '#7cc674', brightYellow: '#f9e0a2', brightBlue: '#73bcf7',
    brightMagenta: '#b2a3ff', brightCyan: '#a2d9d9', brightWhite: '#ffffff'},
  light: {background: '#ffffff', foreground: '#151515', cursor: '#0066cc', cursorAccent: '#ffffff', selectionBackground: 'rgba(0, 102, 204, .2)',
    black: '#151515', red: '#c9190b', green: '#3e8635', yellow: '#795600', blue: '#0066cc', magenta: '#5752d1', cyan: '#009596', white: '#6a6e73',
    brightBlack: '#4f5255', brightRed: '#a30000', brightGreen: '#1e4f18', brightYellow: '#8f4700', brightBlue: '#004080',
    brightMagenta: '#3c3d99', brightCyan: '#005f60', brightWhite: '#8a8d90'},
};
const Prefs = {
  // rightClick: 'paste' (select copies, right-click pastes: MobaXterm, PuTTY) or 'menu'; replaces rightPaste /
  // rightClickPaste of earlier versions (ignored). A paste never presses Enter; several lines are shown first.
  value: {font: 13, theme: 'dark', copySelect: true, rightClick: RIGHT_CLICK, pasteAsk: true, keepScrollback: true, wheelArrows: false,
          ...local.get('shell_prefs', {})},
  save() { local.set('shell_prefs', this.value); },
  apply() {
    $('#workspace').style.setProperty('--sh-term-bg', THEMES[this.value.theme].background);
    Terms.all().forEach(v => {
      v.term.options.fontSize = Number(this.value.font);
      v.term.options.theme = THEMES[this.value.theme];
      v.fitSoon();
    });
  },
  open() {
    const v = this.value;
    $('#setFont').value = String(v.font);
    $('#setTheme').value = v.theme;
    $('#setCopySelect').checked = v.copySelect;
    $('#setRightClick').value = v.rightClick === 'menu' ? 'menu' : 'paste';
    $('#setPasteAsk').checked = v.pasteAsk;
    $('#setKeepScrollback').checked = v.keepScrollback;
    $('#setWheelArrows').checked = v.wheelArrows;
    const dialog = $('#settingsDialog');
    dialog.returnValue = '';
    dialog.showModal();
    dialog.addEventListener('close', () => {
      if (dialog.returnValue !== 'ok') return;
      Object.assign(v, {font: Number($('#setFont').value), theme: $('#setTheme').value, copySelect: $('#setCopySelect').checked,
                        rightClick: $('#setRightClick').value, pasteAsk: $('#setPasteAsk').checked,
                        keepScrollback: $('#setKeepScrollback').checked, wheelArrows: $('#setWheelArrows').checked});
      this.save();
      this.apply();
    }, {once: true});
  },
};

/* =========================================================================
   Session, user menu
   ========================================================================= */
const ROLE_LABELS = {admin: 'Administrator', operator: 'Operator'};
function signedInWith(user) {
  const account = user.source === 'local' ? 'a local account' : 'Active Directory';
  return {sso: 'Signed in with Duo SSO', duo: `Signed in with ${account} and Duo`, none: `Signed in with ${account}`,
    bypassed: `Signed in with ${account} (Duo was unreachable and bypassed)`}[user.mfa] || '';
}
const Session = {
  user: null,
  allowed: false,
  outdated: false,
  status: {},
  isAdmin() { return this.user?.role === 'admin'; },
  apply(status) {
    if (!this.outdated && status.ui_version && UI_VERSION && status.ui_version !== UI_VERSION) {
      this.outdated = true;
      toast('A new version of Shell is available. Reload the page (open sessions stay open).', 'info', {label: 'Reload', fn: () => location.reload()});
    }
    if (!status.user) return window.PortalLauncher?.signIn();
    this.status = status;
    this.user = status.user;
    this.allowed = !!status.allowed;
    UserMenu.render(this.user, status.client);
    $$('.admin-only').forEach(el => { el.hidden = !this.isAdmin(); });
    $('#keepDays').textContent = status.keep_days || '';
    $('#appView').hidden = false;
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

/* =========================================================================
   Host tree (left): Favorites, Recent, then one folder per site and per product
   ========================================================================= */
const CATEGORY_ORDER = ['openstack', 'ontap', 'apic', 'vyos', 'huawei', 'cdn', 'dns', 'repo', 'linux', 'siem', 'esxi', 'gb200'];
const CATEGORY_ICONS = {openstack: 'cloud', ontap: 'database', apic: 'network', vyos: 'network', huawei: 'network', esxi: 'cubes', gb200: 'cubes'};
const Hosts = {
  targets: [],
  sites: [],
  site: '',
  query: '',
  selected: '',
  closed: new Set(local.get('shell_tree_closed', [])),
  favorites: new Set(local.get('shell_favorites', [])),
  recent: local.get('shell_recent', []),
  init() {
    $('#hostQ').addEventListener('input', e => { this.query = e.target.value.trim().toLowerCase(); this.render(); });
    $('#hostQ').addEventListener('keydown', e => {
      if (e.key === 'ArrowDown') { e.preventDefault(); this.move(1, true); $('#hostTree').focus(); }
      if (e.key === 'Enter') { e.preventDefault(); const first = this.visible()[0]; if (first) Terms.open(first); }
      if (e.key === 'Escape') { e.target.value = ''; this.query = ''; this.render(); }
    });
    $('#siteFilter').addEventListener('change', e => { this.site = e.target.value; tabStore.set('shell_site', this.site); this.render(); });
    const tree = $('#hostTree');
    tree.addEventListener('click', e => {
      const fav = e.target.closest('[data-fav]');
      if (fav) return this.toggleFavorite(fav.dataset.fav);
      const more = e.target.closest('[data-more]');
      if (more) { const r = more.getBoundingClientRect(); return HostMenu.open(more.dataset.more, r.left, r.bottom); }
      const group = e.target.closest('[data-group]');
      if (group) return this.toggleGroup(group.dataset.group);
      const row = e.target.closest('[data-host]');
      if (row) this.select(row.dataset.host);
    });
    tree.addEventListener('dblclick', e => {
      const row = e.target.closest('[data-host]');
      if (row && !e.target.closest('button')) Terms.open(row.dataset.host);
    });
    tree.addEventListener('contextmenu', e => {
      const row = e.target.closest('[data-host]');
      if (!row) return;
      e.preventDefault();
      this.select(row.dataset.host);
      HostMenu.open(row.dataset.host, e.clientX, e.clientY);
    });
    tree.addEventListener('keydown', e => {
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); this.move(e.key === 'ArrowDown' ? 1 : -1); }
      if (e.key === 'Enter' && this.selected) { e.preventDefault(); Terms.open(this.selected); }
      if (e.key === 'ContextMenu' && this.selected) {
        const r = $(`[data-host="${CSS.escape(this.selected)}"]`, tree)?.getBoundingClientRect();
        if (r) HostMenu.open(this.selected, r.left + 40, r.bottom);
      }
    });
  },
  async load() {
    const data = await api('/api/targets');
    this.targets = data.targets;
    this.sites = data.sites;
    this.restricted = !!data.restricted;
    const saved = tabStore.get('shell_site', '');
    this.site = this.sites.includes(saved) ? saved : '';
    this.renderSites();
    this.render();
  },
  color(site) { return SITE_COLORS[Math.max(0, this.sites.indexOf(site)) % SITE_COLORS.length]; },
  get(id) { return this.targets.find(t => t.id === id); },
  renderSites() {
    const opts = [['', 'All'], ...this.sites.map(s => [s, s])];
    $('#siteFilter').innerHTML = opts.map(([value, label]) => `<label><input type="radio" name="shsite" value="${esc(value)}"${value === this.site ? ' checked' : ''}>`
      + `<span>${value ? `<span class="site-dot" style="--site-color:${this.color(value)}"></span>` : ''}${esc(label)}</span></label>`).join('');
  },
  matches(t) {
    if (this.site && t.site !== this.site) return false;
    if (!this.query) return true;
    return [t.name, t.address, t.user, t.category_label, t.site, t.via].join(' ').toLowerCase().includes(this.query);
  },
  icon(t) { return CATEGORY_ICONS[t.category] || (t.kind === 'director' ? 'cubes' : 'server'); },
  rowHtml(t, special = false) {
    const open = Terms.all().filter(v => v.target.id === t.id && v.state !== 'closed' && !v.guest).length;
    const fav = this.favorites.has(t.id);
    const addr = `${t.user ? `${t.user}@` : ''}${t.address}${Number(t.port) !== 22 ? `:${t.port}` : ''}${t.via ? ` · via ${t.via}` : ''}`;
    return `<div class="sh-host${t.id === this.selected ? ' is-selected' : ''}${t.problem ? ' is-disabled' : ''}" role="treeitem" data-host="${esc(t.id)}"`
      + `${t.problem ? '' : ' draggable="true"'}`
      + ` title="${esc(t.problem || `${t.site} · ${t.category_label} · ${t.name}\n${addr}\nDouble-click or Enter: connect · drag onto the terminals: open there`)}">`
      + (special ? `<span class="site-dot" style="--site-color:${this.color(t.site)};margin:0 4px"></span>` : icon(this.icon(t)))
      + `<span class="sh-host__text"><span class="sh-host__name">${esc(t.name)}${special ? ` <span class="sh-tab__site">${esc(t.site)} · ${esc(t.category_label)}</span>` : ''}</span>`
      + `<span class="sh-host__addr">${esc(addr)}</span></span>`
      + `<span class="sh-host__tools">${t.problem ? `<svg class="pf-icon site-warn" aria-label="Cannot connect"><use href="#i-alert"></use></svg>` : ''}`
      + (open ? `<span class="sh-host__open" title="${open} open session${open > 1 ? 's' : ''}">${open}</span>` : '')
      + `<button type="button" data-fav="${esc(t.id)}" class="${fav ? 'is-on' : ''}" title="${fav ? 'Remove from favorites' : 'Add to favorites'}" aria-label="Favorite">${icon('star')}</button>`
      + `<button type="button" data-more="${esc(t.id)}" title="More" aria-label="More">${icon('more')}</button></span></div>`;
  },
  groupHtml(key, label, count, cls, extra = '') {
    const open = this.query || !this.closed.has(key);
    return `<button type="button" class="sh-tree__group ${cls}" data-group="${esc(key)}" aria-expanded="${open}">${icon('angle-right')}`
      + `${extra}<span>${label}</span><span class="sh-count">${count}</span></button>`;
  },
  html(targets = this.targets) {
    const shown = targets.filter(t => this.matches(t));
    if (!this.targets.length) {
      return this.restricted
        ? '<div class="sh-tree__empty">No host has been given to your account yet. An administrator gives hosts on Shell → Access.</div>'
        : '<div class="sh-tree__empty">No hosts yet. Administrators add them on Runbook Automation → Hosts &amp; SSH, and in sites.yml.</div>';
    }
    if (!shown.length) return '<div class="sh-tree__empty">No host matches.</div>';
    let html = '';
    const special = (key, label, ids) => {
      const items = ids.map(id => shown.find(t => t.id === id)).filter(Boolean);
      if (!items.length) return;
      const open = this.query || !this.closed.has(key);
      html += `<div class="sh-tree__special">${this.groupHtml(key, label, items.length, 'is-special')}`
        + (open ? items.map(t => this.rowHtml(t, true)).join('') : '') + '</div>';
    };
    if (!this.query) {
      special('fav', 'Favorites', [...this.favorites]);
      special('recent', 'Recent', this.recent.slice(0, 6));
    }
    for (const site of this.sites) {
      const ofSite = shown.filter(t => t.site === site);
      if (!ofSite.length) continue;
      const siteKey = `site:${site}`;
      html += this.groupHtml(siteKey, `<b>${esc(site)}</b>`, ofSite.length, 'is-site', `<span class="site-dot" style="--site-color:${this.color(site)}"></span>`);
      if (!this.query && this.closed.has(siteKey)) continue;
      const cats = [...new Set(ofSite.map(t => t.category))].sort((a, b) => {
        const ia = CATEGORY_ORDER.indexOf(a), ib = CATEGORY_ORDER.indexOf(b);
        return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib) || a.localeCompare(b);
      });
      for (const cat of cats) {
        const items = ofSite.filter(t => t.category === cat);
        const catKey = `cat:${site}:${cat}`;
        html += this.groupHtml(catKey, esc(items[0].category_label), items.length, 'is-category');
        if (this.query || !this.closed.has(catKey)) html += items.map(t => this.rowHtml(t)).join('');
      }
    }
    return html;
  },
  render() {
    $('#hostTree').innerHTML = this.html();
    Start.render();
  },
  visible() { return $$('#hostTree [data-host]').map(el => el.dataset.host); },
  select(id) {
    this.selected = id;
    $$('#hostTree [data-host]').forEach(el => el.classList.toggle('is-selected', el.dataset.host === id));
  },
  move(step, first = false) {
    const ids = [...new Set(this.visible())];
    if (!ids.length) return;
    const at = first ? -1 : ids.indexOf(this.selected);
    const next = ids[Math.max(0, Math.min(ids.length - 1, at + step))];
    this.select(next);
    $(`#hostTree [data-host="${CSS.escape(next)}"]`)?.scrollIntoView({block: 'nearest'});
  },
  toggleGroup(key) {
    if (this.query) return;
    if (this.closed.has(key)) this.closed.delete(key); else this.closed.add(key);
    local.set('shell_tree_closed', [...this.closed]);
    this.render();
  },
  toggleFavorite(id) {
    if (this.favorites.has(id)) this.favorites.delete(id); else this.favorites.add(id);
    local.set('shell_favorites', [...this.favorites]);
    this.render();
  },
  used(id) {
    this.recent = [id, ...this.recent.filter(x => x !== id)].slice(0, 12);
    local.set('shell_recent', this.recent);
  },
};

// Menu of a host (right-click or ⋮): connect here or in a new pane, favorites, copy the address.
const HostMenu = {
  id: '',
  init() {
    const menu = $('#hostMenu');
    menu.addEventListener('click', e => {
      const btn = e.target.closest('button[data-act]');
      if (!btn) return;
      const t = Hosts.get(this.id);
      this.close();
      if (!t) return;
      if (btn.dataset.act === 'open') Terms.open(t.id);
      if (btn.dataset.act === 'split') Terms.open(t.id, {split: true});
      if (btn.dataset.act === 'fav') Hosts.toggleFavorite(t.id);
      if (btn.dataset.act === 'copy') Clip.copyText(t.address);
    });
    document.addEventListener('mousedown', e => { if (!menu.hidden && !menu.contains(e.target)) this.close(); });
    document.addEventListener('keydown', e => { if (e.key === 'Escape' && !menu.hidden) this.close(); });
    window.addEventListener('blur', () => this.close());
  },
  open(id, x, y) {
    const t = Hosts.get(id);
    if (!t) return;
    this.id = id;
    const menu = $('#hostMenu');
    const off = t.problem ? ' disabled' : '';
    menu.innerHTML = `<button type="button" role="menuitem" data-act="open"${off}>${icon('terminal')}Connect</button>`
      + `<button type="button" role="menuitem" data-act="split"${off}>${icon('layout-2')}Connect in a new pane</button><hr>`
      + `<button type="button" role="menuitem" data-act="fav">${icon('star')}${Hosts.favorites.has(id) ? 'Remove from favorites' : 'Add to favorites'}</button>`
      + `<button type="button" role="menuitem" data-act="copy">${icon('copy')}Copy address</button>`
      + (t.problem ? `<hr><div class="pf-text-secondary pf-text-sm" style="padding:4px 16px;max-width:300px">${esc(t.problem)}</div>` : '');
    menu.hidden = false;
    const w = menu.offsetWidth, h = menu.offsetHeight;
    menu.style.left = `${Math.min(x, innerWidth - w - 8)}px`;
    menu.style.top = `${Math.min(y, innerHeight - h - 8)}px`;
    menu.querySelector('button:not(:disabled)')?.focus();
  },
  close() { $('#hostMenu').hidden = true; },
};

// Menu of a terminal (right-click): copy, paste (several lines are shown first; nothing runs before Enter), select all,
// clear, save the selection as a snippet.
const TermMenu = {
  view: null,
  init() {
    const menu = $('#termMenu');
    menu.addEventListener('click', e => {
      const btn = e.target.closest('button[data-act]');
      const view = this.view;
      if (!btn || !view) return;
      this.close();
      ({copy: () => Clip.copyText(view.term.getSelection()),
        paste: () => Clip.pasteFromClipboard(view),
        all: () => view.term.selectAll(),
        clear: () => view.term.clear(),
        snippet: () => { Snippets.toggle(true); Snippets.edit(null); }})[btn.dataset.act]?.();
      if (btn.dataset.act !== 'snippet') view.focus();
    });
    document.addEventListener('mousedown', e => { if (!menu.hidden && !menu.contains(e.target)) this.close(); });
    document.addEventListener('keydown', e => { if (e.key === 'Escape' && !menu.hidden) { this.close(); this.view?.focus(); } });
    window.addEventListener('blur', () => this.close());
  },
  open(view, x, y) {
    this.view = view;
    const menu = $('#termMenu');
    const sel = view.term.hasSelection();
    const open = view.state === 'open';
    menu.innerHTML = `<button type="button" role="menuitem" data-act="copy"${sel ? '' : ' disabled'}>${icon('copy')}Copy<span class="sh-menu__key">${MOD}C</span></button>`
      + `<button type="button" role="menuitem" data-act="paste"${open ? '' : ' disabled'}>${icon('paste')}Paste<span class="sh-menu__key">${MOD}V</span></button>`
      + `<button type="button" role="menuitem" data-act="all">${icon('list')}Select all</button><hr>`
      + `<button type="button" role="menuitem" data-act="snippet"${sel ? '' : ' disabled'}>${icon('code')}Save selection as snippet</button>`
      + `<button type="button" role="menuitem" data-act="clear">${icon('trash')}Clear screen and scrollback</button>`;
    menu.hidden = false;
    menu.style.left = `${Math.min(x, innerWidth - menu.offsetWidth - 8)}px`;
    menu.style.top = `${Math.min(y, innerHeight - menu.offsetHeight - 8)}px`;
    menu.querySelector('button:not(:disabled)')?.focus();
  },
  close() { $('#termMenu').hidden = true; },
};

/* =========================================================================
   Terminals: one xterm per session; it moves between the panes
   ========================================================================= */
// The host clears the screen (`clear`, Ctrl+L): as in Termius, MobaXterm or iTerm, what was on it stays in the scrollback.
// `clear` also sends "erase the scrollback" (CSI 3 J): ignored. Before "erase the screen" (CSI 2 J) the lines in use are
// scrolled up into the scrollback (xterm.js 5.5 has no scrollOnEraseInDisplay). Full-screen programs (vim, top, less) use
// the alternate screen and are left alone. Returns write(bytes): the output of the host, in order.
function scrollbackKeeper(term) {
  term.parser.registerCsiHandler({final: 'J'}, params => params[0] === 3 && Prefs.value.keepScrollback);
  const write = data => new Promise(resolve => term.write(data, resolve));
  const eraseAt = (bytes, from) => {   // index of ESC [ 2 J
    for (let i = bytes.indexOf(0x1b, from); i >= 0 && i + 3 < bytes.length; i = bytes.indexOf(0x1b, i + 1)) {
      if (bytes[i + 1] === 0x5b && bytes[i + 2] === 0x32 && bytes[i + 3] === 0x4a) return i;
    }
    return -1;
  };
  const pushScreen = () => {
    const b = term.buffer.active;
    if (b.type !== 'normal' || !Prefs.value.keepScrollback) return '';
    let last = -1;
    for (let y = term.rows - 1; y >= 0 && last < 0; y -= 1) {
      if (b.getLine(b.baseY + y)?.translateToString(true).trim()) last = y;
    }
    if (last < 0) return '';
    // to the last row, one line feed per line in use (each scrolls one line into the scrollback), cursor back
    return `\x1b[${term.rows};1H${'\n'.repeat(last + 1)}\x1b[${b.cursorY + 1};${b.cursorX + 1}H`;
  };
  let chain = Promise.resolve();
  return bytes => {
    chain = chain.then(async () => {
      let start = 0;
      for (let at = eraseAt(bytes, 0); at >= 0; at = eraseAt(bytes, at + 4)) {
        if (at > start) await write(bytes.subarray(start, at));
        const lift = pushScreen();
        if (lift) await write(lift);
        start = at;   // the erase itself goes with the next part
      }
      if (start < bytes.length) await write(bytes.subarray(start));
    }).catch(() => {});
    return chain;
  };
}

let viewSeq = 0;
class TermView {
  // guest: {mode: 'watch' | 'join', owner}: an administrator in a session of another user (read-only, or typing too)
  constructor(target, info = null, guest = null) {
    this.id = `v${++viewSeq}`;
    this.target = target;
    this.info = info;
    this.guest = guest;
    this.watchers = info?.watchers || [];
    this.sid = info?.id || '';
    this.offset = info ? -1 : 0;
    this.state = info ? info.state : 'connecting';
    this.reason = info?.reason || '';
    this.exitCode = info?.exit_code ?? null;
    this.started = info ? new Date(info.started).getTime() : Date.now();
    this.root = !!info?.root;
    this.queue = [];
    this.sending = false;
    this.size = '';
    this.el = document.createElement('div');
    this.el.className = 'sh-term';
    this.el.dataset.view = this.id;
    this.term = new Terminal({fontFamily: '"Red Hat Mono", "Liberation Mono", Menlo, Consolas, monospace', fontSize: Number(Prefs.value.font),
      lineHeight: 1.15, cursorBlink: true, scrollback: 10000, theme: THEMES[Prefs.value.theme], macOptionIsMeta: true,
      macOptionClickForcesSelection: true,   // tmux / vim reading the mouse: Option-drag (Shift-drag elsewhere) still selects
      drawBoldTextInBrightColors: true, allowTransparency: false});
    this.fit = new FitAddon.FitAddon();
    this.term.loadAddon(this.fit);
    this.output = scrollbackKeeper(this.term);
    this.opened = false;
    this.term.onData(data => this.send(data));
    this.term.onBinary(data => this.send(data));
    this.term.onSelectionChange(() => {   // copy on select (PuTTY, MobaXterm): once the mouse stops
      clearTimeout(this.selTimer);
      this.selTimer = setTimeout(() => {
        if (Prefs.value.copySelect && this.term.hasSelection()) Clip.copyText(this.term.getSelection(), true);
      }, 250);
    });
    this.term.attachCustomKeyEventHandler(e => this.key(e));
    // The wheel in a full-screen program that does not read the mouse (tmux without "mouse on", less): xterm.js would
    // type arrow keys, which in tmux reach the shell as its history (a scroll and Enter could run an old command). Off
    // unless chosen in the settings; a program that reads the mouse (tmux with mouse on, vim) still gets the wheel.
    this.term.attachCustomWheelEventHandler(e => {
      if (this.term.buffer.active.type !== 'alternate' || this.term.modes.mouseTrackingMode !== 'none' || Prefs.value.wheelArrows) return true;
      e.preventDefault();
      if (!this.wheelHint) {
        this.wheelHint = true;
        toast('Scrolling in tmux: turn the mouse on in tmux with  tmux set -g mouse on  (or in ~/.tmux.conf), then the wheel '
          + 'scrolls tmux. Without it: Ctrl+b [ then PgUp / PgDn, q to leave. The wheel sends no arrow keys here (Terminal settings).', 'info');
      }
      return false;
    });
    // Paste (⌘V, Ctrl+V, Ctrl+Shift+V, Shift+Insert, the browser menu) goes through Clip: several lines are shown first.
    this.el.addEventListener('paste', e => {
      e.preventDefault();
      e.stopImmediatePropagation();
      Clip.paste(this, e.clipboardData?.getData('text/plain') || '');
    }, true);
    // Right-click (setting "paste", Windows and Linux by default): selecting copied the text already, a right-click
    // pastes it, as in MobaXterm and PuTTY; with copy on select off, a right-click on a selection copies it instead.
    // Setting "menu" (Mac by default), or Shift + right-click: a menu (Copy, Paste, Select all, ...). A paste never
    // presses Enter, and several lines are shown first: nothing runs by itself.
    this.el.addEventListener('contextmenu', async e => {
      e.preventDefault();
      if (Prefs.value.rightClick === 'menu' || e.shiftKey) return TermMenu.open(this, e.clientX, e.clientY);
      const selection = this.term.hasSelection() ? this.term.getSelection() : '';
      this.term.clearSelection();
      if (selection && !Prefs.value.copySelect) return Clip.copyText(selection);
      if (selection) await Clip.copyText(selection, true);   // just selected: that text is what is pasted
      Clip.pasteFromClipboard(this);
    });
    this.el.addEventListener('mousedown', () => Workspace.focusView(this), true);
    this.resizer = new ResizeObserver(() => this.fitSoon());
    this.resizer.observe(this.el);
  }

  get label() { return this.guest ? `${this.guest.owner}: ${this.target.name}` : this.target.name; }
  get readOnly() { return !!this.guest && this.guest.mode !== 'join'; }
  setGuestMode(mode) {
    this.guest.mode = mode;
    this.term.options.disableStdin = this.readOnly;
  }
  // Keys the page handles itself instead of the terminal.
  key(e) {
    if (e.type !== 'keydown') return true;
    const k = e.key.toLowerCase();
    // Copy: Ctrl+Shift+C (Windows, Linux), Ctrl+Insert, Cmd+C (Mac). The browser's own action is stopped: in Chrome and
    // Edge, Ctrl+Shift+C opens DevTools (Inspect element).
    if ((e.ctrlKey && e.shiftKey && !e.altKey && e.code === 'KeyC') || (e.ctrlKey && !e.shiftKey && e.code === 'Insert')
      || (IS_MAC && e.metaKey && k === 'c')) {
      e.preventDefault();
      e.stopPropagation();
      if (this.term.hasSelection()) Clip.copyText(this.term.getSelection());
      return false;
    }
    if ((e.ctrlKey && e.shiftKey && k === 'v') || (e.ctrlKey && !e.shiftKey && !e.altKey && k === 'v' && !IS_MAC)) return false;  // browser paste event
    if (IS_MAC && e.metaKey && ['v', 'a', 'f', 'r', 't', 'w', 'l'].includes(k)) {
      if (k === 'a') { this.term.selectAll(); return false; }
      return false;
    }
    return true;
  }
  mount(container) {
    if (this.el.parentElement !== container) container.appendChild(this.el);
    if (!this.opened) {
      this.term.open(this.el);
      this.opened = true;
    }
    this.fitSoon();
  }
  park() { this.el.remove(); }
  // Focus without scrolling the page (the xterm input sits at the cursor; the guide is below the workspace).
  focus() {
    const x = window.scrollX, y = window.scrollY;
    this.term.focus();
    if (window.scrollY !== y || window.scrollX !== x) window.scrollTo(x, y);
  }
  fitSoon() {
    clearTimeout(this.fitTimer);
    this.fitTimer = setTimeout(() => this.fitNow(), 60);
  }
  fitNow() {
    if (!this.opened || !this.el.isConnected || !this.el.offsetWidth || !this.el.offsetHeight) return;
    try { this.fit.fit(); } catch (e) { return; }
    const size = `${this.term.cols}x${this.term.rows}`;
    if (size !== this.size && this.sid && this.state === 'open' && !this.guest) {   // the size is the user's own
      this.size = size;
      api(`/api/sessions/${this.sid}/resize`, {cols: this.term.cols, rows: this.term.rows}).catch(() => {});
    }
    Workspace.renderStatus();
  }
  dims() {
    const d = this.fit.proposeDimensions?.();
    return d && d.cols ? d : {cols: 120, rows: 32};
  }
  send(data) {
    if (this.state === 'closed' || this.readOnly) return;
    // While old output is drawn again (page reloaded, session opened in another tab), xterm answers the terminal queries
    // in it (cursor position, device attributes, colours): those answers are not typed into the host.
    if (this.muted > 0 && data.startsWith('\x1b')) return;
    this.queue.push(data);   // typed while connecting: sent once the session is open
    if (this.sid) this.flush();
  }
  async flush() {
    if (this.sending || !this.queue.length || !this.sid) return;
    this.sending = true;
    try {
      while (this.queue.length) {
        let chunk = '';
        while (this.queue.length && chunk.length < 16000) {
          const next = this.queue[0];
          if (chunk.length + next.length > 16000 && chunk) break;
          if (next.length > 16000) { chunk = next.slice(0, 16000); this.queue[0] = next.slice(16000); break; }
          chunk += this.queue.shift();
        }
        await api(`/api/sessions/${this.sid}/input`, {data: chunk});
      }
    } catch (e) {
      this.queue = [];
      if (this.state === 'open') toast(`${this.label}: ${e.message}`);
    } finally {
      this.sending = false;
    }
  }
  receive(chunk) {
    if (chunk.state === 'gone') return this.ended('The session is no longer on the portal server (it ended or the portal restarted)', null);
    if (chunk.data) {
      const bin = atob(chunk.data);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i);
      if (this.offset < 0 || chunk.truncated) this.catchingUp = true;   // old output, drawn again
      if (this.catchingUp) {
        this.muted = (this.muted || 0) + 1;
        this.output(bytes).then(() => { this.muted -= 1; });
        if (!chunk.more) this.catchingUp = false;
      } else this.output(bytes);
    }
    if (typeof chunk.offset === 'number') this.offset = chunk.offset;
    if (chunk.root && !this.root) { this.root = true; Workspace.renderTabs(); }
    if (chunk.watchers) this.watched(chunk.watchers);
    if (chunk.state === 'closed' && this.state !== 'closed') this.ended(chunk.reason, chunk.exit_code);
    else if (chunk.state === 'open' && this.state === 'connecting') { this.state = 'open'; Workspace.render(); }
  }
  // Administrators watching or joined: shown in the status bar; the user of the session is told when one arrives.
  watched(list) {
    const key = l => l.map(w => `${w.user}:${w.mode}`).join(',');
    if (key(list) === key(this.watchers)) return;
    if (!this.guest) {
      for (const w of list) {
        const before = this.watchers.find(x => x.user === w.user);
        if (!before || before.mode !== w.mode) {
          toast(w.mode === 'join' ? `${w.user} joined your session on ${this.target.name} and can type into it.`
            : `${w.user} is watching your session on ${this.target.name} (read-only).`, w.mode === 'join' ? 'warning' : 'info');
        }
      }
    }
    this.watchers = list;
    if (Workspace.current() === this) Workspace.renderStatus();
    Workspace.renderTabs();
  }
  ended(reason, code) {
    this.state = 'closed';
    this.reason = reason || 'The session ended';
    this.exitCode = code;
    this.failed = code === 255 || code === null;
    this.term.options.cursorBlink = false;
    this.overlay();
    Workspace.renderTabs();
    Workspace.renderStatus();
    Hosts.render();
  }
  overlay() {
    $('.sh-ended', this.el)?.remove();
    if (this.state !== 'closed') return;
    const box = document.createElement('div');
    box.className = `sh-ended${this.failed ? ' is-failed' : ''}`;
    box.innerHTML = `${icon(this.failed ? 'x-circle' : 'info')}<span>${esc(this.reason)}</span>`
      + `<button type="button" class="pf-btn pf-m-primary pf-m-small" data-reconnect>${icon('refresh')}Reconnect</button>`
      + `<button type="button" class="pf-btn pf-m-link pf-m-small" data-discard>Close</button>`;
    box.querySelector('[data-reconnect]').addEventListener('click', () => Terms.reconnect(this));
    box.querySelector('[data-discard]').addEventListener('click', () => Terms.discard(this));
    this.el.appendChild(box);
  }
  dispose() {
    this.resizer.disconnect();
    this.term.dispose();
    this.el.remove();
  }
}

const Terms = {
  views: [],
  opening: new Set(),   // hosts being opened now: a second double-click does not open a second session
  all() { return this.views; },
  byId(id) { return this.views.find(v => v.id === id); },
  // Open a session on a host of the tree: in the active pane, an empty pane, or a new pane (split).
  async open(targetId, {split = false, pane = null, replace = null} = {}) {
    const target = Hosts.get(targetId);
    if (!target) return toast('This host is not in the list any more. Reload the page.');
    if (target.problem) return toast(`${target.name}: ${target.problem}`, 'warning');
    if (this.opening.has(target.id)) return;
    this.opening.add(target.id);
    setTimeout(() => this.opening.delete(target.id), 1500);
    if (location.hash.startsWith('#/history')) location.hash = '#/';
    await Fonts.ready;
    const view = new TermView(target);
    if (replace) {
      this.views.splice(this.views.indexOf(replace), 1, view);
      const at = Workspace.panes.indexOf(replace.id);
      replace.dispose();
      Workspace.place(view, at >= 0 ? at : Workspace.active);
    } else {
      this.views.push(view);
      Workspace.place(view, pane ?? Workspace.paneFor(split));
    }
    Hosts.used(target.id);
    Workspace.render();
    view.term.write(`\x1b[2mConnecting to ${target.user ? `${target.user}@` : ''}${target.address}`
      + `${target.via ? ` via ${target.via}` : ''} (${target.site} · ${target.category_label} · ${target.name})…\x1b[0m\r\n`);
    view.focus();
    const {cols, rows} = view.dims();
    try {
      const data = await api('/api/sessions', {target: target.id, cols, rows});
      if (!this.views.includes(view)) {   // its tab was closed while it was connecting: end it on the server too
        api(`/api/sessions/${data.session.id}`, undefined, 'DELETE').catch(() => {});
        return;
      }
      view.sid = data.session.id;
      view.info = data.session;
      view.state = data.session.state;
      view.size = `${cols}x${rows}`;
      Poller.kick();
      view.flush();
    } catch (e) {
      view.term.write(`\x1b[31m${e.message}\x1b[0m\r\n`);
      view.ended(e.message, null);
    }
    Workspace.render();
    Hosts.render();
  },
  reconnect(view) { return this.open(view.target.id, {replace: view}); },
  // Administrators: a session of another user as a tab of this page, read-only (watch) or typing too (join).
  async guest(sid, mode) {
    const existing = this.views.find(v => v.sid === sid);
    if (existing && !existing.guest) { location.hash = '#/'; return Workspace.show(existing); }   // one's own session
    if (mode === 'join') {
      const row = existing?.info || (await api('/api/sessions?all=1')).sessions.find(x => x.id === sid);
      if (!row) return toast('This session has ended.', 'info');
      if (!await Confirm.ask(`Join the session of ${row.user}?`, `${row.site} · ${row.category_label} · ${row.name}: what you type goes `
        + `to their shell, as theirs. ${row.user} sees that you joined; the activity log and the recording say so.`, 'Join')) return;
    }
    const data = await api(`/api/sessions/${sid}/watch`, {mode});
    location.hash = '#/';
    if (existing) {
      existing.setGuestMode(mode);
      Workspace.show(existing);
      return Workspace.render();
    }
    const info = data.session;
    const known = Hosts.get(info.target) || {id: info.target, site: info.site, name: info.name, category: info.category,
      category_label: info.category_label, address: info.address, user: info.account, via: '', port: 22, problem: ''};
    const view = new TermView({...known, become: false}, info, {mode, owner: info.user});
    view.setGuestMode(mode);
    await Fonts.ready;
    this.views.push(view);
    Workspace.place(view, Workspace.paneFor(false));
    Workspace.render();
    Poller.kick();
    view.focus();
  },
  async close(view, ask = true) {
    if (view.guest) {   // leave a session of someone else: it keeps running
      api(`/api/sessions/${view.sid}/watch`, {mode: 'leave'}).catch(() => {});
      return this.discard(view);
    }
    if (view.state !== 'closed' && view.sid) {
      if (ask && !await Confirm.ask(`End the session on ${view.label}?`, `The SSH connection to ${view.target.address} is closed; `
        + 'a command still running in it stops (use tmux or screen on the host for long work).')) return;
      try { await api(`/api/sessions/${view.sid}`, undefined, 'DELETE'); } catch (e) { /* ended meanwhile */ }
    }
    this.discard(view);
  },
  discard(view) {
    const at = this.views.indexOf(view);
    if (at < 0) return;
    this.views.splice(at, 1);
    const pane = Workspace.panes.indexOf(view.id);
    view.dispose();
    if (pane >= 0) {   // the next tab not shown elsewhere takes the pane
      const free = this.views.find(v => !Workspace.panes.includes(v.id));
      Workspace.panes[pane] = free ? free.id : null;
    }
    Poller.kick();
    Workspace.render();
    Hosts.render();
  },
  // The page was reloaded: the sessions of this user still open on the portal server come back as tabs.
  async reattach() {
    const data = await api('/api/sessions');
    const saved = tabStore.get('shell_ws', {});
    for (const info of data.sessions) {
      const target = Hosts.get(info.target) || {id: info.target, site: info.site, name: info.name, category: info.category,
        category_label: info.category_label, address: info.address, user: info.account, via: '', become: info.become, problem: ''};
      target.become = info.become;
      this.views.push(new TermView(target, info));
    }
    if (!this.views.length) return;
    Workspace.layout = ['1', '2', '2r', '4'].includes(saved.layout) ? saved.layout : '1';
    const bySid = sid => this.views.find(v => v.sid === sid)?.id || null;
    Workspace.panes = Array.from({length: Workspace.count()}, (_, i) => bySid((saved.panes || [])[i]));
    if (!Workspace.panes.some(Boolean)) Workspace.panes[0] = this.views[0].id;
    Workspace.active = Math.min(saved.active || 0, Workspace.count() - 1);
    Workspace.render();
    Hosts.render();   // open-session counts in the tree
    Poller.kick();
  },
};

const Fonts = {ready: (document.fonts?.load('13px "Red Hat Mono"') || Promise.resolve()).catch(() => {})};

/* =========================================================================
   Workspace: layout (1, 2 side by side, 2 above each other, 4), panes, tabs, status bar
   ========================================================================= */
const Workspace = {
  layout: '1',
  panes: [null],
  active: 0,
  count(layout = this.layout) { return {1: 1, 2: 2, '2r': 2, 4: 4}[layout] || 1; },
  init() {
    $$('[data-layout]').forEach(b => b.addEventListener('click', () => this.setLayout(b.dataset.layout)));
    $('#newTabBtn').addEventListener('click', () => { Nav.showHosts(); $('#hostQ').focus(); $('#hostQ').select(); });
    $('#snippetsBtn').addEventListener('click', () => Snippets.toggle());
    $('#settingsBtn').addEventListener('click', () => Prefs.open());
    $('#fullBtn').title = 'Full screen (there Ctrl+W, Ctrl+T and Ctrl+N go to the terminal, not to the browser)';
    $('#fullBtn').addEventListener('click', () => {
      if (document.fullscreenElement) document.exitFullscreen(); else $('#workspace').requestFullscreen?.().catch(() => {});
    });
    document.addEventListener('fullscreenchange', () => {
      // In full screen Ctrl+W, Ctrl+T and Ctrl+N reach the terminal (bash: Ctrl+W deletes a word) instead of closing or
      // opening browser tabs (Chrome, Edge: Keyboard Lock API; elsewhere nothing changes).
      if (document.fullscreenElement) navigator.keyboard?.lock?.(['KeyW', 'KeyT', 'KeyN']).catch(() => {});
      else navigator.keyboard?.unlock?.();
      Terms.all().forEach(v => v.fitSoon());
    });
    const tabs = $('#tabs');
    tabs.addEventListener('click', e => {
      const close = e.target.closest('[data-close]');
      const tab = e.target.closest('[data-tab]');
      if (close) { e.stopPropagation(); const v = Terms.byId(close.dataset.close); if (v) Terms.close(v); return; }
      if (tab) this.show(Terms.byId(tab.dataset.tab));
    });
    tabs.addEventListener('auxclick', e => {
      const tab = e.target.closest('[data-tab]');
      if (tab && e.button === 1) { const v = Terms.byId(tab.dataset.tab); if (v) Terms.close(v); }
    });
    // Drag and drop (Termius, VS Code): a tab or a host of the list on the left onto the terminals. On a single pane:
    // its left / right / top / bottom side splits the screen (the dragged one opens on that side), its middle shows it
    // there; with several panes: the pane it is dropped on. A tab dropped between tabs moves there; a host dropped on
    // the tab bar opens as a new tab.
    tabs.addEventListener('dragstart', e => {
      const tab = e.target.closest('[data-tab]');
      if (!tab) return;
      e.dataTransfer.setData('text/x-shell-view', tab.dataset.tab);
      e.dataTransfer.effectAllowed = 'move';
    });
    $('#hostTree').addEventListener('dragstart', e => {
      const row = e.target.closest('[data-host]');
      if (!row) return;
      e.dataTransfer.setData('text/x-shell-host', row.dataset.host);
      e.dataTransfer.effectAllowed = 'copyMove';
    });
    const dragged = e => (e.dataTransfer.types.includes('text/x-shell-view') ? 'view'
      : e.dataTransfer.types.includes('text/x-shell-host') ? 'host' : '');
    const clear = () => {
      $$('.sh-pane[data-drop], .sh-start[data-drop]').forEach(p => { delete p.dataset.drop; });
      $$('.sh-tab.is-drop-before, .sh-tab.is-drop-after').forEach(t => t.classList.remove('is-drop-before', 'is-drop-after'));
      $('#tabs').classList.remove('is-drop');
    };
    document.addEventListener('dragend', clear);
    const panes = $('#panes');
    const zone = (box, e) => {
      if (this.layout !== '1' || !Terms.all().length) return 'center';
      const r = box.getBoundingClientRect();
      const x = (e.clientX - r.left) / r.width, y = (e.clientY - r.top) / r.height;
      return x < 0.25 ? 'left' : x > 0.75 ? 'right' : y < 0.25 ? 'top' : y > 0.75 ? 'bottom' : 'center';
    };
    const dropBox = e => e.target.closest('[data-pane]') || e.target.closest('.sh-start');
    panes.addEventListener('dragover', e => {
      const box = dropBox(e);
      if (!box || !dragged(e)) return;
      e.preventDefault();
      e.dataTransfer.dropEffect = dragged(e) === 'host' ? 'copy' : 'move';
      const z = zone(box, e);
      $$('.sh-pane[data-drop], .sh-start[data-drop]').forEach(p => { if (p !== box) delete p.dataset.drop; });
      if (box.dataset.drop !== z) box.dataset.drop = z;
    });
    panes.addEventListener('dragleave', e => { if (!panes.contains(e.relatedTarget)) clear(); });
    panes.addEventListener('drop', e => {
      const box = dropBox(e);
      const kind = dragged(e);
      if (!box || !kind) return;
      e.preventDefault();
      const z = zone(box, e);
      clear();
      const id = e.dataTransfer.getData(kind === 'view' ? 'text/x-shell-view' : 'text/x-shell-host');
      const index = box.dataset.pane === undefined ? 0 : Number(box.dataset.pane);
      this.dropped(kind, id, index, z);
    });
    tabs.addEventListener('dragover', e => {
      const kind = dragged(e);
      if (!kind) return;
      e.preventDefault();
      e.dataTransfer.dropEffect = kind === 'host' ? 'copy' : 'move';
      const tab = e.target.closest('[data-tab]');
      $$('.sh-tab.is-drop-before, .sh-tab.is-drop-after').forEach(t => t.classList.remove('is-drop-before', 'is-drop-after'));
      if (kind === 'view' && tab) {
        const r = tab.getBoundingClientRect();
        tab.classList.add(e.clientX < r.left + r.width / 2 ? 'is-drop-before' : 'is-drop-after');
      }
      $('#tabs').classList.toggle('is-drop', kind === 'host');
    });
    tabs.addEventListener('dragleave', e => { if (!tabs.contains(e.relatedTarget)) clear(); });
    tabs.addEventListener('drop', e => {
      const kind = dragged(e);
      if (!kind) return;
      e.preventDefault();
      const tab = e.target.closest('[data-tab]');
      const after = tab?.classList.contains('is-drop-after');
      clear();
      if (kind === 'host') return Terms.open(e.dataTransfer.getData('text/x-shell-host'));
      const view = Terms.byId(e.dataTransfer.getData('text/x-shell-view'));
      const target = tab && Terms.byId(tab.dataset.tab);
      if (!view || !target || view === target) return;
      const list = Terms.views;
      list.splice(list.indexOf(view), 1);
      list.splice(list.indexOf(target) + (after ? 1 : 0), 0, view);
      this.renderTabs();
    });
    panes.addEventListener('click', e => {
      const close = e.target.closest('[data-unpane]');
      if (close) { this.panes[Number(close.dataset.unpane)] = null; this.render(); return; }
      const card = e.target.closest('[data-start]');
      if (card) Terms.open(card.dataset.start);
      const pane = e.target.closest('[data-pane]');
      if (pane) this.activate(Number(pane.dataset.pane));
    });
    $('#statusBar').addEventListener('click', e => {
      const btn = e.target.closest('button[data-act]');
      const view = this.current();
      if (!btn || !view) return;
      ({copy: () => (view.term.hasSelection() ? Clip.copyText(view.term.getSelection()) : toast('Select text in the terminal first.', 'info')),
        paste: () => Clip.pasteFromClipboard(view),
        root: () => run(btn, async () => { await api(`/api/sessions/${view.sid}/root`, {}); view.root = true; this.renderTabs(); this.renderStatus(); view.focus(); }),
        reconnect: () => Terms.reconnect(view),
        end: () => Terms.close(view),
        join: () => run(btn, () => Terms.guest(view.sid, 'join')),
        watchonly: () => run(btn, () => Terms.guest(view.sid, 'watch')),
        leave: () => Terms.close(view),
        clear: () => { view.term.clear(); view.focus(); }})[btn.dataset.act]?.();
    });
    setInterval(() => { const el = $('#statusUptime'); const v = this.current(); if (el && v && v.state === 'open') el.textContent = duration((Date.now() - v.started) / 1000); }, 1000);
    window.addEventListener('beforeunload', e => {
      // Sessions stay open on the server for a while after the page is closed; say so when the page is left.
      if (Terms.all().some(v => v.state === 'open')) { e.preventDefault(); e.returnValue = ''; }
    });
  },
  current() { return Terms.byId(this.panes[this.active]) || null; },
  // A tab (kind "view") or a host of the list ("host") dropped on pane `index`, on its side `zone` (single pane only).
  dropped(kind, id, index, zone) {
    const view = kind === 'view' ? Terms.byId(id) : null;
    if (kind === 'view' && !view) return;
    if (zone !== 'center' && this.layout === '1') {
      const stay = Terms.byId(this.panes[0]);
      const other = stay && stay !== view ? stay : Terms.all().find(v => v !== view) || null;
      const first = zone === 'left' || zone === 'top';
      this.layout = zone === 'left' || zone === 'right' ? '2' : '2r';
      this.panes = first ? [null, other?.id || null] : [other?.id || null, null];
      index = first ? 0 : 1;
    }
    if (kind === 'host') return Terms.open(id, {pane: index});
    this.place(view, index);
    this.render();
    view.focus();
  },
  paneFor(split) {
    if (split) {
      if (this.layout === '1') this.setLayout('2', false);
      else if (!this.panes.includes(null) && this.layout !== '4') this.setLayout('4', false);
      const empty = this.panes.indexOf(null);
      return empty >= 0 ? empty : this.active;
    }
    if (this.panes[this.active] === null) return this.active;
    const empty = this.panes.indexOf(null);
    return this.count() > 1 && empty >= 0 ? empty : this.active;
  },
  place(view, index) {
    const old = this.panes.indexOf(view.id);
    if (old >= 0 && old !== index) this.panes[old] = this.panes[index];   // moved from another pane: the two swap
    this.panes[index] = view.id;
    this.active = index;
  },
  show(view) {
    if (!view) return;
    const at = this.panes.indexOf(view.id);
    if (at >= 0) this.activate(at); else { this.place(view, this.active); this.render(); }
    view.focus();
  },
  activate(index) {
    if (index === this.active && $(`.sh-pane[data-pane="${index}"]`)?.classList.contains('is-active')) return;
    this.active = index;
    $$('.sh-pane').forEach(p => p.classList.toggle('is-active', Number(p.dataset.pane) === index));
    this.renderTabs();
    this.renderStatus();
    this.save();
  },
  focusView(view) {
    const at = this.panes.indexOf(view.id);
    if (at >= 0 && at !== this.active) this.activate(at);
  },
  setLayout(layout, render = true) {
    const n = this.count(layout);
    const shown = this.panes.filter(Boolean);
    this.layout = layout;
    this.panes = Array.from({length: n}, (_, i) => this.panes[i] ?? null);
    // panes that disappear: their sessions stay open as tabs; empty new panes take tabs not shown yet
    const hidden = shown.filter(id => !this.panes.includes(id));
    for (let i = 0; i < n; i += 1) {
      if (this.panes[i] === null) this.panes[i] = hidden.shift() || Terms.all().find(v => !this.panes.includes(v.id))?.id || null;
    }
    this.active = Math.min(this.active, n - 1);
    if (render) this.render();
  },
  render() {
    $$('[data-layout]').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.layout === this.layout)));
    const box = $('#panes');
    box.className = `sh-panes is-l${this.layout}`;
    Terms.all().forEach(v => { if (!this.panes.includes(v.id)) v.park(); });
    if (!Terms.all().length) {
      box.innerHTML = '';
      box.className = 'sh-panes is-l1';
      box.appendChild(Start.element());
    } else {
      const keep = new Map(Terms.all().map(v => [v.id, v.el]));
      box.innerHTML = this.panes.map((id, i) => this.paneHtml(Terms.byId(id), i)).join('');
      this.panes.forEach((id, i) => {
        const view = Terms.byId(id);
        if (view && keep.has(id)) view.mount($(`.sh-pane[data-pane="${i}"] [data-slot]`, box));
      });
    }
    $('#navOpen').hidden = !Terms.all().some(v => v.state !== 'closed');
    $('#navOpen').textContent = Terms.all().filter(v => v.state !== 'closed').length;
    this.renderTabs();
    this.renderStatus();
    this.save();
  },
  paneHtml(view, i) {
    const color = view ? Hosts.color(view.target.site) : '';
    const head = view
      ? `<span class="sh-state ${this.stateClass(view)}"></span><span>${esc(view.target.site)} · <b>${esc(view.label)}</b></span>`
        + `<span class="mono">${esc(view.target.user ? `${view.target.user}@` : '')}${esc(view.target.address)}</span>`
        + `<button type="button" class="sh-tab__close" data-unpane="${i}" title="Empty this pane (the session stays open in its tab)" aria-label="Empty this pane">${icon('x')}</button>`
      : '<span>Empty pane</span>';
    const body = view ? '<div data-slot style="display:contents"></div>'
      : `<div class="sh-pane__empty">${icon('terminal')}<b>Empty pane</b><span>Drag a tab here, click a tab, or double-click a host.</span></div>`;
    return `<section class="sh-pane${i === this.active ? ' is-active' : ''}" data-pane="${i}" style="${color ? `--site-color:${color}` : ''}">`
      + `<div class="sh-pane__head">${head}</div>${body}</section>`;
  },
  stateClass(view) {
    if (view.state === 'closed') return view.failed ? 'is-failed' : 'is-closed';
    return `is-${view.state}${view.root ? ' is-root' : ''}`;
  },
  renderTabs() {
    $('#tabs').innerHTML = this.tabsHtml(Terms.all(), this.panes[this.active], this.panes);
    const box = $('#tabs'), tab = $('#tabs [data-tab].is-current');   // keep the current tab in view (not the page)
    if (tab && tab.offsetLeft < box.scrollLeft) box.scrollLeft = tab.offsetLeft;
    else if (tab && tab.offsetLeft + tab.offsetWidth > box.scrollLeft + box.clientWidth) box.scrollLeft = tab.offsetLeft + tab.offsetWidth - box.clientWidth;
  },
  tabsHtml(views, currentId, shownIds) {
    const names = {};
    return views.map(v => {
      const key = `${v.target.site}:${v.label}`;
      names[key] = (names[key] || 0) + 1;
      const n = names[key] > 1 ? ` (${names[key]})` : '';
      const current = currentId === v.id;
      const shown = shownIds.includes(v.id);
      return `<div class="sh-tab${current ? ' is-current' : ''}${shown ? ' is-shown' : ''}" role="tab" tabindex="0" draggable="true" data-tab="${v.id}"`
        + ` aria-selected="${current}" style="--site-color:${Hosts.color(v.target.site)}" title="${esc(`${v.target.site} · ${v.target.category_label} · ${v.label}\n${v.target.user ? `${v.target.user}@` : ''}${v.target.address}${v.state === 'closed' ? `\n${v.reason}` : ''}`)}">`
        + `<span class="sh-state ${this.stateClass(v)}"></span>${v.guest ? icon(v.readOnly ? 'eye' : 'terminal') : ''}`
        + `<span class="sh-tab__label">${esc(v.label)}${esc(n)}</span>`
        + `<span class="sh-tab__site">${esc(v.target.site)}</span>`
        + `<button type="button" class="sh-tab__close" data-close="${v.id}" title="${v.state === 'closed' ? 'Close' : 'End the session'}" aria-label="Close">${icon('x')}</button></div>`;
    }).join('');
  },
  renderStatus() {
    $('#statusBar').innerHTML = this.statusHtml(this.current());
  },
  // The status bar of the active pane (MobaXterm): state, account@address, how long, size, actions.
  statusHtml(v) {
    if (!v) {
      return `<span class="sh-status__item">${Terms.all().length ? 'Click a tab or drag it onto this pane.' : 'No session open.'}</span>`
        + `<span class="sh-status__spacer"></span><span class="sh-status__item">Copy ${MOD}C · Paste ${MOD}V · `
        + `right-click: ${Prefs.value.rightClick === 'menu' ? 'menu' : 'paste (select = copy)'}</span>`;
    }
    const t = v.target;
    const state = v.state === 'open' ? 'Connected' : v.state === 'connecting' ? 'Connecting…' : (v.failed ? 'Failed' : 'Ended');
    const btn = (act, ic, label, extra = '') => `<button type="button" class="pf-btn${act === 'end' ? ' is-danger' : ''}" data-act="${act}"${extra}>${icon(ic)}${label}</button>`;
    const others = v.watchers.filter(w => w.user !== Session.user?.username);
    const guest = v.guest ? (v.readOnly
      ? `<span class="pf-label pf-m-gold pf-m-compact">${icon('eye')}Watching ${esc(v.guest.owner)} (read-only)</span>`
      : `<span class="pf-label pf-m-red pf-m-compact">${icon('terminal')}Joined: you type into the shell of ${esc(v.guest.owner)}</span>`) : '';
    const watchers = others.map(w => (w.mode === 'join'
      ? `<span class="pf-label pf-m-red pf-m-compact" title="${esc(w.user)} can type into this session">${icon('terminal')}${esc(w.user)} joined</span>`
      : `<span class="pf-label pf-m-gold pf-m-compact" title="${esc(w.user)} sees this session (read-only)">${icon('eye')}${esc(w.user)} watching</span>`)).join('');
    if (v.guest) {
      return `<span class="sh-status__item"><span class="sh-state ${this.stateClass(v)}"></span>${state}</span>${guest}`
        + `<span class="sh-status__item"><span class="site-dot" style="--site-color:${Hosts.color(t.site)}"></span>${esc(t.site)} · ${esc(t.category_label)}</span>`
        + `<span class="sh-status__item"><span class="mono">${esc(t.user ? `${t.user}@` : '')}${esc(t.address)}</span></span>${watchers}`
        + (v.state === 'closed' ? `<span class="sh-status__item" title="${esc(v.reason)}">${esc(v.reason.slice(0, 120))}</span>` : '')
        + '<span class="sh-status__spacer"></span>'
        + btn('copy', 'copy', 'Copy', ` title="Copy the selection (${MOD}C)"`)
        + (v.state !== 'open' ? '' : v.readOnly ? btn('join', 'terminal', 'Join (type)', ' title="Type into this session too"')
          : btn('paste', 'paste', 'Paste') + btn('watchonly', 'eye', 'Watch only', ' title="Stop typing: read-only again"'))
        + btn('leave', 'sign-out', 'Leave', ` title="Close this tab; the session of ${esc(v.guest.owner)} keeps running"`);
    }
    return `<span class="sh-status__item"><span class="sh-state ${this.stateClass(v)}"></span>${state}</span>`
      + `<span class="sh-status__item"><span class="site-dot" style="--site-color:${Hosts.color(t.site)}"></span>${esc(t.site)} · ${esc(t.category_label)}</span>`
      + `<span class="sh-status__item"><span class="mono">${esc(t.user ? `${t.user}@` : '')}${esc(t.address)}</span>`
      + `<span>SSH port ${esc(t.port || 22)}</span>${t.via ? `<span>via ${esc(t.via)}</span>` : ''}</span>`
      + (v.state === 'open' ? `<span class="sh-status__item">${icon('in-progress')}<span id="statusUptime">${duration((Date.now() - v.started) / 1000)}</span></span>` : '')
      + (v.opened ? `<span class="sh-status__item">${v.term.cols}×${v.term.rows}</span>` : v.size ? `<span class="sh-status__item">${v.size.replace('x', '×')}</span>` : '')
      + (v.root ? '<span class="pf-label pf-m-gold pf-m-compact">sudo -i</span>' : '') + watchers
      + (v.state === 'closed' ? `<span class="sh-status__item" title="${esc(v.reason)}">${esc(v.reason.slice(0, 120))}</span>` : '')
      + '<span class="sh-status__spacer"></span>'
      + btn('copy', 'copy', 'Copy', ` title="Copy the selection (${MOD}C)"`)
      + btn('paste', 'paste', 'Paste', ` title="Paste (${MOD}V)"${v.state === 'open' ? '' : ' disabled'}`)
      + btn('clear', 'trash', 'Clear', ' title="Clear the screen and the scrollback of this page (the host is not touched)"')
      + (t.become && v.state === 'open' && !v.root ? btn('root', 'root', 'Become root', ` title="sudo -i${t.privilege === 'sudo_password' ? ': the portal answers the password prompt' : ''}"`) : '')
      + (v.state === 'closed' ? btn('reconnect', 'refresh', 'Reconnect') : btn('end', 'plug', 'End session'));
  },
  save() {
    tabStore.set('shell_ws', {layout: this.layout, active: this.active,
      panes: this.panes.map(id => Terms.byId(id)?.sid || null)});
  },
};

// The empty workspace: favorites and recent hosts as cards, and the keys.
const Start = {
  element() {
    const box = document.createElement('div');
    box.className = 'sh-start';
    box.id = 'startView';
    box.innerHTML = this.html();
    return box;
  },
  html() {
    const pick = [...new Set([...Hosts.favorites, ...Hosts.recent])].map(id => Hosts.get(id)).filter(t => t && !t.problem).slice(0, 8);
    const cards = pick.length ? pick : Hosts.targets.filter(t => !t.problem && (!Hosts.site || t.site === Hosts.site)).slice(0, 6);
    return `<div class="sh-start__title">${icon('terminal')}<div><h1>Web Terminal</h1>`
      + `<p>Double-click a host on the left to open a terminal. Sessions run on the portal server with the accounts administrators stored.</p></div></div>`
      + (cards.length ? `<h2>${pick.length ? 'Favorites and recent' : 'Hosts'}</h2><div class="sh-start__cards">`
        + cards.map(t => `<button type="button" class="sh-start__card" data-start="${esc(t.id)}">${icon(Hosts.icon(t))}`
          + `<span>${esc(t.name)} <span class="sh-tab__site">${esc(t.site)} · ${esc(t.category_label)}</span></span>`
          + `<small>${esc(t.user ? `${t.user}@` : '')}${esc(t.address)}</small></button>`).join('') + '</div>' : '')
      + '<h2>Keys</h2><div class="sh-help">'
      + [['/', 'search hosts'], ['Enter', 'connect the selected host'], [`${MOD}C`, 'copy the selection'], [`${MOD}V`, 'paste'],
         ...(Prefs.value.rightClick === 'menu' ? [['Right-click', 'menu: copy, paste, snippet']]
           : [['Select', 'copies'], ['Right-click', 'pastes (Shift + right-click: menu)']]), ['Drag a host or a tab', 'to a side of the terminal: split; onto a pane: show it there']]
        .map(([k, what]) => `<span><kbd>${esc(k)}</kbd> ${esc(what)}</span>`).join('') + '</div>';
  },
  render() { const el = $('#startView'); if (el) el.innerHTML = this.html(); },
};

/* =========================================================================
   Output of every session of this page, one long request at a time
   ========================================================================= */
const Poller = {
  controller: null,
  running: false,
  kick() {
    this.controller?.abort();
    if (!this.running) this.loop();
  },
  async loop() {
    this.running = true;
    while (true) {
      const live = Terms.all().filter(v => v.sid && v.state !== 'closed');
      if (!live.length) break;
      this.controller = new AbortController();
      try {
        const c = live.map(v => `${v.sid}:${v.offset}`).join(',');
        const data = await api(`/api/poll?${qs({c, wait: 20})}`, undefined, 'GET', this.controller.signal);
        for (const [sid, chunk] of Object.entries(data.sessions || {})) Terms.all().find(v => v.sid === sid)?.receive(chunk);
      } catch (e) {
        if (e.name !== 'AbortError') await sleep(2000);
      }
    }
    this.running = false;
  },
};

/* =========================================================================
   Copy and paste
   ========================================================================= */
const Clip = {
  last: '',   // the last text copied on this page: pasted when the browser does not give the clipboard
  async copyText(text, quiet = false) {
    if (!text) return;
    this.last = text;
    try {
      await navigator.clipboard.writeText(text);
      if (!quiet) toast('Copied to the clipboard', 'success');
    } catch (e) {
      if (!quiet) toast('The browser refused the copy: select the text and use the browser menu.');
    }
  },
  async pasteFromClipboard(view) {
    let text = null;
    try {
      text = await navigator.clipboard.readText();
    } catch (e) {
      // the browser asks once whether this page may read the clipboard; refused: the text copied on this page, if any
      if (this.last) text = this.last;
      if (!this.warned) {
        this.warned = true;
        toast(`The browser did not give the clipboard to the page${this.last ? ' (the text copied here was pasted)' : ''}: allow `
          + `"Clipboard" for this site (lock icon in the address bar), or paste with ${MOD}V.`, 'info');
      }
    }
    if (text) this.paste(view, text);
  },
  // true when the text was pasted (several lines: after the confirmation)
  async paste(view, text) {
    if (!text || !view || view.state !== 'open') return false;
    if (view.readOnly) { toast('Read-only: Join the session to type into it.', 'info'); return false; }
    // Line breaks at the end are dropped: a paste never runs the (last) command before Enter is pressed.
    text = text.replace(/\r\n?/g, '\n').replace(/\n+$/, '');
    if (!text) return false;
    const lines = text.split('\n');
    if (lines.length > 1 && Prefs.value.pasteAsk && !await this.ask(view, text, lines.length)) {
      view.focus();
      return false;
    }
    view.term.paste(text);
    view.focus();
    return true;
  },
  ask(view, text, count) {
    const dialog = $('#pasteDialog');
    $('#pasteTitle').textContent = `Paste ${count} lines into ${view.label}?`;
    $('#pasteBody').innerHTML = `The lines are typed into <b>${esc(view.target.site)} · ${esc(view.label)}</b> `
      + `(<span class="mono">${esc(view.target.address)}</span>): a shell can run each line as soon as it arrives `
      + '(bash 5.1 and newer keeps a paste on the command line until Enter).';
    $('#pastePreview').textContent = text.length > 6000 ? `${text.slice(0, 6000)}\n… (${text.length - 6000} more characters)` : text;
    $('#pasteOk').textContent = `Paste ${count} lines`;
    $('#pasteNoAsk').checked = false;
    dialog.returnValue = '';
    dialog.showModal();
    $('#pasteOk').focus();
    return new Promise(resolve => dialog.addEventListener('close', () => {
      if (dialog.returnValue === 'ok' && $('#pasteNoAsk').checked) { Prefs.value.pasteAsk = false; Prefs.save(); }
      resolve(dialog.returnValue === 'ok');
    }, {once: true}));
  },
};

/* =========================================================================
   Snippets: saved commands (own ones, and the ones administrators share)
   ========================================================================= */
const Snippets = {
  items: [],
  loaded: false,
  editing: null,
  init() {
    $('#snippetCloseBtn').addEventListener('click', () => this.toggle(false));
    $('#snippetAddBtn').addEventListener('click', () => this.edit(null));
    $('#snippetQ').addEventListener('input', () => this.render());
    $('#snippetList').addEventListener('click', e => {
      const btn = e.target.closest('button[data-act]');
      if (!btn) return;
      const item = this.items.find(s => String(s.id) === btn.dataset.id);
      if (!item) return;
      if (btn.dataset.act === 'paste' || btn.dataset.act === 'run') this.use(item, btn.dataset.act === 'run');
      if (btn.dataset.act === 'edit') this.edit(item);
      if (btn.dataset.act === 'delete') this.remove(item);
    });
    $('#snippetForm').addEventListener('submit', e => {
      if (e.submitter?.value !== 'ok') return;
      e.preventDefault();
      run($('#snippetSave'), () => this.save());
    });
  },
  async toggle(show = $('#snippetDrawer').hidden) {
    $('#snippetDrawer').hidden = !show;
    $('#snippetsBtn').setAttribute('aria-pressed', String(show));
    Terms.all().forEach(v => v.fitSoon());
    if (show && !this.loaded) await run(null, () => this.load());
    if (show) $('#snippetQ').focus();
  },
  async load() {
    this.items = (await api('/api/snippets')).snippets;
    this.loaded = true;
    this.render();
  },
  html(items) {
    if (!items.length) return '<div class="sh-drawer__empty">No snippets yet. <b>Add</b> saves a command you use often; administrators can share one with everyone.</div>';
    const me = Session.user?.username;
    return items.map(s => {
      const mine = s.shared ? Session.isAdmin() : s.owner === me;
      return `<div class="sh-snippet"><div class="sh-snippet__title"><span>${esc(s.name)}</span>${s.shared ? '<span class="pf-label pf-m-blue pf-m-compact">Shared</span>' : ''}</div>`
        + `<pre>${esc(s.command)}</pre><div class="sh-snippet__actions">`
        + `<button type="button" class="pf-btn pf-m-secondary" data-act="paste" data-id="${s.id}" title="Paste into the active terminal">${icon('paste')}Paste</button>`
        + `<button type="button" class="pf-btn pf-m-link" data-act="run" data-id="${s.id}" title="Paste and press Enter">${icon('play')}Run</button>`
        + (mine ? `<span class="pf-toolbar__spacer"></span><button type="button" class="pf-btn pf-m-plain" data-act="edit" data-id="${s.id}" aria-label="Change">${icon('pencil')}</button>`
          + `<button type="button" class="pf-btn pf-m-plain" data-act="delete" data-id="${s.id}" aria-label="Remove">${icon('trash')}</button>` : '')
        + '</div></div>';
    }).join('');
  },
  render() {
    const q = $('#snippetQ').value.trim().toLowerCase();
    $('#snippetList').innerHTML = this.html(this.items.filter(s => !q || `${s.name} ${s.command}`.toLowerCase().includes(q)));
  },
  // Run pastes the command, then presses Enter as a key of its own: a shell with bracketed paste (bash 5.1 and newer:
  // RHEL 9, VyOS 1.4+) keeps pasted text on the command line, so a newline inside the paste would not run it.
  async use(item, enter) {
    const view = Workspace.current();
    if (!view || view.state !== 'open') return toast('Open a session first (the snippet goes to the terminal of the active pane).', 'info');
    if (view.readOnly) return toast('Read-only: Join the session to type into it.', 'info');
    const command = item.command.replace(/\r\n?/g, '\n').replace(/\n+$/, '');
    const pasted = command.includes('\n') ? await Clip.paste(view, command) : (view.term.paste(command), true);
    if (pasted && enter) view.send('\r');
    view.focus();
  },
  edit(item) {
    this.editing = item;
    $('#snippetTitle').textContent = item ? 'Change snippet' : 'Add snippet';
    $('#snippetName').value = item?.name || '';
    const view = Workspace.current();
    $('#snippetCommand').value = item?.command || (view?.term.hasSelection() ? view.term.getSelection().trim() : '');
    $('#snippetShared').checked = !!item?.shared;
    $('#snippetDialog').showModal();
    $('#snippetName').focus();
  },
  async save() {
    const body = {name: $('#snippetName').value, command: $('#snippetCommand').value, shared: $('#snippetShared').checked};
    if (this.editing) await api(`/api/snippets/${this.editing.id}`, body, 'PUT'); else await api('/api/snippets', body);
    $('#snippetDialog').close('saved');
    await this.load();
    toast('Snippet saved', 'success');
  },
  async remove(item) {
    if (!await Confirm.ask(`Remove the snippet ${item.name}?`, item.shared ? 'It is removed for every Shell user.' : 'Only this snippet is removed.', 'Remove')) return;
    await run(null, async () => { await api(`/api/snippets/${item.id}`, undefined, 'DELETE'); await this.load(); });
  },
};

/* =========================================================================
   Session history and recordings
   ========================================================================= */
const History = {
  items: [],
  live: [],
  init() {
    $('#historySite').addEventListener('change', () => run(null, () => this.load()));
    $('#historyUser').addEventListener('change', () => run(null, () => this.load()));
    $('#historyRefresh').addEventListener('click', e => run(e.currentTarget, () => this.load()));
    $('#historyMore').addEventListener('click', e => run(e.currentTarget, () => this.load(true)));
    $('#historyList').addEventListener('click', e => {
      const btn = e.target.closest('button[data-act]');
      if (!btn) return;
      const row = this.items.find(r => r.id === btn.dataset.id);
      if (!row) return;
      if (btn.dataset.act === 'play') run(btn, () => Player.open(row));
      if (btn.dataset.act === 'text') run(btn, () => downloadFile(`/export/history/${row.id}.txt`, `shell-${row.id}.txt`));
      if (btn.dataset.act === 'end') this.end(row);
      if (btn.dataset.act === 'watch' || btn.dataset.act === 'join') run(btn, () => Terms.guest(row.id, btn.dataset.act));
      if (btn.dataset.act === 'show') Terms.guest(row.id, 'watch');   // one's own session: shown, not watched
    });
  },
  async load(more = false) {
    const sites = Session.status.sites || [];
    const select = $('#historySite');
    if (select.options.length !== sites.length + 1) {
      select.innerHTML = '<option value="">All sites</option>' + sites.map(s => `<option>${esc(s)}</option>`).join('');
    }
    const before = more && this.items.length ? this.items[this.items.length - 1].started : '';
    const data = await api(`/api/history?${qs({site: select.value, user: $('#historyUser').value.trim(), limit: 100, before})}`);
    this.items = more ? [...this.items, ...data.items] : data.items;
    this.live = data.live;
    $('#historyMore').hidden = data.items.length < 100;
    $('#historyShown').textContent = `${this.items.length} session${this.items.length === 1 ? '' : 's'}`;
    $('#historyList').innerHTML = this.rowsHtml(this.items);
  },
  result(r) {
    if (this.live.includes(r.id)) return '<span class="pf-label pf-m-blue">Open</span>';
    if (r.status === 'failed') return `<span class="pf-label pf-m-red" title="${esc(r.reason)}">Failed</span>`;
    if (r.status === 'open') return '<span class="pf-label pf-m-gold">Unknown</span>';
    return `<span class="pf-label" title="${esc(r.reason)}">Ended</span>`;
  },
  rowsHtml(items) {
    if (!items.length) return '<tr><td colspan="8"><div class="pf-empty-state">No sessions yet.</div></td></tr>';
    return items.map(r => {
      const secs = r.ended ? (new Date(r.ended) - new Date(r.started)) / 1000 : (Date.now() - new Date(r.started)) / 1000;
      const live = this.live.includes(r.id);
      return `<tr><td class="pf-nowrap">${esc(fmtTime(r.started))}</td><td>${esc(r.username)}</td>`
        + `<td>${esc(r.label)}<span class="pf-table__sub mono">${esc(r.address)}</span></td>`
        + `<td class="mono">${esc(r.account || '-')}</td><td class="pf-nowrap">${duration(secs)}</td>`
        + `<td>${this.result(r)}${r.root ? ' <span class="pf-label pf-m-gold pf-m-compact">sudo -i</span>' : ''}`
        + `${r.reason && !live ? `<span class="pf-table__sub">${esc(r.reason.slice(0, 140))}</span>` : ''}</td>`
        + `<td class="pf-text-sm">${esc(r.client_ip || '-')}</td><td class="pf-table__actions">`
        + (r.recording ? `<button type="button" class="pf-btn pf-m-plain" data-act="play" data-id="${r.id}" title="Show the recording">${icon('play')}</button>`
          + `<button type="button" class="pf-btn pf-m-plain" data-act="text" data-id="${r.id}" title="Download the recording as text">${icon('download')}</button>` : '')
        + (live && r.username === Session.user?.username
          ? `<button type="button" class="pf-btn pf-m-plain" data-act="show" data-id="${r.id}" title="Show it in Terminals">${icon('terminal')}</button>` : '')
        + (live && Session.isAdmin() && r.username !== Session.user?.username
          ? `<button type="button" class="pf-btn pf-m-link" data-act="watch" data-id="${r.id}" title="See its output live (read-only)">${icon('eye')}Watch</button>`
            + `<button type="button" class="pf-btn pf-m-link" data-act="join" data-id="${r.id}" title="Type into it too">${icon('terminal')}Join</button>` : '')
        + (live && (Session.isAdmin() || r.username === Session.user?.username)
          ? `<button type="button" class="pf-btn pf-m-link pf-m-danger" data-act="end" data-id="${r.id}">End</button>` : '')
        + '</td></tr>';
    }).join('');
  },
  async end(row) {
    const other = row.username !== Session.user?.username;
    if (!await Confirm.ask(`End the session of ${row.username}?`, `${row.label}: the SSH connection is closed now${other ? ' and the activity log records that you ended it' : ''}.`)) return;
    await run(null, async () => {
      await api(`/api/sessions/${row.id}`, undefined, 'DELETE');
      await sleep(800);
      await this.load();
    });
  },
};

/* =========================================================================
   Access (administrators): which hosts each operator may open. Rules: * (everything), site:<site>, cat:<site>:<product>,
   host:<id>; a site or a product also covers the hosts added to it later. A host covered by a wider rule is shown ticked
   and greyed: untick the wider rule first.
   ========================================================================= */
const Access = {
  data: null,
  username: '',
  rules: new Set(),        // the ticked rules
  meta: new Map(),         // rule -> {expires, ticket, active}: temporary access (empty expires: permanent)
  init() {
    const now = new Date(Date.now() + 8 * 3600e3);   // a sensible default for "Until": in 8 hours, local time
    $('#accUntil').value = new Date(now.getTime() - now.getTimezoneOffset() * 60e3).toISOString().slice(0, 16);
    ['#accUntil', '#accTicket'].forEach(sel => $(sel).addEventListener('focus', () => { $('#accTemporary').checked = true; }));
    $('#accUsers').addEventListener('click', e => {
      const row = e.target.closest('[data-user]');
      if (row) this.select(row.dataset.user);
    });
    $('#accQ').addEventListener('input', () => this.renderUsers());
    $('#accHostQ').addEventListener('input', () => this.renderTree());
    $('#accAll').addEventListener('change', e => { this.toggle('*', e.target.checked); });
    $('#accTree').addEventListener('change', e => {
      const box = e.target.closest('input[data-rule]');
      if (box) this.toggle(box.dataset.rule, box.checked);
    });
    $('#accSave').addEventListener('click', e => run(e.currentTarget, () => this.save()));
    $('#accReset').addEventListener('click', () => this.select(this.username, true));
  },
  async load() {
    this.data = await api('/api/access');
    this.renderUsers();
    const keep = this.data.accounts.find(a => a.username === this.username);
    const first = keep || this.data.accounts.find(a => a.role !== 'admin') || this.data.accounts[0];
    if (first) this.select(first.username, true); else this.renderTree();
  },
  account(name = this.username) { return this.data?.accounts.find(a => a.username === name); },
  allows(rules, t) {
    return rules.has('*') || rules.has(`site:${t.site}`) || rules.has(`cat:${t.site}:${t.category}`) || rules.has(`host:${t.id}`);
  },
  summary(a) {
    if (a.role === 'admin') return 'Administrator: every host';
    const rules = new Set(a.rules);
    if (rules.has('*')) return 'Every host of every site';
    const n = this.data.targets.filter(t => this.allows(rules, t)).length;
    const temp = (a.grants || []).filter(g => g.expires && g.active !== false).length;
    const gone = (a.grants || []).filter(g => g.active === false).length;
    return (n ? `${n} host${n === 1 ? '' : 's'} (${a.rules.length} rule${a.rules.length === 1 ? '' : 's'})` : 'No host yet')
      + (temp ? ` · ${temp} temporary` : '') + (gone ? ` · ${gone} expired` : '');
  },
  usersHtml(accounts) {
    if (!accounts.length) return '<div class="sh-drawer__empty">No account has the Web Terminal module yet: tick <b>Web Terminal</b> for an account on the Users page.</div>';
    return accounts.map(a => `<button type="button" class="sh-access__user${a.username === this.username ? ' is-selected' : ''}" role="option"`
      + ` aria-selected="${a.username === this.username}" data-user="${esc(a.username)}"><b>${esc(a.display_name || a.username)}</b>`
      + `<span>${a.role === 'admin' ? '<span class="pf-label pf-m-blue pf-m-compact">Administrator</span>' : ''}`
      + `${a.source === 'local' ? ' <span class="pf-label pf-m-compact">Local</span>' : ''}${a.enabled ? '' : ' <span class="pf-label pf-m-compact">Disabled</span>'}</span>`
      + `<small>${esc(a.username)} · ${esc(this.summary(a))}</small></button>`).join('');
  },
  renderUsers() {
    const q = $('#accQ').value.trim().toLowerCase();
    $('#accUsers').innerHTML = this.usersHtml((this.data?.accounts || []).filter(a => !q || `${a.username} ${a.display_name}`.toLowerCase().includes(q)));
  },
  current() {
    return [...this.rules].sort().map(r => ({rule: r, expires: this.meta.get(r)?.expires || '', ticket: this.meta.get(r)?.ticket || ''}));
  },
  dirty() {
    const a = this.account();
    const key = list => list.map(g => `${g.rule}|${g.expires || ''}|${g.ticket || ''}`).sort().join('\n');
    return !!a && key(this.current()) !== key(a.grants || []);
  },
  async select(name, force = false) {
    if (!force && name !== this.username && this.dirty()
      && !await Confirm.ask('Leave the changes unsaved?', `The hosts of ${this.username} were changed and not saved.`, 'Leave', 'Stay')) return;
    this.username = name;
    const grants = this.account()?.grants || [];
    this.rules = new Set(grants.map(g => g.rule));
    this.meta = new Map(grants.map(g => [g.rule, {expires: g.expires || '', ticket: g.ticket || '', active: g.active !== false}]));
    this.renderUsers();
    this.renderTree();
  },
  validity() {
    if (!$('#accTemporary').checked) return {expires: '', ticket: $('#accTicket').value.trim(), active: true};
    const when = new Date($('#accUntil').value);
    if (Number.isNaN(when.getTime()) || when <= new Date()) throw new Error('Choose a time in the future for "Until".');
    return {expires: when.toISOString(), ticket: $('#accTicket').value.trim(), active: true};
  },
  toggle(rule, on) {
    if (on) {
      try { this.meta.set(rule, this.validity()); } catch (e) { toast(e.message, 'warning'); this.renderTree(); return; }
      this.rules.add(rule);
      // a wider rule covers the narrower ones below it: those are dropped
      const [kind, site, cat] = rule.split(':');
      for (const r of [...this.rules]) {
        if (r === rule) continue;
        if (rule === '*') this.rules.delete(r);
        else if (kind === 'site' && (r.startsWith(`cat:${site}:`) || r.startsWith(`host:${site}:`))) this.rules.delete(r);
        else if (kind === 'cat' && r.startsWith(`host:${site}:`)) {
          const t = this.data.targets.find(x => `host:${x.id}` === r);
          if (t && t.category === cat) this.rules.delete(r);
        }
      }
    } else { this.rules.delete(rule); this.meta.delete(rule); }
    for (const r of [...this.meta.keys()]) if (!this.rules.has(r)) this.meta.delete(r);
    this.renderTree();
  },
  badge(rule) {
    const m = this.meta.get(rule);
    if (!m || (!m.expires && !m.ticket)) return '';
    const when = m.expires ? new Date(m.expires) : null;
    const text = !when ? esc(m.ticket) : `${m.active === false || when <= new Date() ? 'expired' : 'until'} ${esc(fmtShort(when))}`;
    return ` <span class="pf-label pf-m-compact${when && (m.active === false || when <= new Date()) ? ' pf-m-red' : when ? ' pf-m-gold' : ''}"`
      + ` title="${esc([when ? `Valid until ${fmtTime(m.expires)}` : 'Permanent', m.ticket].filter(Boolean).join(' · '))}">${text}</span>`;
  },
  treeHtml() {
    const a = this.account();
    if (!a) return '<div class="sh-drawer__empty">Choose an account on the left.</div>';
    const admin = a.role === 'admin';
    const q = $('#accHostQ').value.trim().toLowerCase();
    const live = new Set([...this.rules].filter(r => this.meta.get(r)?.active !== false
      && !(this.meta.get(r)?.expires && new Date(this.meta.get(r).expires) <= new Date())));
    const all = admin || live.has('*');
    const box = (rule, checked, covered, mixed = false) => `<input type="checkbox" data-rule="${esc(rule)}"${checked || covered ? ' checked' : ''}`
      + `${covered || admin ? ' disabled' : ''}${mixed && !checked && !covered ? ' data-mixed="1"' : ''}>`;
    let html = '';
    for (const site of this.data.sites) {
      const ofSite = this.data.targets.filter(t => t.site === site
        && (!q || [t.name, t.address, t.category_label, t.user].join(' ').toLowerCase().includes(q)));
      if (!ofSite.length) continue;
      const siteOn = live.has(`site:${site}`);
      const siteSome = ofSite.some(t => this.allows(live, t));
      html += `<label class="sh-acc-row is-site${all ? ' is-covered' : ''}">${box(`site:${site}`, siteOn, all, siteSome)}`
        + `<span class="site-dot" style="--site-color:${Hosts.color(site)}"></span>Everything on ${esc(site)}${this.badge(`site:${site}`)}`
        + `<span class="pf-text-secondary pf-text-sm">${ofSite.length} host${ofSite.length === 1 ? '' : 's'}</span></label>`;
      const cats = [...new Set(ofSite.map(t => t.category))].sort((x, y) => {
        const ix = CATEGORY_ORDER.indexOf(x), iy = CATEGORY_ORDER.indexOf(y);
        return (ix < 0 ? 99 : ix) - (iy < 0 ? 99 : iy) || x.localeCompare(y);
      });
      for (const cat of cats) {
        const items = ofSite.filter(t => t.category === cat);
        const catOn = live.has(`cat:${site}:${cat}`);
        const covered = all || siteOn;
        html += `<label class="sh-acc-row is-cat${covered ? ' is-covered' : ''}">${box(`cat:${site}:${cat}`, catOn, covered, items.some(t => this.allows(live, t)))}`
          + `All ${esc(items[0].category_label)}${this.badge(`cat:${site}:${cat}`)}<span class="pf-text-secondary pf-text-sm">${items.length}</span></label>`;
        for (const t of items) {
          const hostCovered = covered || catOn;
          html += `<label class="sh-acc-row is-host${hostCovered ? ' is-covered' : ''}">${box(`host:${t.id}`, live.has(`host:${t.id}`), hostCovered)}`
            + `${icon(Hosts.icon(t))}<span>${esc(t.name)}${this.badge(`host:${t.id}`)}</span><span class="mono">${esc(t.user ? `${t.user}@` : '')}${esc(t.address)}</span></label>`;
        }
      }
    }
    return html || '<div class="sh-drawer__empty">No host matches.</div>';
  },
  renderTree() {
    const a = this.account();
    $('#accTitle').textContent = a ? `Hosts of ${a.display_name || a.username}` : 'Choose an account';
    $('#accAll').checked = !!a && (a.role === 'admin' || (this.rules.has('*') && this.meta.get('*')?.active !== false));
    $('#accAll').disabled = !a || a.role === 'admin';
    $('#accTree').innerHTML = this.data ? this.treeHtml() : '';
    $$('#accTree input[data-mixed]').forEach(x => { x.indeterminate = true; });
    const preview = a ? this.summary({...a, rules: [...this.rules], grants: this.current().map(g => ({...g, active: this.meta.get(g.rule)?.active !== false}))}) : '';
    $('#accCount').textContent = a ? (a.role === 'admin' ? 'Administrators open every host' : preview) : '';
    const dirty = this.dirty();
    $('#accSave').disabled = !dirty;
    $('#accReset').disabled = !dirty;
    $('#accDirty').textContent = dirty ? 'Not saved yet' : '';
  },
  async save() {
    const a = this.account();
    const data = await api(`/api/access/${encodeURIComponent(a.username)}`, {grants: this.current()}, 'PUT');   // expired ones are dropped
    a.grants = data.grants;
    a.rules = data.rules;
    this.select(a.username, true);
    toast(`Hosts of ${a.display_name || a.username} saved: ${this.summary(a)}. Open sessions to hosts no longer given end now; `
      + 'temporary access ends by itself at its time.', 'success');
  },
};

const Player = {
  term: null,
  row: null,
  init() {
    $('#playerDialog').addEventListener('close', () => { this.term?.dispose(); this.term = null; });
    $('#playerDownload').addEventListener('click', e => run(e.currentTarget, () => downloadFile(`/export/history/${this.row.id}.txt`, `shell-${this.row.id}.txt`)));
  },
  async open(row) {
    const data = await api(`/api/history/${row.id}/recording`);
    this.row = row;
    $('#playerTitle').textContent = row.label;
    $('#playerInfo').textContent = `${row.username} · ${fmtTime(row.started)} – ${row.ended ? fmtTime(row.ended) : 'open'} · `
      + `${data.size < 1024 ? `${data.size} bytes` : data.size < 1048576 ? `${(data.size / 1024).toFixed(0)} KB` : `${(data.size / 1048576).toFixed(1)} MB`} recorded${data.truncated ? ' (the last 2 MB are shown; Download as text has everything)' : ''}`;
    $('#playerDialog').showModal();
    this.term = new Terminal({fontFamily: '"Red Hat Mono", Menlo, Consolas, monospace', fontSize: Number(Prefs.value.font), scrollback: 200000,
      theme: THEMES[Prefs.value.theme], disableStdin: true, cursorBlink: false, convertEol: false});
    const fit = new FitAddon.FitAddon();
    this.term.loadAddon(fit);
    const output = scrollbackKeeper(this.term);   // a `clear` in the session does not hide what came before it
    $('#player').innerHTML = '';
    this.term.open($('#player'));
    fit.fit();
    const bin = atob(data.data);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i);
    output(bytes).then(() => this.term?.write('\r\n\x1b[2m[end of the recording]\x1b[0m'));
  },
};

/* =========================================================================
   Navigation: #/ terminals, #/history
   ========================================================================= */
const Nav = {
  page: '',
  init() {
    window.addEventListener('hashchange', () => this.go());
    $('#navToggle').setAttribute('aria-expanded', String(!matchMedia('(max-width: 1000px)').matches));
    $('#navToggle').addEventListener('click', () => {
      const page = $('#appView');
      const narrow = matchMedia('(max-width: 1000px)').matches;
      page.classList.toggle(narrow ? 'is-nav-open' : 'is-nav-collapsed');
      $('#navToggle').setAttribute('aria-expanded', String(narrow ? page.classList.contains('is-nav-open') : !page.classList.contains('is-nav-collapsed')));
      Terms.all().forEach(v => v.fitSoon());
    });
    document.addEventListener('keydown', e => {
      if (e.key !== '/' || e.ctrlKey || e.metaKey || e.altKey) return;
      if (e.target.closest('input, textarea, select, .xterm, dialog')) return;
      e.preventDefault();
      this.showHosts();
      $('#hostQ').focus();
      $('#hostQ').select();
    });
  },
  showHosts() {
    const page = $('#appView');
    if (matchMedia('(max-width: 1000px)').matches) page.classList.add('is-nav-open'); else page.classList.remove('is-nav-collapsed');
  },
  go() {
    if ($('#appView').hidden) return;
    UserMenu.close();
    let page = location.hash.startsWith('#/history') ? 'history'
      : location.hash.startsWith('#/access') && Session.isAdmin() ? 'access' : 'terminals';
    if (!Session.allowed) page = 'noaccess';
    $$('[data-page]').forEach(el => { el.hidden = el.dataset.page !== page; });
    $$('.pf-nav__link[data-route]').forEach(a => a.classList.toggle('is-current', a.dataset.route === page));
    this.page = page;
    document.title = {history: 'Session history · Web Terminal', access: 'Access · Web Terminal'}[page] || 'Web Terminal';
    if (page === 'history') run(null, () => History.load());
    if (page === 'access') run(null, () => Access.load());
    if (page === 'terminals') { Terms.all().forEach(v => v.fitSoon()); Workspace.current()?.focus(); }
  },
};

/* =========================================================================
   Start
   ========================================================================= */
document.addEventListener('DOMContentLoaded', async () => {
  UserMenu.init();
  Hosts.init();
  HostMenu.init();
  TermMenu.init();
  Workspace.init();
  Snippets.init();
  History.init();
  Access.init();
  Player.init();
  Nav.init();
  const status = await Session.refresh();
  if (!status) return toast('Cannot reach the portal server.');
  if (!status.user) return;
  Nav.go();
  if (Session.allowed) {
    Prefs.apply();
    await run(null, () => Hosts.load());
    await run(null, () => Terms.reattach());
    Workspace.render();
  }
  // Keep the portal session alive while this page is used (typing in a terminal counts).
  let active = false;
  ['click', 'keydown'].forEach(ev => document.addEventListener(ev, () => { active = true; }, {passive: true, capture: true}));
  setInterval(async () => {
    if (!active) return;
    active = false;
    try {
      const data = await (await fetch('/api/keepalive', {method: 'POST'})).json();
      if (!data.user) window.PortalLauncher?.signIn();
    } catch (e) { /* server not reachable for a moment */ }
  }, 120000);
  setInterval(() => { if (Session.allowed) Hosts.load().catch(() => {}); }, 300000);   // hosts added on Hosts & SSH
});

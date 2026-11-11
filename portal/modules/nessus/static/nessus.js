'use strict';
/* Nessus (portal module /vulns/): the vulnerabilities Tenable Vulnerability Management found with the Nessus scanner of
   every site, kept by the portal for remediation tracking (Overview, Findings, Hosts), and the scans of Tenable (launch,
   stop, Verify fix for one host). Same look and helpers as Runbook Automation (PatternFly v5 like AWX, docs/UI-SPEC.md);
   sign-in, users and credentials belong to the portal. */

/* =========================================================================
   Utilities (same as Runbook Automation)
   ========================================================================= */
const BASE = '/vulns';
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
const qs = params => Object.entries(params).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v ?? '')}`).join('&');
const icon = name => `<svg class="pf-icon" aria-hidden="true"><use href="#i-${name}"></use></svg>`;
const plural = (n, word, many = `${word}s`) => `${n} ${n === 1 ? word : many}`;

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
const OTHER = '(other)';   // the findings outside the management networks of every site (findings.OTHER)

function fmtTime(iso) {
  if (!iso) return '-';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString('en-GB', {day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23'}).replace('Sept', 'Sep');
}
function shortTime(iso) {
  if (!iso) return '-';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString('en-GB', {day: 'numeric', month: 'short', hour: '2-digit',
    minute: '2-digit', hourCycle: 'h23'}).replace('Sept', 'Sep');
}
function shortDate(iso) {
  if (!iso) return '-';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleDateString('en-GB', {day: 'numeric', month: 'short', year: 'numeric'}).replace('Sept', 'Sep');
}
function dl(rows) {
  return `<dl class="pf-dl pf-m-horizontal">${rows.filter(Boolean).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join('')}</dl>`;
}
function alertBox(kind, title, body = '') {
  const name = {success: 'check-circle', danger: 'x-circle', warning: 'alert', info: 'info'}[kind];
  return `<div class="pf-alert pf-m-${kind}"${kind === 'danger' ? ' role="alert"' : ''}>${icon(name)}<div class="pf-alert__title">${title}</div>`
    + (body ? `<div class="pf-alert__body">${body}</div>` : '') + '</div>';
}
const label = (text, color = '', ic = '', title = '') => `<span class="pf-label${color ? ` pf-m-${color}` : ''}"${title ? ` title="${esc(title)}"` : ''}>`
  + `${ic ? icon(ic) : ''}${esc(text)}</span>`;

// Severity of Tenable, one PatternFly label color each; the state of a finding; the status of a scan.
const SEVERITY = {critical: ['Critical', 'red'], high: ['High', 'orange'], medium: ['Medium', 'gold'], low: ['Low', 'blue'], info: ['Info', '']};
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const sevLabel = s => { const [text, color] = SEVERITY[s] || [s, '']; return label(text, color); };
const STATE = {OPEN: ['Open', '', 'alert'], REOPENED: ['Reopened', 'red', 'refresh'], FIXED: ['Fixed', 'green', 'check-circle']};
const stateLabel = s => { const [text, color, ic] = STATE[s] || [s, '', 'info']; return label(text, color, ic); };
const SCAN = {running: ['Running', 'blue', 'in-progress'], pending: ['Pending', 'blue', 'in-progress'], initializing: ['Starting', 'blue', 'in-progress'],
  processing: ['Processing', 'blue', 'in-progress'], resuming: ['Resuming', 'blue', 'in-progress'], publishing: ['Publishing', 'blue', 'in-progress'],
  stopping: ['Stopping', 'gold', 'in-progress'], canceling: ['Stopping', 'gold', 'in-progress'], aborting: ['Stopping', 'gold', 'in-progress'],
  pausing: ['Pausing', 'gold', 'in-progress'], paused: ['Paused', 'gold', 'minus-circle'], completed: ['Completed', 'green', 'check-circle'],
  canceled: ['Stopped', 'gold', 'minus-circle'], cancelled: ['Stopped', 'gold', 'minus-circle'], stopped: ['Stopped', 'gold', 'minus-circle'],
  aborted: ['Aborted', 'red', 'x-circle'], imported: ['Imported', '', 'info'], empty: ['Never run', '', 'minus-circle']};
const scanLabel = s => { const [text, color, ic] = SCAN[s] || [s || 'Unknown', '', 'info']; return label(text, color, ic); };
const SCAN_RUNNING = ['running', 'pending', 'initializing', 'processing', 'resuming', 'publishing', 'stopping', 'canceling', 'aborting', 'pausing', 'paused'];
const SEVERITY_FILTERS = [['', 'Every severity'], ['medium', 'Medium and above'], ['high', 'High and above'], ['critical', 'Critical only']];
const STATE_FILTERS = [['active', 'Open and reopened'], ['open', 'Open'], ['reopened', 'Reopened'], ['fixed', 'Fixed'], ['all', 'Every state']];
const options = (list, value) => list.map(([v, t]) => `<option value="${esc(v)}"${v === value ? ' selected' : ''}>${esc(t)}</option>`).join('');
const count = n => `<span class="ns-count${n ? '' : ' ns-zero'}">${Number(n) || 0}</span>`;
const pluginUrl = id => `https://www.tenable.com/plugins/nessus/${encodeURIComponent(id)}`;
document.addEventListener('click', e => {
  const btn = e.target.closest('[data-copy]');
  if (!btn) return;
  navigator.clipboard?.writeText(btn.dataset.copy).then(() => toast('Copied to clipboard', 'success'), () => toast('Copy failed'));
});

/* =========================================================================
   Requests and notifications (same as Runbook Automation)
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

// The sites of sites.yml, and "Other" while there are findings outside the management networks of every site.
const Site = {
  current: '',
  list: [],
  set(status) {
    this.list = (status.sites || []).map((x, i) => ({...x, color: SITE_COLORS[i % SITE_COLORS.length]}));
    if ((status.counts || {})['']) this.list.push({name: OTHER, title: 'Other', scanner: '', networks: [], color: '#8a8d90', other: true});
  },
  info(name) { return this.list.find(x => x.name === name) || {name, networks: [], scanner: '', color: SITE_COLORS[0]}; },
  title(name) { return name === OTHER ? 'Other' : name; },
  key(name) { return name === OTHER ? '' : name; },   // the key of the counts of a site
  render() {
    $('#siteSwitch').innerHTML = this.list.map(x => `<label title="${x.other ? 'Findings outside the management networks of every site' : `Site ${esc(x.name)}`}">`
      + `<input type="radio" name="site" value="${esc(x.name)}"${x.name === this.current ? ' checked' : ''}><span>`
      + `<span class="site-dot" style="--site-color:${x.color}"></span>${esc(this.title(x.name))}</span></label>`).join('');
    $('#navSites').innerHTML = this.list.filter(x => !x.other).map(x => `<div><span class="site-dot" style="--site-color:${x.color}"></span>${esc(x.name)}`
      + `<span class="pf-text-sm">${x.scanner ? esc(x.scanner) : 'no scanner'} · ${x.networks.length ? plural(x.networks.length, 'network') : 'no networks'}</span></div>`).join('');
  },
  activate(name) {
    this.current = name;
    if (name) tabStore.set('nessus_site', name);
    document.title = name ? `[${this.title(name)}] ${BASE_TITLE}` : BASE_TITLE;
    $$('.site-name-current').forEach(el => { el.textContent = name ? this.title(name) : '-'; });
    $$('#siteSwitch input').forEach(x => { x.checked = x.value === name; });
  },
};

const Session = {
  user: null,
  outdated: false,
  counts: {},
  checkVersion(status) {
    if (this.outdated || !status.ui_version || !UI_VERSION || status.ui_version === UI_VERSION) return;
    this.outdated = true;
    toast('A new version of Nessus is available. Reload the page.', 'info', {label: 'Reload', fn: () => location.reload()});
  },
  apply(status) {
    this.checkVersion(status);
    if (!status.user) return window.PortalLauncher?.signIn();
    this.user = status.user;
    this.allowed = !!status.allowed;
    this.configured = !!status.configured;
    this.canScan = !!status.can_scan;
    this.admin = !!status.is_admin;
    this.counts = status.counts || {};
    this.problems = status.problems || [];
    this.syncHours = status.sync_hours;
    UserMenu.render(this.user, status.client);
    $$('.admin-only').forEach(el => { el.hidden = !this.admin; });
    $('#ncText').textContent = this.admin
      ? 'The portal reads the scans and findings of Tenable Vulnerability Management with the API keys of one Tenable user: enter its access key (username) and secret key (password) on Administration → Credentials, target Tenable Vulnerability Management.'
      : 'The portal reads the scans and findings of Tenable Vulnerability Management with the API keys of one Tenable user. Ask an administrator to enter them on Administration → Credentials.';
    $('#appView').hidden = false;
    Site.set(status);
    const names = Site.list.map(x => x.name);
    Site.render();
    Site.activate([Site.current, tabStore.get('nessus_site')].find(n => n && names.includes(n)) || names[0] || '');
    Nav.counts();
    if (status.sync) Sync.apply(status.sync);
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
   Navigation (hash): #/overview, #/findings, #/hosts, #/hosts/<ip>, #/scans, #/scans/<id>
   ========================================================================= */
const Router = {
  page: '',
  init() {
    window.addEventListener('hashchange', () => this.go());
    $('#siteSwitch').addEventListener('change', e => {
      if (e.target.name !== 'site') return;
      Site.activate(e.target.value);
      Nav.counts();
      // one host or scan belongs to one site: another site shows its list
      if (this.page === 'host') location.hash = '#/hosts';
      else if (this.page === 'scan') location.hash = '#/scans';
      else this.go();
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
    const [, section = 'overview', id] = (location.hash.match(/^#\/([a-z]+)(?:\/([^/?#]+))?/) || []);
    let page = section === 'hosts' ? (id ? 'host' : 'hosts') : section === 'scans' ? (id ? 'scan' : 'scans')
      : section === 'findings' ? 'findings' : 'overview';
    if (!Session.allowed) page = 'noaccess';
    else if (!Session.configured) page = 'notconfigured';
    $$('[data-page]').forEach(el => { el.hidden = el.dataset.page !== page; });
    this.page = page;
    const route = {host: 'hosts', scan: 'scans'}[page] || page;
    $$('.pf-nav__link[data-route]').forEach(a => a.classList.toggle('is-current', a.dataset.route === route));
    ScanPage.stop();
    Scans.stop();
    if (page === 'overview') run(null, () => Overview.load());
    if (page === 'findings') run(null, () => Findings.load());
    if (page === 'hosts') run(null, () => Hosts.load());
    if (page === 'host') run(null, () => HostPage.open(decodeURIComponent(id)));
    if (page === 'scans') run(null, () => Scans.load());
    if (page === 'scan') run(null, () => ScanPage.open(Number(id)));
    Sync.render();
    window.scrollTo(0, 0);
  },
  // the data changed (a sync ended, a scan launched): the page shows it again, where it is
  reload() {
    if (this.page === 'overview') run(null, () => Overview.load());
    if (this.page === 'findings') run(null, () => Findings.load());
    if (this.page === 'hosts') run(null, () => Hosts.load());
    if (this.page === 'host') run(null, () => HostPage.open(decodeURIComponent((location.hash.match(/^#\/hosts\/([^/?#]+)/) || [])[1] || '')));
  },
};

// Left menu: the counts of the current site (open findings, hosts with an open finding, scans of its scanner).
const Nav = {
  scans: {},
  counts() {
    const c = Session.counts[Site.key(Site.current)] || {findings: 0, hosts: 0};
    const put = (sel, n) => { const el = $(sel); el.textContent = n ?? ''; el.hidden = n === undefined || n === null; };
    put('#navFindings', c.findings);
    put('#navHosts', c.hosts);
    put('#navScans', this.scans[Site.current]);
  },
};

/* =========================================================================
   Sync of the findings: the last one in the title of the pages, "Sync now", the bar while one runs
   ========================================================================= */
const Sync = {
  state: null,
  timer: 0,
  init() {
    document.addEventListener('click', e => {
      const b = e.target.closest('[data-sync-now]');
      if (b) run(b, () => this.start());
    });
  },
  apply(state) {
    const was = this.state?.running;
    this.state = state;
    this.render();
    if (state?.running && !was) this.poll();
  },
  text() {
    const s = this.state || {};
    const ok = s.last_ok;
    if (!s.last) return 'Never synced';
    const when = ok ? `Last sync ${shortTime(ok.finished || ok.started)}` : 'No successful sync yet';
    return s.last.status === 'error' ? `${when} · the last one failed` : when;
  },
  title() {
    const s = this.state || {};
    const parts = [];
    if (s.last_ok) parts.push(`Sync #${s.last_ok.id} by ${s.last_ok.username}${s.last_ok.reason === 'auto' ? ' (automatic)' : ''}: ${s.last_ok.received} findings received, `
      + `${s.last_ok.new} new, ${s.last_ok.fixed} fixed, ${s.last_ok.reopened} reopened`);
    if (s.last?.status === 'error') parts.push(`Last sync failed: ${s.last.error}`);
    if (Session.syncHours > 0) parts.push(`A page that opens syncs by itself when the last sync is older than ${Session.syncHours} hours.`);
    return parts.join('\n');
  },
  html() {
    const running = !!this.state?.running;
    return `<span class="pf-text-sm" title="${esc(this.title())}">${esc(this.text())}</span>`
      + `<button type="button" class="pf-btn pf-m-secondary pf-m-small" data-sync-now${running ? ' disabled' : ''}>${icon('refresh')}`
      + `${running ? 'Syncing…' : 'Sync now'}</button>`;
  },
  render() {
    $$('[data-sync]').forEach(el => { el.innerHTML = this.html(); });
    const r = this.state?.running;
    const box = $('#nsRunning');
    box.hidden = !r || !Session.allowed || !Session.configured;
    box.innerHTML = r ? alertBox('info', 'Sync of the findings running on the portal server',
      `<span>${esc(r.phase || 'Starting')} · by ${esc(r.username)}${r.reason === 'auto' ? ' (automatic)' : ''}, started ${esc(shortTime(r.started))}. `
      + 'It goes on when this page is closed.</span>') : '';
  },
  async start() {
    const data = await api('/api/sync', {});
    toast(`Sync #${data.id} started: Tenable prepares the export of the findings (it can take a few minutes).`, 'info');
    this.apply(data.sync);
  },
  async poll() {
    clearTimeout(this.timer);
    let data;
    try { data = await api('/api/sync'); } catch (e) { this.timer = setTimeout(() => this.poll(), 10000); return; }
    const was = this.state?.running;
    this.state = data.sync;
    Session.counts = data.counts || Session.counts;
    Nav.counts();
    this.render();
    if (data.sync.running) { this.timer = setTimeout(() => this.poll(), 3000); return; }
    if (was) {
      const last = data.sync.last || {};
      if (last.status === 'ok') toast(`Sync #${last.id} done: ${last.received} findings received, ${last.new} new, ${last.fixed} fixed, ${last.reopened} reopened.`, 'success');
      else toast(`Sync #${last.id} failed: ${last.error || 'unknown error'}`);
      if ((Session.counts[''] && !Site.list.some(x => x.other)) || (!Session.counts[''] && Site.list.some(x => x.other))) await Session.refresh();
      Router.reload();
    }
  },
};

/* =========================================================================
   Overview: one card per site (KPI tiles per severity, reopened, fixed in 30 days, trend, scanner)
   ========================================================================= */
const Overview = {
  data: null,
  init() {
    $('#ovSites').addEventListener('click', e => {
      const k = e.target.closest('[data-kpi]');
      const link = e.target.closest('[data-open]');
      if (!k && !link) return;
      e.preventDefault();
      const el = k || link;
      Site.activate(el.dataset.site);
      Nav.counts();
      if (k) Findings.setFilters({severity: k.dataset.kpi, state: 'active', view: 'plugins', q: ''});
      location.hash = k ? '#/findings' : `#/${link.dataset.open}`;
    });
  },
  async load() {
    this.data = await api('/api/overview');
    this.render();
  },
  notice() {
    const d = this.data || {};
    const s = d.sync || {};
    const out = [];
    if (!s.last_ok && !s.running) {
      out.push(alertBox('info', 'No findings yet', `<b>Sync now</b> reads from Tenable the findings of the last 90 days (low to critical); `
        + 'later syncs read only what changed. It runs on the portal server and takes a few minutes.'));
    }
    if (s.last?.status === 'error') out.push(alertBox('danger', `The last sync failed (${esc(shortTime(s.last.started))})`, esc(s.last.error || '')));
    if (d.scanners_error) out.push(alertBox('warning', 'The scanners could not be read from Tenable', esc(d.scanners_error)));
    if (Session.admin && Session.problems.length) {
      out.push(alertBox('warning', 'sites.yml: tenable', Session.problems.map(esc).join('<br>')));
    }
    return out.join('');
  },
  scannerLabel(site) {
    if (!site.scanner) return label('No scanner in sites.yml', 'gold', 'alert', 'tenable.scanner of this site in sites.yml names its Nessus scanner');
    const st = site.scanner_status;
    if (!st) return label('Scanner not in Tenable', 'gold', 'alert', `${site.scanner} is not a scanner of Tenable`);
    return st.status === 'on' ? label('Scanner online', 'green', 'check-circle', `${st.name}, last seen ${shortTime(st.last_connect)}`)
      : label('Scanner offline', 'red', 'x-circle', `${st.name}, last seen ${shortTime(st.last_connect)}`);
  },
  spark(trend) {
    if (!trend.length) return '<span class="pf-text-secondary">After the first sync</span>';
    const max = Math.max(1, ...trend.map(p => p.active));
    const bars = trend.map((p, i) => `<span${i === trend.length - 1 ? ' class="is-last"' : ''} style="height:${Math.max(8, Math.round(100 * p.active / max))}%"`
      + ` title="${esc(`${shortTime(p.ts)}: ${p.active} open, ${p.reopened} reopened, ${p.fixed} fixed (30 days)`)}"></span>`).join('');
    const first = trend[0].active, last = trend[trend.length - 1].active;
    const word = last < first ? `down from ${first}` : last > first ? `up from ${first}` : 'unchanged';
    return `<span class="ns-spark" aria-hidden="true">${bars}</span> <span class="pf-text-sm">${last} open, ${word} (${plural(trend.length, 'sync')})</span>`;
  },
  // One card (also drawn by the guide of this page)
  card(site, other = false) {
    const name = other ? OTHER : site.name;
    const color = other ? '#8a8d90' : Site.info(site.name).color;
    const active = site.active || {};
    const total = SEVERITIES.reduce((n, k) => n + (active[k] || 0), 0);
    const kpis = SEVERITIES.map(k => `<button type="button" class="kpi is-${k}${active[k] ? '' : ' is-zero'}" data-kpi="${k}" data-site="${esc(name)}" `
      + `title="${esc(`${SEVERITY[k][0]}${k === 'critical' ? '' : ' and above'}: open findings of ${Site.title(name)}`)}">`
      + `<span class="kpi-value">${active[k] || 0}</span><span class="kpi-label">${SEVERITY[k][0]}</span></button>`).join('');
    const rows = [
      ['Open', `<b>${total}</b> on ${plural(site.hosts || 0, 'host')}`],
      ['Reopened', site.reopened ? label(String(site.reopened), 'red', 'refresh', 'Fixed before, found again') : count(0)],
      ['Fixed (30 days)', site.fixed ? label(String(site.fixed), 'green', 'check-circle') : count(0)],
      ['Trend', this.spark(site.trend || [])],
      other ? ['Scanners', (site.scanners || []).map(s => `${esc(s.name)} ${s.status === 'on' ? label('online', 'green') : label('offline', 'red')}`).join('<br>') || '-']
        : ['Scanner', site.scanner ? `<span class="mono">${esc(site.scanner)}</span>${site.scanner_status ? `<br><span class="pf-text-secondary pf-text-sm">last seen ${esc(shortTime(site.scanner_status.last_connect))}</span>` : ''}` : '-'],
      !other && ['Networks', (site.networks || []).length ? site.networks.map(n => `<span class="mono">${esc(n)}</span>`).join('<br>') : label('None in sites.yml', 'gold', 'alert')],
      other && (site.found_by || []).length && ['Found by', site.found_by.map(x => `<span class="mono">${esc(x.scanner)}</span> `
        + `<span class="pf-text-secondary pf-text-sm">${plural(x.hosts, 'host')}</span>`).join('<br>')],
    ];
    const links = other ? [['findings', 'Findings'], ['hosts', 'Hosts']] : [['findings', 'Findings'], ['hosts', 'Hosts'], ['scans', 'Scans']];
    return `<div class="pf-card ns-site-card" data-site-card="${esc(name)}"><div class="pf-card__header"><div class="ns-site-head">`
      + `<span class="site-dot" style="--site-color:${color}"></span><h2 class="pf-card__title">${esc(other ? 'Other' : site.name)}</h2></div>`
      + `<span class="pf-card__actions">${other ? '<span class="pf-text-secondary pf-text-sm">Outside the networks of every site</span>' : this.scannerLabel(site)}</span></div>`
      + `<div class="pf-card__body"><div class="kpis">${kpis}</div>${dl(rows)}${other ? '' : this.seenHtml(site)}</div>`
      + `<div class="pf-card__footer">${links.map(([p, t]) => `<a class="pf-btn pf-m-link pf-m-inline" href="#/${p}" data-open="${p}" data-site="${esc(name)}">`
        + `${t}${icon('angle-right')}</a>`).join(' ')}</div></div>`;
  },
  // Administrators: the networks the site's scanner found that sites.yml does not list, and a tenable line to check and copy
  // (also drawn by the guide). Never used by the launch guard until it is in sites.yml.
  seenHtml(site) {
    const s = site.seen;
    if (!s) return '';
    const nets = s.networks.map(n => `<span class="mono">${esc(n.network)}</span> (${plural(n.hosts, 'host')}${n.covered ? '' : ', not in sites.yml'})`);
    return `<div class="ns-seen" data-seen><div class="ns-fix__head"><h3 class="ns-fix__title">Networks seen</h3>`
      + `${label('Suggestion: check it', 'gold', 'alert', 'Not used to launch scans until it is written into sites.yml')}</div>`
      + `<p class="pf-text-sm">Seen by <span class="mono">${esc(s.scanners.join(', '))}</span>${s.guessed ? ' (scanners with the site name in theirs: a guess)' : ''}: `
      + `${nets.join(', ')}. The portal launches scans only inside the networks of sites.yml: check these with the network team, then `
      + 'put the line in /etc/ops-portal/sites.yml under the site.</p>'
      + `<div class="ns-cmd"><pre class="pf-code-block">${esc(s.yaml)}</pre><button type="button" class="pf-btn pf-m-plain pf-m-small" `
      + `data-copy="${esc(s.yaml)}" aria-label="Copy the line">${icon('copy')}</button></div></div>`;
  },
  render() {
    const d = this.data;
    if (!d) return;
    $('#ovNotice').innerHTML = this.notice();
    const other = d.other || {};
    const otherCount = SEVERITIES.reduce((n, k) => n + ((other.active || {})[k] || 0), 0);   // as the site switch: active findings only
    $('#ovSites').innerHTML = d.sites.map(s => this.card(s)).join('') + (otherCount ? this.card(other, true) : '')
      || `<div class="pf-card"><div class="pf-empty-state">${icon('cubes')}<h2 class="pf-title">No sites</h2><span>Add the sites to sites.yml on the server first.</span></div></div>`;
  },
};

/* =========================================================================
   How to fix it: the fix plan of one finding (modules/nessus/remedy.py), drawn like "How to fix it" of Runbook
   Automation: numbered steps with where they run and their commands (copy button), the versions, the vendor links and
   Tenable's own solution. Shown only: the portal never runs these commands.
   ========================================================================= */
const Fix = {
  facts(plan) {
    const f = plan.facts || {};
    const out = [label(plan.platform.label, 'blue', 'server', 'Platform, from the operating system Tenable found')];
    if (f.has_patch === true) out.push(label(f.patch_date ? `Patch since ${shortDate(f.patch_date)}` : 'Patch available', 'green', 'check-circle'));
    if (f.has_patch === false) out.push(label('No patch: a configuration change', '', 'tool'));
    if (f.exploit === true) out.push(label('Exploit available', 'red', 'alert', 'A public exploit exists: fix this first'));
    if (f.exploit === false) out.push(label('No known exploit', ''));
    return out.join(' ');
  },
  // the Shell hosts of this address the account may open (Shell cannot open a host from a link: the text says which)
  shellHtml(shell) {
    if (!shell || !shell.length) return '';
    const t = shell[0];
    const which = shell.map(x => `${x.site} · ${x.category} · ${x.name}`).join(' or ');
    return `<a class="pf-btn pf-m-secondary pf-m-small" href="/terminal/" target="_blank" rel="noopener" data-shell title="${esc(`In Shell, open ${which} (${t.address})`)}">`
      + `${icon('terminal')}Open a terminal</a><span class="pf-text-secondary pf-text-sm">In Shell pick <b>${esc(which)}</b>`
      + `${t.problem ? ` (${esc(t.problem)})` : ''}</span>`;
  },
  step(x, i) {
    const cmds = x.commands.join('\n');
    return `<div class="ns-rec"><div class="ns-rec__head"><span class="ns-rec__num">${i + 1}</span><div><p class="ns-rec__title">${esc(x.text)}</p></div></div>`
      + `<div class="ns-rec__where"><span class="pf-label pf-m-blue">${icon('terminal')} ${esc(x.where)}</span></div>`
      + (x.commands.length ? `<div class="ns-cmd"><pre class="pf-code-block">${esc(cmds)}</pre>`
        + `<button type="button" class="pf-btn pf-m-plain pf-m-small" data-copy="${esc(cmds)}" aria-label="Copy the commands">${icon('copy')}</button></div>` : '')
      + '</div>';
  },
  html(plan, shell = [], scope = '') {
    if (!plan) return '';
    const versions = plan.versions.length ? `<div class="ns-fix__versions pf-table-wrap"><table class="pf-table pf-m-compact" aria-label="Versions">`
      + '<thead><tr><th>Package / product</th><th>Installed</th><th>Fixed in</th></tr></thead><tbody>'
      + plan.versions.map(v => `<tr><td class="mono">${esc(v.item)}</td><td class="mono">${esc(v.installed || '-')}</td><td class="mono">${esc(v.fixed || '-')}</td></tr>`).join('')
      + '</tbody></table></div>' : '';
    const links = plan.links.length ? `<div class="ns-rec__refs"><span class="pf-text-secondary">Vendor and Tenable</span>`
      + plan.links.map(u => `<a href="${esc(u)}" target="_blank" rel="noopener">${esc(u.replace(/^https?:\/\//, '').slice(0, 70))}${icon('external')}</a>`).join('') + '</div>' : '';
    return `<div class="ns-fix" data-fix><div class="ns-fix__head"><h3 class="ns-fix__title">How to fix it${scope ? ` <span class="pf-text-secondary pf-text-sm">${esc(scope)}</span>` : ''}</h3>`
      + `<span class="ns-fix__facts">${this.facts(plan)}</span><span class="ns-fix__shell">${this.shellHtml(shell)}</span></div>`
      + `<p class="ns-fix__lead"><b>${esc(plan.title)}.</b> ${esc(plan.why)}</p>${versions}`
      + plan.steps.map((x, i) => this.step(x, i)).join('')
      + (plan.notes.length ? `<ul class="ns-fix__notes">${plan.notes.map(n => `<li>${esc(n)}</li>`).join('')}</ul>` : '')
      + (plan.tenable ? `<div class="ns-fix__tenable"><span class="pf-text-secondary">Tenable says</span><p>${esc(plan.tenable)}</p></div>` : '')
      + links + '</div>';
  },
};

/* =========================================================================
   Findings: one row per plugin with its hosts (expand), or every finding; filters and CSV
   ========================================================================= */
const Findings = {
  filters: {q: '', severity: '', state: 'active', view: 'plugins'},
  data: null,
  open: new Set(),
  hostsOf: {},
  plans: {},   // finding id -> {finding, shell} (GET /api/findings/<id>)
  seq: 0,
  init() {
    $('#fdSeverity').innerHTML = options(SEVERITY_FILTERS, '');
    $('#fdState').innerHTML = options(STATE_FILTERS, 'active');
    let timer = 0;
    $('#fdQ').addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(() => this.changed(), 250); });
    ['#fdSeverity', '#fdState'].forEach(sel => $(sel).addEventListener('change', () => this.changed()));
    $('#fdView').addEventListener('change', () => this.changed());
    $('#fdExport').addEventListener('click', e => run(e.currentTarget, () => downloadFile(`/export/findings.csv?${qs(this.params())}`,
      'Nessus_Findings.csv')));
    $('#fdTable').addEventListener('click', e => {
      if (e.target.closest('[data-clear]')) { this.setFilters({q: '', severity: '', state: 'active'}); this.changed(); return; }
      const row = e.target.closest('tr.ns-row');
      if (row && (e.target.closest('[data-toggle]') || !e.target.closest('a,button'))) this.expand(row, !this.open.has(row.dataset.key));
    });
    document.addEventListener('keydown', e => {   // "/" goes to the search of the page, Esc empties it
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
  setFilters(f) {
    Object.assign(this.filters, f);
    $('#fdQ').value = this.filters.q;
    $('#fdSeverity').value = this.filters.severity;
    $('#fdState').value = this.filters.state;
    $$('#fdView input').forEach(x => { x.checked = x.value === this.filters.view; });
  },
  changed() {
    this.filters = {q: $('#fdQ').value.trim(), severity: $('#fdSeverity').value, state: $('#fdState').value,
      view: $('#fdView input:checked')?.value || 'plugins'};
    run(null, () => this.load());
  },
  params() {
    const {q, severity, state, view} = this.filters;
    return {site: Site.current, severity, state, q, view};
  },
  async load() {
    const seq = ++this.seq;
    const data = await api(`/api/findings?${qs(this.params())}`);
    if (seq !== this.seq) return;   // a newer search answered first
    this.data = data;
    this.hostsOf = {};
    this.plans = {};
    this.render();
    for (const key of this.open) if ($(`#fdTable tr.ns-row[data-key="${CSS.escape(key)}"]`)) this.loadDetail(key);
  },
  head(view) {
    return view === 'plugins'
      ? '<thead><tr><td class="ns-toggle-col"></td><th>Plugin</th><th>Severity</th><th>Hosts</th><th>Open</th><th>Reopened</th>'
        + '<th>Fixed</th><th class="ns-nowrap">VPR</th><th class="ns-nowrap">First found</th><th class="ns-nowrap">Last seen</th></tr></thead>'
      : '<thead><tr><td class="ns-toggle-col"></td><th>Host</th><th>Plugin</th><th>Severity</th><th>State</th><th>Port</th>'
        + '<th class="ns-nowrap">First found</th><th class="ns-nowrap">Last seen</th></tr></thead>';
  },
  empty(cols) {
    const synced = !!Sync.state?.last_ok;
    return `<tbody><tr><td colspan="${cols}"><div class="pf-empty-state">${icon(synced ? 'search' : 'refresh')}`
      + (synced ? `<h2 class="pf-title">No finding matches</h2><span>Nothing on ${esc(Site.title(Site.current))} with these filters.</span>`
        + '<button type="button" class="pf-btn pf-m-link" data-clear>Clear filters</button>'
        : '<h2 class="pf-title">No findings yet</h2><span><b>Sync now</b> reads the findings of the last 90 days from Tenable.</span>')
      + '</div></td></tr></tbody>';
  },
  // One row per plugin, its hosts in the expanded row (also drawn by the guide of this page)
  pluginRow(p) {
    const open = this.open.has(`p${p.plugin_id}`);
    const cves = p.cves.length ? `<span class="pf-table__sub mono">${esc(p.cves.slice(0, 3).join(' '))}${p.cves.length > 3 ? ` +${p.cves.length - 3}` : ''}</span>` : '';
    return `<tbody><tr class="ns-row${open ? ' is-expanded' : ''}" data-plugin="${p.plugin_id}" data-key="p${p.plugin_id}">`
      + `<td class="ns-toggle-col"><button type="button" class="pf-table__toggle" data-toggle aria-expanded="${open}" aria-controls="fdd-${p.plugin_id}" `
      + `aria-label="Hosts of ${esc(p.plugin_name)}">${icon('angle-right')}</button></td>`
      + `<td><span class="ns-name">${esc(p.plugin_name)}</span><span class="pf-table__sub">${esc(p.plugin_family)} · plugin ${p.plugin_id}</span>${cves}</td>`
      + `<td>${sevLabel(p.severity)}</td><td>${count(p.hosts)}</td><td>${count(p.open)}</td><td>${p.reopened ? label(String(p.reopened), 'red', 'refresh') : count(0)}</td>`
      + `<td>${p.fixed ? label(String(p.fixed), 'green', 'check-circle') : count(0)}</td><td class="ns-nowrap">${p.vpr ?? '-'}</td>`
      + `<td class="ns-nowrap">${esc(shortDate(p.first_found))}</td><td class="ns-nowrap">${esc(shortDate(p.last_found))}</td></tr>`
      + `<tr class="ns-detail" id="fdd-${p.plugin_id}"${open ? '' : ' hidden'}><td></td><td colspan="9">${this.detailHtml(p)}</td></tr></tbody>`;
  },
  // the hosts of a plugin and the fix plan of its first host (each host page has the plan of its own versions)
  detailHtml(p, hosts = this.hostsOf[p.plugin_id], fix = hosts && hosts[0] ? this.plans[hosts[0].id] : null) {
    const list = hosts ? `<ul class="ns-hosts">${hosts.map(f => `<li><a href="#/hosts/${encodeURIComponent(f.ipv4)}">${esc(f.ipv4)}</a> `
      + `<span class="pf-text-secondary pf-text-sm">${esc(f.hostname || '')}${f.port ? ` · ${f.port}/${esc(f.protocol.toLowerCase())}` : ''}</span> `
      + `${f.state !== 'OPEN' ? stateLabel(f.state) : ''}</li>`).join('')}</ul>` : '<span class="pf-text-secondary">Loading…</span>';
    return dl([
      ['Hosts', list],
      p.cves.length && ['CVE', `<span class="mono">${esc(p.cves.join(', '))}</span>`],
      ['Scores', `CVSS v3 ${p.cvss3 ?? '-'} · VPR ${p.vpr ?? '-'}`],
      ['Plugin', `<a href="${pluginUrl(p.plugin_id)}" target="_blank" rel="noopener">${p.plugin_id} on tenable.com${icon('external')}</a>`],
    ]) + (fix ? Fix.html(fix.finding.plan, fix.shell, hosts.length > 1 ? `for ${fix.finding.ipv4}; each host page has the plan of its own versions`
      : `for ${fix.finding.ipv4}`) : hosts && hosts.length ? '<span class="pf-text-secondary">Loading How to fix it…</span>' : '');
  },
  // Every finding, its fix plan in the expanded row (also drawn by the guide)
  findingRow(f) {
    const key = `f${f.id}`;
    const open = this.open.has(key);
    const fix = this.plans[f.id];
    return `<tbody><tr class="ns-row${open ? ' is-expanded' : ''}" data-finding="${f.id}" data-key="${key}">`
      + `<td class="ns-toggle-col"><button type="button" class="pf-table__toggle" data-toggle aria-expanded="${open}" aria-controls="fdf-${f.id}" `
      + `aria-label="How to fix ${esc(f.plugin_name)} on ${esc(f.ipv4)}">${icon('angle-right')}</button></td>`
      + `<td class="ns-nowrap"><a class="mono" href="#/hosts/${encodeURIComponent(f.ipv4)}">${esc(f.ipv4)}</a><span class="pf-table__sub">${esc(f.hostname || '')}</span></td>`
      + `<td><span class="ns-name">${esc(f.plugin_name)}</span><span class="pf-table__sub">plugin ${f.plugin_id}${f.cves.length ? ` · ${esc(f.cves.slice(0, 2).join(' '))}` : ''}</span></td>`
      + `<td>${sevLabel(f.severity)}</td><td>${stateLabel(f.state)}${f.state === 'FIXED' && f.last_fixed ? `<span class="pf-table__sub">${esc(shortDate(f.last_fixed))}</span>` : ''}</td>`
      + `<td class="ns-nowrap mono">${f.port ? `${f.port}/${esc(f.protocol.toLowerCase())}` : '-'}</td>`
      + `<td class="ns-nowrap">${esc(shortDate(f.first_found))}</td><td class="ns-nowrap">${esc(shortDate(f.last_found))}</td></tr>`
      + `<tr class="ns-detail" id="fdf-${f.id}"${open ? '' : ' hidden'}><td></td><td colspan="7">`
      + `${fix ? Fix.html(fix.finding.plan, fix.shell) : '<span class="pf-text-secondary">Loading How to fix it…</span>'}</td></tr></tbody>`;
  },
  render() {
    const d = this.data;
    if (!d) return;
    const view = d.view;
    const cols = view === 'plugins' ? 10 : 8;
    const body = d.items.length ? (view === 'plugins' ? d.items.map(p => this.pluginRow(p)) : d.items.map(f => this.findingRow(f))).join('')
      : this.empty(cols);
    $('#fdTable').innerHTML = this.head(view) + body;
    const what = view === 'plugins' ? 'plugin' : 'finding';
    $('#fdShown').textContent = d.total > d.items.length ? `${d.items.length} of ${plural(d.total, what)}` : plural(d.total, what);
  },
  expand(row, open) {
    const key = row.dataset.key;
    if (open) this.open.add(key); else this.open.delete(key);
    row.classList.toggle('is-expanded', open);
    $('[data-toggle]', row).setAttribute('aria-expanded', String(open));
    row.nextElementSibling.hidden = !open;
    if (open) this.loadDetail(key);
  },
  // the fix plan of one finding, read once (GET /api/findings/<id>, as the guide reads it too)
  async plan(id) {
    if (!this.plans[id]) {
      const data = await api(`/api/findings/${id}`);
      this.plans[id] = {finding: data.finding, shell: data.shell};
    }
    return this.plans[id];
  },
  async loadDetail(key) {
    try {
      if (key.startsWith('f')) {
        const id = Number(key.slice(1));
        await this.plan(id);
        const f = (this.data?.items || []).find(x => x.id === id);
        const cell = $(`#fdf-${id} td:last-child`);
        if (f && cell) cell.innerHTML = Fix.html(this.plans[id].finding.plan, this.plans[id].shell);
        return;
      }
      const pluginId = key.slice(1);
      const p = (this.data?.items || []).find(x => String(x.plugin_id) === pluginId);
      if (!p) return;
      if (!this.hostsOf[pluginId]) {
        const {site, severity, state, q} = this.params();
        this.hostsOf[pluginId] = (await api(`/api/findings?${qs({site, severity, state, q, plugin: pluginId})}`)).items;
      }
      const hosts = this.hostsOf[pluginId];
      const draw = () => { const cell = $(`#fdd-${CSS.escape(pluginId)} td:last-child`); if (cell) cell.innerHTML = this.detailHtml(p); };
      draw();
      if (hosts.length) { await this.plan(hosts[0].id); draw(); }
    } catch (e) { toast(e.message); }
  },
};

/* =========================================================================
   Hosts of the site, and one host (its findings with output and solution; Verify fix)
   ========================================================================= */
const Hosts = {
  data: null,
  seq: 0,
  init() {
    $('#hsSeverity').innerHTML = options(SEVERITY_FILTERS, '');
    $('#hsState').innerHTML = options(STATE_FILTERS, 'active');
    let timer = 0;
    $('#hsQ').addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(() => run(null, () => this.load()), 250); });
    ['#hsSeverity', '#hsState'].forEach(sel => $(sel).addEventListener('change', () => run(null, () => this.load())));
    const open = e => {
      const tr = e.target.closest('tr[data-ip]');
      if (tr && (e.type === 'click' || e.key === 'Enter') && !e.target.closest('a')) location.hash = `#/hosts/${encodeURIComponent(tr.dataset.ip)}`;
    };
    $('#hsList').addEventListener('click', open);
    $('#hsList').addEventListener('keydown', open);
  },
  async load() {
    const seq = ++this.seq;
    const data = await api(`/api/hosts?${qs({site: Site.current, severity: $('#hsSeverity').value, state: $('#hsState').value, q: $('#hsQ').value.trim()})}`);
    if (seq !== this.seq) return;
    this.data = data;
    this.render();
  },
  // One host (also drawn by the guide)
  row(h) {
    const sev = k => (h[k] ? label(String(h[k]), SEVERITY[k][1]) : count(0));
    return `<tr class="is-clickable" data-ip="${esc(h.ipv4)}" tabindex="0"><td><a class="mono" href="#/hosts/${encodeURIComponent(h.ipv4)}">${esc(h.ipv4)}</a>`
      + `<span class="pf-table__sub">${esc(h.hostname || '')}</span></td>`
      + SEVERITIES.map(k => `<td>${sev(k)}</td>`).join('')
      + `<td>${h.reopened ? label(String(h.reopened), 'red', 'refresh') : count(0)}</td><td>${h.fixed ? label(String(h.fixed), 'green', 'check-circle') : count(0)}</td>`
      + `<td class="ns-nowrap">${esc(shortDate(h.last_found))}</td></tr>`;
  },
  render() {
    const d = this.data;
    $('#hsShown').textContent = d.total > d.items.length ? `${d.items.length} of ${plural(d.total, 'host')}` : plural(d.total, 'host');
    $('#hsList').innerHTML = d.items.map(h => this.row(h)).join('')
      || `<tr><td colspan="8"><div class="pf-empty-state">${icon('server')}<h2 class="pf-title">No host</h2>`
        + `<span>${Sync.state?.last_ok ? `No host of ${esc(Site.title(Site.current))} with these filters.` : '<b>Sync now</b> reads the findings from Tenable first.'}</span></div></td></tr>`;
  },
};

const HostPage = {
  data: null,
  expanded: new Set(),   // findings opened (details shown)
  init() {
    $('#hoState').innerHTML = options(STATE_FILTERS, 'all');
    $('#hoState').addEventListener('change', () => this.renderList());
    $('#hoTable').addEventListener('click', e => {
      const row = e.target.closest('tr.ns-row');
      if (row && (e.target.closest('[data-toggle]') || !e.target.closest('a,button'))) this.expand(row, !this.expanded.has(row.dataset.id));
    });
    $('#hoVerify').addEventListener('click', () => ScanDialog.openVerify(this.data));
  },
  async open(ip) {
    this.data = null;
    $('#hoCrumb').textContent = ip;
    $('#hoTitle').textContent = ip;
    $('#hoName').textContent = '';
    $('#hoDetail').innerHTML = '';
    $('#hoNotice').innerHTML = '';
    $('#hoTable').innerHTML = '';
    $('#hoVerify').hidden = true;
    $('#hoShell').innerHTML = '';
    const data = await api(`/api/hosts/${encodeURIComponent(ip)}`);
    if (Router.page !== 'host') return;
    this.data = data;
    if (data.site && data.site !== Site.key(Site.current)) Site.activate(data.site);
    if (!data.site && Site.current !== OTHER && Site.list.some(x => x.other)) Site.activate(OTHER);
    this.render();
  },
  verifyState(d) {
    const v = d.verify || {};
    if (!Session.canScan) return {show: false};
    if (!d.site) return {show: true, ok: false, why: 'This address is outside the management networks of every site: no scanner may scan it.'};
    if (v.reason) return {show: true, ok: false, why: v.reason};
    if (v.error) return {show: true, ok: false, why: `The scans could not be read from Tenable: ${v.error}`};
    if (!v.scans.length) return {show: true, ok: false, why: `Tenable has no scan on the scanner of ${d.site}.`};
    return {show: true, ok: true, why: ''};
  },
  render() {
    const d = this.data;
    const active = d.items.filter(f => f.state !== 'FIXED');
    const worst = SEVERITIES.find(k => active.some(f => f.severity === k));
    $('#hoName').textContent = d.hostname || '';
    $('#hoShell').innerHTML = Fix.shellHtml(d.shell);
    $('#hoDetail').innerHTML = dl([
      ['Site', d.site ? `<b>${esc(d.site)}</b> <span class="pf-text-secondary pf-text-sm">${esc(d.site_via.startsWith('scanner ')
        ? `found by ${d.site_via}` : d.site_via)}</span>` : `Other <span class="pf-text-secondary pf-text-sm">(no network of a site holds it${
        d.scanners.length ? `, and ${d.scanners.join(', ')} ${d.scanners.length === 1 ? 'is' : 'are'} no site's scanner` : ''})</span>`],
      d.os && ['Operating system', esc(d.os)],
      ['Open', active.length ? `${SEVERITIES.map(k => [k, active.filter(f => f.severity === k).length]).filter(x => x[1])
        .map(([k, n]) => `${label(`${n} ${SEVERITY[k][0]}`, SEVERITY[k][1])}`).join(' ')}` : label('None', 'green', 'check-circle')],
      ['Reopened', String(d.items.filter(f => f.state === 'REOPENED').length)],
      ['Fixed', String(d.items.filter(f => f.state === 'FIXED').length)],
      ['Last seen', esc(fmtTime(d.items.reduce((m, f) => (f.last_found > m ? f.last_found : m), '')))],
    ]);
    const v = this.verifyState(d);
    const btn = $('#hoVerify');
    btn.hidden = !v.show;
    btn.disabled = !v.ok || !active.length;
    btn.title = v.ok ? (active.length ? `Scan ${d.ip} again with a scan of ${d.site}, to see what was fixed` : 'Nothing open on this host') : v.why;
    $('#hoNotice').innerHTML = !worst ? alertBox('success', 'Nothing open on this host', 'Every finding the portal has of it is fixed.') : '';
    this.renderList();
  },
  head() {
    return '<thead><tr><td class="ns-toggle-col"></td><th>Plugin</th><th>Severity</th><th>State</th><th>Port</th>'
      + '<th class="ns-nowrap">First found</th><th class="ns-nowrap">Last seen</th></tr></thead>';
  },
  // One finding with its output and solution, in its own tbody (also drawn by the guide)
  row(f) {
    const id = String(f.id);
    const open = this.expanded.has(id);
    return `<tbody><tr class="ns-row${open ? ' is-expanded' : ''}" data-id="${id}"><td class="ns-toggle-col"><button type="button" class="pf-table__toggle" data-toggle `
      + `aria-expanded="${open}" aria-controls="hod-${id}" aria-label="Details of ${esc(f.plugin_name)}">${icon('angle-right')}</button></td>`
      + `<td><span class="ns-name">${esc(f.plugin_name)}</span><span class="pf-table__sub">${esc(f.plugin_family)} · plugin ${f.plugin_id}</span></td>`
      + `<td>${sevLabel(f.severity)}</td><td>${stateLabel(f.state)}</td><td class="ns-nowrap mono">${f.port ? `${f.port}/${esc(f.protocol.toLowerCase())}` : '-'}`
      + `${f.service ? `<span class="pf-table__sub">${esc(f.service)}</span>` : ''}</td><td class="ns-nowrap">${esc(shortDate(f.first_found))}</td>`
      + `<td class="ns-nowrap">${esc(shortDate(f.last_found))}</td></tr>`
      + `<tr class="ns-detail" id="hod-${id}"${open ? '' : ' hidden'}><td></td><td colspan="6">${this.detailHtml(f)}</td></tr></tbody>`;
  },
  detailHtml(f) {
    return Fix.html(f.plan, this.data?.shell || []) + '<h3 class="ns-fix__title ns-details-title">Details</h3>' + dl([
      ['Synopsis', esc(f.synopsis || '-')],
      f.description && ['Description', esc(f.description)],
      f.cves.length && ['CVE', `<span class="mono">${esc(f.cves.join(', '))}</span>`],
      ['Scores', `CVSS v3 ${f.cvss3 ?? '-'} · VPR ${f.vpr ?? '-'}`],
      f.scanner && ['Found by', `<span class="mono">${esc(f.scanner)}</span>${f.scan_started ? ` <span class="pf-text-secondary pf-text-sm">scan of `
        + `${esc(fmtTime(f.scan_started))}</span>` : ''}`],
      ['Dates', `First found ${esc(fmtTime(f.first_found))} · last seen ${esc(fmtTime(f.last_found))}`
        + (f.last_fixed ? ` · fixed ${esc(fmtTime(f.last_fixed))}` : '')],
      ['Output', f.output ? `<pre class="pf-code-block">${esc(f.output)}</pre>` : '<span class="pf-text-secondary">No output</span>'],
      ['Plugin', `<a href="${pluginUrl(f.plugin_id)}" target="_blank" rel="noopener">${f.plugin_id} on tenable.com${icon('external')}</a>`],
    ]);
  },
  renderList() {
    const d = this.data;
    if (!d) return;
    const states = {active: ['OPEN', 'REOPENED'], open: ['OPEN'], reopened: ['REOPENED'], fixed: ['FIXED'], all: ['OPEN', 'REOPENED', 'FIXED']}[$('#hoState').value];
    const items = d.items.filter(f => states.includes(f.state));
    $('#hoShown').textContent = plural(items.length, 'finding');
    $('#hoTable').innerHTML = this.head() + (items.map(f => this.row(f)).join('')
      || `<tbody><tr><td colspan="7"><div class="pf-empty-state">${icon('check-circle')}<h2 class="pf-title">No finding</h2><span>Nothing with this state.</span></div></td></tr></tbody>`);
  },
  expand(row, open) {
    const id = row.dataset.id;
    if (open) this.expanded.add(id); else this.expanded.delete(id);
    row.classList.toggle('is-expanded', open);
    $('[data-toggle]', row).setAttribute('aria-expanded', String(open));
    row.nextElementSibling.hidden = !open;
  },
};

/* =========================================================================
   Scans of the site (Tenable): status, scope, last run, schedule; launch and stop
   ========================================================================= */
const Scans = {
  items: [],
  timer: 0,
  init() {
    $('#scRefresh').addEventListener('click', e => run(e.currentTarget, () => this.load(true)));
    $('#scQ').addEventListener('input', () => this.render());
    $('#scList').addEventListener('click', e => {
      const b = e.target.closest('[data-act]');
      if (!b) return;
      const scan = this.items.find(s => String(s.id) === b.dataset.id);
      if (scan) ScanDialog.open(b.dataset.act, scan);
    });
  },
  stop() { clearTimeout(this.timer); },
  async load(force = false) {
    this.stop();
    const data = await api(`/api/scans?${qs({site: Site.current, force: force ? '1' : ''})}`);
    if (Router.page !== 'scans') return;
    this.items = data.items;
    this.proposals = data.proposals || {};
    this.sitesFile = data.sites_file || 'sites.yml';
    Nav.scans[Site.current] = this.items.length;
    Nav.counts();
    this.render();
    // while a scan runs, its status is read again (the portal reads Tenable at most every 10 s)
    if (this.items.some(s => SCAN_RUNNING.includes(s.status))) this.timer = setTimeout(() => run(null, () => this.load(true)), 15000);
  },
  scope(s) {
    return s.guard.ok ? label('Management only', 'green', 'check-circle', s.guard.reason)
      : `${label('Not launchable', 'red', 'x-circle')}<span class="pf-table__sub">${esc(s.guard.reason)}</span>`;
  },
  actions(s) {
    if (!Session.canScan) return '';
    const out = [];
    if (s.can_stop) out.push(`<button type="button" class="pf-btn pf-m-secondary pf-m-small" data-act="stop" data-id="${s.id}">Stop</button>`);
    else out.push(`<button type="button" class="pf-btn pf-m-secondary pf-m-small" data-act="launch" data-id="${s.id}"${s.can_launch ? '' : ` disabled title="${esc(s.launch_reason)}"`}>`
      + `${icon('play')}Launch</button>`);
    return out.join(' ');
  },
  // What sites.yml lacks for the scans of Tenable (from their targets): for a person to add, the portal never applies it
  proposalHtml(siteName) {
    const file = `<code>${esc(this.sitesFile)}</code>`;
    if (siteName === OTHER) {
      const names = Object.entries(this.proposals?.['']?.scanners || {});
      return !names.length ? '' : `<p>Scanners of these scans, and the site their name suggests: ${names.map(([n, s]) => `<code>${esc(n)}</code>${s ? ` → ${esc(s)}` : ''}`).join(', ')}. `
        + `Add <code>tenable.scanner</code> to that site in ${file}: the portal reads the file again by itself.</p>`;
    }
    const p = this.proposals?.[siteName];
    if (!p) return '';
    const yaml = `tenable: {scanner: "${p.scanner}", networks: [${p.networks.map(n => `"${n}"`).join(', ')}]}`;
    return `<p>The private targets of ${plural(p.scans, 'scan')} of ${esc(siteName)} outside its management networks: `
      + `<span class="mono">${esc(p.networks.join(', '))}</span>. If they are management networks of ${esc(siteName)}, put them under the site ${esc(siteName)} in ${file} `
      + `(keep its other keys), e.g. <code>${esc(yaml)}</code>. The portal reads the file again by itself (no restart): the scans of those networks, `
      + 'and every new scan made in Tenable inside them, can then be launched here. Public addresses are never proposed.</p>';
  },
  // One scan (also drawn by the guide)
  row(s) {
    return `<tr data-scan="${s.id}"><td><a class="ns-name" href="#/scans/${s.id}">${esc(s.name)}</a><span class="pf-table__sub mono">${esc(s.scanner || '-')}</span>`
      + `<span class="pf-table__sub mono" title="${esc(s.targets)}">${esc(s.targets.length > 80 ? `${s.targets.slice(0, 79)}…` : s.targets || 'no target list')}</span></td>`
      + `<td>${scanLabel(s.status)}</td><td class="pf-table__detail">${this.scope(s)}</td><td class="ns-nowrap">${esc(shortTime(s.last_run))}</td>`
      + `<td>${esc(s.schedule)}</td><td class="pf-table__actions">${this.actions(s)}</td></tr>`;
  },
  render() {
    const q = $('#scQ').value.trim().toLowerCase();
    const items = this.items.filter(s => !q || `${s.name} ${s.targets} ${s.scanner} ${s.policy}`.toLowerCase().includes(q));
    $('#scShown').textContent = q ? `${items.length} of ${plural(this.items.length, 'scan')}` : plural(this.items.length, 'scan');
    const site = Site.info(Site.current);
    $('#scNotice').innerHTML = Site.current === OTHER ? alertBox('info', 'Scans of no site', 'Scans on a scanner that is not the scanner of a site in sites.yml (tenable.scanner): the portal never launches them.'
      + this.proposalHtml(OTHER))
      : !site.scanner ? alertBox('warning', `${esc(Site.title(Site.current))} has no scanner in sites.yml`, 'Add tenable.scanner (the name of its Nessus scanner in Tenable) to the site in sites.yml.'
        + this.proposalHtml(Site.current))
        : !site.networks.length ? alertBox('warning', `${esc(Site.current)} has no management networks in sites.yml`, 'The portal launches a scan only when every target is inside tenable.networks of its site.'
          + this.proposalHtml(Site.current))
          : this.proposals?.[Site.current] ? alertBox('info', `Scans of ${esc(Site.current)} outside its management networks`, this.proposalHtml(Site.current)) : '';
    $('#scList').innerHTML = items.map(s => this.row(s)).join('')
      || `<tr><td colspan="6"><div class="pf-empty-state">${icon('search')}<h2 class="pf-title">No scan</h2>`
        + `<span>${q ? 'No scan matches.' : `Tenable has no scan on the scanner of ${esc(Site.title(Site.current))}. Scans are made in Tenable.`}</span></div></td></tr>`;
  },
};

const ScanPage = {
  scan: null,
  timer: 0,
  init() {
    $('#snActions').addEventListener('click', e => {
      const b = e.target.closest('[data-act]');
      if (b && this.scan) ScanDialog.open(b.dataset.act, this.scan);
    });
  },
  stop() { clearTimeout(this.timer); },
  async open(id) {
    this.stop();
    this.scan = null;
    $('#snCrumb').textContent = `Scan ${id}`;
    $('#snTitle').textContent = '';
    $('#snStatus').innerHTML = '';
    $('#snActions').innerHTML = '';
    $('#snDetail').innerHTML = '';
    $('#snHosts').innerHTML = '';
    $('#snHistory').innerHTML = '';
    const data = await api(`/api/scans/${id}`);
    if (Router.page !== 'scan') return;
    this.scan = data.scan;
    if (this.scan.site && this.scan.site !== Site.current) Site.activate(this.scan.site);
    this.render();
    this.watch();
  },
  watch() {
    if (!SCAN_RUNNING.includes(this.scan.status)) return;
    this.timer = setTimeout(async () => {
      try {
        const st = await api(`/api/scans/${this.scan.id}/status`);
        if (Router.page !== 'scan') return;
        if (st.status !== this.scan.status) return run(null, () => this.open(this.scan.id));
      } catch (e) { /* the next look tries again */ }
      this.watch();
    }, 10000);
  },
  render() {
    const s = this.scan;
    $('#snCrumb').textContent = s.name;
    $('#snTitle').textContent = s.name;
    $('#snStatus').innerHTML = scanLabel(s.status);
    $('#snActions').innerHTML = Scans.actions(s);
    $('#snDetail').innerHTML = dl([
      ['Scanner', `<span class="mono">${esc(s.scanner || '-')}</span> · ${s.site ? `site <b>${esc(s.site)}</b>` : 'no site'}`],
      ['Targets', `<span class="mono">${esc(s.targets || 'no target list')}</span>`],
      ['Scope', Scans.scope(s)],
      ['Policy', esc(s.policy || '-')],
      ['Schedule', esc(s.schedule || '-')],
      ['Last run', s.started ? `${esc(fmtTime(s.started))}${s.ended ? ` – ${esc(fmtTime(s.ended))}` : ''}` : '-'],
    ]);
    $('#snNotice').innerHTML = SCAN_RUNNING.includes(s.status) ? alertBox('info', `The scan is ${esc((SCAN[s.status] || [s.status])[0].toLowerCase())}`,
      'Its hosts are scanned now; the findings reach the portal with the next sync after it ends.') : '';
    $('#snHosts').innerHTML = s.hosts.map(h => `<tr><td>${h.in_portal ? `<a class="mono" href="#/hosts/${encodeURIComponent(h.hostname)}">${esc(h.hostname)}</a>`
      : `<span class="mono">${esc(h.hostname)}</span>`}</td>${['critical', 'high', 'medium', 'low', 'info'].map(k => `<td>${h[k] && SEVERITY[k][1] ? label(String(h[k]), SEVERITY[k][1]) : count(h[k])}</td>`).join('')}</tr>`).join('')
      || `<tr><td colspan="6"><div class="pf-empty-state">${icon('server')}<h2 class="pf-title">No host</h2><span>The scan has not run yet, or found no host.</span></div></td></tr>`;
    $('#snHistory').innerHTML = s.history.map(h => `<tr><td class="ns-nowrap">${esc(fmtTime(h.started))}</td><td class="ns-nowrap">${esc(SCAN_RUNNING.includes(h.status) ? '-' : fmtTime(h.ended))}</td>`
      + `<td>${scanLabel(h.status)}</td><td>${h.scheduled ? 'Schedule' : 'By hand (Tenable or the portal)'}</td></tr>`).join('')
      || '<tr><td colspan="4"><span class="pf-text-secondary">No run yet</span></td></tr>';
  },
};

/* =========================================================================
   Launch, stop, Verify fix: the dialog with the typed confirmation (as the high-risk fixes of Runbook Automation)
   ========================================================================= */
const ScanDialog = {
  mode: 'launch',
  scan: null,
  host: null,
  init() {
    $('#sdForm').addEventListener('submit', e => { e.preventDefault(); this.submit(); });
    $('#sdConfirm').addEventListener('input', () => this.sync());
    $('#sdScan').addEventListener('change', () => this.renderVerify());
  },
  expected() { return this.mode === 'verify' ? this.host.ip : this.scan.name; },
  networksOf(site) { return (Site.info(site).networks || []).join(', ') || 'none'; },
  // What the dialog shows (also drawn by the guide of the page)
  content(mode, scan, host = null) {
    const site = scan?.site || host?.site || '';
    const risk = mode === 'stop'
      ? alertBox('info', 'Stop the scan now', 'The hosts not scanned yet keep their earlier results; what was found until now stays in Tenable.')
      : alertBox('warning', 'A scan can load or disturb the scanned devices', 'Nessus sends many probes to every target: it can load BMCs, switches '
        + 'and storage controllers, fill their logs or lock accounts, and old or fragile devices may stop answering. Run it in a time '
        + 'agreed with the owners of the devices.');
    const where = mode === 'verify'
      ? dl([['Host', `<b class="mono">${esc(host.ip)}</b> ${esc(host.hostname || '')}`], ['Site', `<b>${esc(site)}</b>`],
        ['Scanner', `<span class="mono">${esc(scan?.scanner || '-')}</span>`], ['Targets', `Only <span class="mono">${esc(host.ip)}</span> (the other targets of the scan are not scanned)`]])
      : dl([['Scan', `<b>${esc(scan.name)}</b>`], ['Scanner', `<span class="mono">${esc(scan.scanner || '-')}</span> · site <b>${esc(site || '-')}</b>`],
        ['Targets', `<pre class="pf-code-block">${esc(scan.targets || '-')}</pre>`]]);
    const scope = mode === 'stop' ? ''
      : mode === 'verify' ? `Only ${host.ip} is scanned, inside the management networks of ${site}: ${this.networksOf(site)}.`
        : `This scan only covers the management networks of ${site}: ${this.networksOf(site)}.`;
    return {title: {launch: 'Launch scan', stop: 'Stop scan', verify: `Verify fix on ${host?.ip || ''}`}[mode], risk, where, scope,
      expected: mode === 'verify' ? host.ip : scan.name, button: {launch: 'Launch', stop: 'Stop scan', verify: 'Verify fix'}[mode],
      danger: mode === 'stop'};
  },
  show(mode, scan, host = null) {
    this.mode = mode;
    this.scan = scan;
    this.host = host;
    const d = this.content(mode, scan, host);
    $('#sdTitle').textContent = d.title;
    $('#sdRisk').innerHTML = d.risk;
    $('#sdWhere').innerHTML = d.where;
    $('#sdScope').textContent = d.scope;
    $('#sdScope').hidden = !d.scope;
    $('#sdConfirmName').textContent = d.expected;
    $('#sdConfirm').value = '';
    $('#sdError').hidden = true;
    $('#sdRun').className = `pf-btn ${d.danger ? 'pf-m-danger' : 'pf-m-primary'}`;
    $('#sdRun').innerHTML = `${icon(mode === 'stop' ? 'minus-circle' : mode === 'verify' ? 'refresh' : 'play')}${esc(d.button)}`;
    this.sync();
    $('#scanDialog').showModal();
    $('#sdConfirm').focus();
  },
  open(mode, scan) {
    $('#sdScanGroup').hidden = true;
    this.show(mode, scan);
  },
  openVerify(host) {
    const scans = host.verify.scans;
    if (!scans.length) return;
    $('#sdScanGroup').hidden = false;
    $('#sdScan').innerHTML = scans.map(s => `<option value="${s.id}">${esc(s.name)}${SCAN_RUNNING.includes(s.status) ? ` (${esc(s.status)})` : ''}</option>`).join('');
    this.show('verify', this.verifyScan(host), host);
  },
  verifyScan(host) {
    const s = host.verify.scans.find(x => String(x.id) === $('#sdScan').value) || host.verify.scans[0];
    return {...s, site: host.site};
  },
  renderVerify() {
    this.scan = this.verifyScan(this.host);
    $('#sdWhere').innerHTML = this.content('verify', this.scan, this.host).where;
  },
  sync() { $('#sdRun').disabled = $('#sdConfirm').value.trim() !== this.expected(); },
  async submit() {
    if ($('#sdRun').disabled) return;
    const mode = this.mode, scan = this.scan;
    await run($('#sdRun'), async () => {
      try {
        const body = {confirm: $('#sdConfirm').value.trim(), ...(mode === 'verify' ? {ip: this.host.ip} : {})};
        await api(`/api/scans/${scan.id}/${mode}`, body);
        $('#scanDialog').close();
        toast(mode === 'stop' ? `${scan.name} is stopping.` : mode === 'verify'
          ? `${scan.name} launched for ${this.host.ip} only. Sync after it ends to see what was fixed.`
          : `${scan.name} launched.`, 'success');
        if (Router.page === 'scans') run(null, () => Scans.load(true));
        if (Router.page === 'scan') run(null, () => ScanPage.open(scan.id));
      } catch (e) {
        $('#sdError').textContent = e.message;
        $('#sdError').hidden = false;
      }
    });
  },
};

/* =========================================================================
   Start
   ========================================================================= */
document.addEventListener('DOMContentLoaded', async () => {
  UserMenu.init();
  Sync.init();
  Overview.init();
  Findings.init();
  Hosts.init();
  HostPage.init();
  Scans.init();
  ScanPage.init();
  ScanDialog.init();
  document.addEventListener('click', e => { const b = e.target.closest('dialog [data-close]'); if (b) b.closest('dialog').close(); });
  Router.init();
  if (!location.hash) history.replaceState(null, '', '#/overview');
  const status = await Session.refresh();
  if (!status) return toast('Cannot reach the portal server.');
  if (status.user) Router.go();
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

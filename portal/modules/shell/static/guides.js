'use strict';
/* Guides of Shell, one per page (data-page): Terminals and Session history. Each is drawn from the page as it is now with
   the page's own markup (Hosts.html, Workspace.tabsHtml / paneHtml / statusHtml, Snippets.html, History.rowsHtml): the
   real host tree of this user, the open sessions (or the first host of the tree when none is open), the snippets and the
   history. A guide never opens a session, sends a key or reads a recording; the terminal text in the miniature is drawn
   for the guide. The player is the portal's (static/guide.js, PortalGuide). */
const {M} = PortalGuide;

const SG = {
  // A stand-in for a session in the miniature (what Workspace.paneHtml / tabsHtml need).
  fake(target, id, state = 'open') {
    return {id, target, label: target.name, state, root: false, failed: false, reason: '', started: Date.now() - 754000,
            opened: false, size: '132x38', term: {cols: 132, rows: 38}};
  },
  // The screen of a terminal in the miniature: a prompt and a command typical for the host.
  screen(t) {
    const user = t.user || 'user';
    const host = t.kind === 'ontap' ? `${t.site}-cluster` : t.kind === 'apic' ? 'apic1' : t.name.replace(/\s+/g, '-').toLowerCase();
    const prompt = t.kind === 'ontap' ? `${host}::> ` : t.category === 'vyos' ? `${user}@${host}:~$ ` : `[${user}@${host} ~]$ `;
    const cmd = t.kind === 'ontap' ? 'cluster show' : t.kind === 'apic' ? 'show controller' : t.category === 'vyos' ? 'show interfaces'
      : t.kind === 'director' ? 'source ~/stackrc; openstack baremetal node list' : 'uptime';
    const out = t.kind === 'ontap' ? 'Node                  Health  Eligibility\n--------------------- ------- ------------\nnode-01               true    true\nnode-02               true    true'
      : t.category === 'vyos' ? 'Interface    IP Address        S/L  Description\n---------    ----------        ---  -----------\neth0         10.249.0.1/24      u/u  LAN\neth1         203.0.113.2/30    u/u  WAN'
      : ' 10:42:07 up 87 days,  3:12,  1 user,  load average: 0.41, 0.38, 0.35';
    return `<pre class="sh-guide-term" style="margin:0;height:100%;color:#e0e0e0;font:12px/1.35 var(--pf-font-mono);white-space:pre">`
      + `<span style="color:#8a8d90">Connecting to ${esc(user)}@${esc(t.address)}…</span>\n${esc(prompt)}${esc(cmd)}\n${esc(out)}\n${esc(prompt)}<span style="background:#73bcf7"> </span></pre>`;
  },
  // The sidebar and the workspace side by side, as on the page (the guide shows the whole page, not only <main>).
  frame(tree, tabs, panes, layout, status, drawer = '') {
    const side = M.clone($('.sh-hosts'));
    $('[data-g="hostTree"]', side).innerHTML = M.frag(tree);
    const ws = M.clone($('#workspace'));
    ws.style.height = '440px';
    $('[data-g="tabs"]', ws).innerHTML = M.frag(tabs);
    const box = $('[data-g="panes"]', ws);
    box.className = `sh-panes is-l${layout}`;
    box.innerHTML = M.frag(panes);
    $('[data-g="statusBar"]', ws).innerHTML = M.frag(status);
    $$('[data-layout]', ws).forEach(b => b.setAttribute('aria-pressed', String(b.dataset.layout === layout)));
    const d = $('[data-g="snippetDrawer"]', ws);
    d.hidden = true;
    $('[data-g="snippetList"]', d).innerHTML = M.frag(drawer);
    side.style.height = '440px';
    return `<div class="sh-page" style="display:grid;grid-template-columns:270px minmax(0,1fr);background:var(--pf-sidebar-bg)">`
      + `<div class="pf-sidebar" style="grid-row:1">${side.outerHTML}</div><div>${ws.outerHTML}</div></div>`;
  },
  paneWith(view, i, active) {
    const html = Workspace.paneHtml(view, i).replace('<div data-slot style="display:contents"></div>',
      `<div class="sh-term" data-g="term${i}">${SG.screen(view.target)}</div>`);
    return active ? html : html.replace(' is-active', '');
  },
};

const GUIDES = {
  terminals: {
    title: 'open, split, copy and paste',
    width: 1180,
    build() {
      const usable = Hosts.targets.filter(t => !t.problem);
      if (!usable.length) return null;
      const open = Terms.all().filter(v => v.state !== 'closed');
      const first = open[0]?.target || Hosts.get(Hosts.recent.find(id => Hosts.get(id) && !Hosts.get(id).problem)) || usable[0];
      const second = usable.find(t => t.id !== first.id && t.site === first.site) || usable.find(t => t.id !== first.id) || first;
      const word = first.name.split(/[\s-]+/).find(w => w.length > 2) || first.name;
      const a = SG.fake(first, 'ga'), b = SG.fake(second, 'gb');
      const saved = {query: Hosts.query, site: Hosts.site, selected: Hosts.selected};
      Object.assign(Hosts, {query: '', site: ''});
      const tree = Hosts.html();
      Hosts.query = word.toLowerCase();
      const found = Hosts.html();
      Hosts.selected = first.id;
      const picked = Hosts.html();
      Object.assign(Hosts, saved);
      const startPane = `<div class="sh-start" style="height:100%">${Start.html()}</div>`;
      const html = SG.frame(tree, '', startPane, '1', Workspace.statusHtml(null), Snippets.html(Snippets.items.slice(0, 4)));
      const tabs1 = Workspace.tabsHtml([a], 'ga', ['ga']);
      const tabs2 = Workspace.tabsHtml([a, b], 'gb', ['ga', 'gb']);
      const row = `@[data-g="hostTree"] [data-host="${CSS.escape(first.id)}"]`;
      const set = (key, html) => ['set', key, M.frag(html)];
      const sample = Snippets.items[0] || {name: 'Pacemaker status', command: 'sudo pcs status'};
      return {html, scenes: [
        {title: 'Find a host', text: 'Every host of the portal, per site and product: OpenStack management host and director, ONTAP, APIC, '
          + 'the hosts of Hosts &amp; SSH (VyOS, CDN, DNS, Linux…). Type a name, an address or a product; <kbd>/</kbd> jumps here.',
         do: [['type', 'hostQ', word], set('hostTree', found)]},
        {title: 'Connect', text: 'Double-click the host (or Enter). The portal server opens SSH with the account the administrators stored: '
          + 'you never type a key or a password. A tab opens, coloured by site.',
         do: [set('hostTree', picked), ['move', row], ['click', row], ['click', row],
              set('tabs', tabs1), set('panes', SG.paneWith(a, 0, true)), set('statusBar', Workspace.statusHtml(a)),
              ['tip', '@[data-g="tabs"] .sh-tab', `${first.site} · ${first.name}`]]},
        {title: 'Split the screen', text: 'Up to four panes, like Termius: pick a layout, then drag a tab onto a pane, or use '
          + '<b>Connect in a new pane</b> in the menu of a host (right-click).',
         do: [['untip'], ['click', '@[data-layout="2"]'], ['attr', '@[data-layout="2"]', 'aria-pressed', 'true'], ['attr', '@[data-layout="1"]', 'aria-pressed', 'false'],
              ['cls', 'panes', 'is-l1', false], ['cls', 'panes', 'is-l2'], set('tabs', tabs2),
              set('panes', SG.paneWith(a, 0, false) + SG.paneWith(b, 1, true)), set('statusBar', Workspace.statusHtml(b)),
              ['tip', '@[data-g="panes"] [data-pane="1"]', `${second.site} · ${second.name}`]]},
        {title: 'Copy and paste', text: `Selecting text copies it. A right-click (Windows, like MobaXterm) or <b>${MOD}V</b> pastes; nothing runs before Enter, several lines are shown `
          + 'first, so nothing runs on a production host by surprise. The status bar shows where the active pane is connected.',
         do: [['untip'], ['move', '@[data-g="statusBar"] [data-act="copy"]'], ['tip', '@[data-g="statusBar"] [data-act="copy"]', `Copy · ${MOD}C`],
              ['move', '@[data-g="statusBar"] [data-act="paste"]'], ['tip', '@[data-g="statusBar"] [data-act="paste"]', `Paste · ${MOD}V`]]},
        {title: 'Snippets', text: 'Commands you use often, yours or shared by an administrator: <b>Paste</b> puts one in the active terminal, '
          + '<b>Run</b> also presses Enter.',
         do: [['untip'], ['click', 'snippetsBtn'], ['show', 'snippetDrawer'], ['tip', '@[data-g="snippetList"]', sample.name]]},
        {title: 'End the session', text: 'The × of a tab or <b>End session</b> closes the connection. A session left open ends by itself '
          + `after ${Session.status.limits?.idle_minutes || 30} minutes without input or output; every session is in Session history with its recording.`,
         do: [['untip'], ['hide', 'snippetDrawer'], ['move', '@[data-g="statusBar"] [data-act="end"]'], ['tip', '@[data-g="statusBar"] [data-act="end"]', 'End session']]},
      ]};
    },
  },
  access: {
    title: 'give an operator its hosts',
    width: 1100,
    build() {
      if (!Access.data) return null;
      const copy = M.clone($('#page-access'));
      copy.hidden = false;
      const op = Access.data.accounts.find(a => a.role !== 'admin');
      const firstCat = $('[data-g="accTree"] .sh-acc-row.is-cat input', copy);
      const scenes = [{title: 'Accounts with Shell', text: 'Every account that has the Shell module (Users page). An operator opens '
        + 'only the hosts given here, nothing by default; administrators open every host.', do: [['move', 'accUsers'], ['tip', 'accUsers', op ? esc(op.username) : 'Accounts']]}];
      if (firstCat) {
        scenes.push({title: 'Give hosts', text: 'Tick a whole site, a product of a site (also the hosts added to it later) or single '
          + 'hosts. Hosts covered by a wider tick are shown greyed.',
          do: [['untip'], ['check', '@[data-g="accTree"] .sh-acc-row.is-cat input'], ['tip', '@[data-g="accTree"] .sh-acc-row.is-cat', 'All of this product']]});
      }
      scenes.push({title: 'Save', text: 'Save applies to the next session the operator opens; sessions already open stay open. The '
        + 'activity log records the change.', do: [['untip'], ['attr', 'accSave', 'disabled', null], ['click', 'accSave']]});
      return {html: copy.outerHTML, scenes};
    },
  },
  history: {
    title: 'find a session and its recording',
    build() {
      const page = $('#page-history');
      const head = M.clone($('section.pf-m-light', page));
      const card = M.clone($('section:not(.pf-m-light) .pf-card', page));
      M.keep(card, '[data-g="historyList"] tr', 5);
      const html = head.outerHTML + `<section class="pf-page__section">${card.outerHTML}</section>`;
      const first = History.items.find(r => r.recording);
      const scenes = [{title: 'Every session', text: 'Who opened a shell on which host, from where, how long, and how it ended. '
        + (Session.isAdmin() ? 'Administrators see every user and can end a session that is still open.' : 'You see your own sessions.'),
        do: [['move', 'historyList'], ['tip', 'historyList', 'Newest first']]},
      {title: 'Filter', text: 'Per site' + (Session.isAdmin() ? ', and per user' : '') + '.',
        do: [['untip'], ['move', 'historySite']]}];
      if (first) {
        scenes.push({title: 'The recording', text: `The output of the session as it was shown (kept ${Session.status.keep_days || 30} days): `
          + '▶ shows it in a terminal, the download is plain text for a ticket or an RCA.',
          do: [['move', `@[data-g="historyList"] [data-act="play"][data-id="${first.id}"]`], ['tip', `@[data-g="historyList"] [data-act="play"][data-id="${first.id}"]`, 'Show the recording'],
               ['move', `@[data-g="historyList"] [data-act="text"][data-id="${first.id}"]`]]});
      }
      return {html, scenes};
    },
  },
};

PortalGuide.mount(GUIDES, {page: name => document.querySelector(`[data-page="${name}"]`)});

'use strict';
/* Guides of ACI, one per tab: each built from the tab as it is now, with the page's own markup functions (Bindings.rowHtml,
   StaticPort.planHtml, Fabric.rowHtml, Report.rowHtml, IpUsage.rowHtml / dialogHtml, Audit.rowHtml / bodyHtml,
   Provision.planHtml) and dialogs. When a list is not read yet, the guide reads it with the same GET as the page (Show,
   Read from APIC, a row) and draws it in the copy; the rows typed on Static Port and every form stay as they are. Nothing
   is sent to APIC. The player is the portal's (static/guide.js, PortalGuide). */
const {M} = PortalGuide;

const GA = {
  panel(name) {
    const copy = M.clone($(`#tab-${name}`));
    copy.hidden = false;
    $$('.site-blocked', copy).forEach(x => { x.innerHTML = ''; });
    return copy;
  },
  toast(kind, text, key) {
    return M.key(M.el(`<div class="pg-toast" hidden><div class="toast toast-${kind}">${icon({error: 'alert', success: 'check', info: 'info'}[kind])}`
      + `<div class="toast-text">${esc(text)}</div></div></div>`), key);
  },
  // the radios of a copy and the fields that follow them (data-when="pvAppMode=new"), as Provision.update does
  when(s) {
    $$('[data-when]', s).forEach(el => {
      const [name, value] = el.dataset.when.split('=');
      const on = $$('input[type=radio]', s).find(r => r.name.replace(/^g\d+-/, '') === name && r.checked);
      el.hidden = !on || on.value !== value;
    });
  },
  options(select, items, placeholder) {
    select.innerHTML = (placeholder ? `<option value="">${esc(placeholder)}</option>` : '')
      + items.map(x => `<option value="${esc(x)}">${esc(x)}</option>`).join('');
  },
  // an EPG of this site: the one chosen on the page, else the first one found (the same reads as choosing it)
  async epg(target) {
    const v = target.values();
    if (v.tenant && v.app && v.epg) return {...v, apps: [v.app], epgs: [v.epg]};
    const tenants = [...$('#spTenant').options].map(o => o.value).filter(Boolean);
    for (const tenant of [v.tenant, ...tenants].filter(Boolean).slice(0, 6)) {
      const apps = (await api('/api/discover?' + qs({kind: 'apps', tenant}))).items;
      for (const app of apps.slice(0, 4)) {
        const epgs = (await api('/api/discover?' + qs({kind: 'epgs', tenant, app}))).items;
        if (epgs.length) return {tenant, app, epg: epgs[0], apps, epgs};
      }
    }
    return null;
  },
  async fabric() { return Fabric.data || api('/api/fabric'); },
  emptyRow(cols, ic, title, text) {
    return `<tr class="empty-row"><td colspan="${cols}"><div class="empty">${icon(ic)}<div><b>${esc(title)}</b><p>${esc(text)}</p></div></div></td></tr>`;
  },
};

const GUIDES = {
  // ---------------------------------------------------------------- Static Port
  static: {
    title: 'bind ports to an EPG (static port)',
    width: 1000,
    async build() {
      const site = Site.current;
      if (!site || !Site.info(site).configured) return null;
      const epg = await GA.epg(StaticPort.target);
      if (!epg) return null;
      const fab = await GA.fabric();
      // two ports next to each other on one leaf with an interface policy and nothing bound yet (else free ones)
      const ports = (fab.interfaces || []).filter(r => r.status === 'access' && !r.bindings.length);
      const pick = list => list.find((r, i) => list[i + 1] && list[i + 1].node === r.node);
      const first = pick(ports) || pick((fab.interfaces || []).filter(r => r.status === 'free')) || null;
      if (!first) return null;
      const second = (fab.interfaces || []).find(r => r.node === first.node && r.interface !== first.interface && r.status === first.status
        && port(r.interface) > port(first.interface));
      const suggest = await api('/api/vlan-suggest?' + qs({tenant: epg.tenant, app: epg.app, epg: epg.epg, count: 10}));
      const vlan = String(suggest.free[0] || 300);
      const copy = GA.panel('static');
      // the form as it starts: no EPG chosen, no row yet
      $('[data-g="spTenant"]', copy).selectedIndex = 0;
      GA.options($('[data-g="spApp"]', copy), epg.apps, 'Select an app profile');
      GA.options($('[data-g="spEpg"]', copy), epg.epgs, 'Select an EPG');
      $('[data-g="spExisting"]', copy).hidden = true;
      $$('.tool-panel', copy).forEach(p => { p.hidden = true; });
      $('[data-g="physicalTable"] tbody', copy).innerHTML = GA.emptyRow(8, 'plug', 'No physical / port-channel bindings yet',
        'Add them with Search APIC, Interface range, Bulk text, or Blank row.');
      $('[data-g="physicalTable"]', copy).hidden = false;
      $('[data-g="pathsTable"]', copy).hidden = true;
      $('[data-g="physicalCount"]', copy).textContent = '0';
      $('[data-g="spContext"]', copy).innerHTML = '<span class="muted">Select a tenant, app profile, and EPG</span>';
      $('[data-g="spCount"]', copy).textContent = '0 bindings';
      $('[data-g="spReviewBtn"]', copy).disabled = true;
      $('[data-g="spDefMode"]', copy).value = 'regular';
      const pop = M.el(`<div class="popover" data-g="gsuggest" hidden><div class="popover-head"><b>Suggested VLANs</b>`
        + `<button type="button" class="btn-icon" aria-label="Close">${icon('x')}</button></div>${VlanSuggest.html(suggest, epg.epg)}</div>`);
      $('[data-suggest="rgVlan"]', copy).parentElement.append(pop);
      const rows = [first, second].filter(Boolean).map(r => Bindings.newRow('physical', {pod: String(r.pod), node: String(r.node), interface: r.interface, vlan}));
      rows.forEach(r => { r.mode = 'regular'; r.immediacy = 'immediate'; });
      const rowsHtml = M.rows(rows.map((r, i) => Bindings.rowHtml('physical', r, i)).join(''));
      const tdn = r => `topology/pod-${r.pod}/paths-${r.node}/pathep-[${r.interface}]`;
      const plan = {site, epg_dn: `uni/tn-${epg.tenant}/ap-${epg.app}/epg-${epg.epg}`, summary: {new: rows.length, change: 0, same: 0}, conflicts: [], blocked: false,
        items: rows.map(r => ({status: 'new', tdn: tdn(r), encap: `vlan-${vlan}`, mode: r.mode, immediacy: r.immediacy}))};
      const review = M.dialog('#reviewDialog');
      $('[data-g="reviewTitle"]', review).textContent = 'Review static port';
      $('[data-g="reviewBody"]', review).innerHTML = M.frag(StaticPort.planHtml(plan));
      $('[data-g="reviewConfirmLabel"]', review).textContent = `Apply ${plural(rows.length, 'change')} to ${site}`;
      $('[data-g="reviewConfirm"]', review).className = 'btn btn-primary';
      $('[data-g="reviewConfirm"]', review).hidden = false;
      $('[data-g="reviewConfirm"]', review).disabled = false;
      const products = $$('[data-g="productPicker"] input', copy).length;
      const scenes = [
        {title: 'Choose the EPG', text: `Tenant, application profile and EPG of site <b>${esc(site)}</b> (the site of the masthead). <b>Existing bindings</b> then shows what the EPG already has.`,
          do: [['pick', 'spTenant', epg.tenant], ['pick', 'spApp', epg.app], ['pick', 'spEpg', epg.epg],
            ['set', 'spContext', crumbs([epg.tenant, epg.app, epg.epg])], ['attr', 'spExistingBtn', 'disabled', null], ['tip', 'spExistingBtn', 'The paths this EPG already has']]},
      ];
      if (products) {
        scenes.push({title: 'Or start from a product', text: `A product fills in the paths of its <b>${esc(site)}</b> template, with one VLAN for all of them; <b>Templates</b> keeps those paths.`,
          do: [['untip'], ['move', '@[data-g="productPicker"] label'], ['tip', '@[data-g="productPicker"] label', 'Its paths come into the table below']]});
      }
      scenes.push(
        {title: 'Add the ports', text: `<b>Interface range</b> adds ports one after the other on a leaf; <b>Search APIC</b> finds a port, port-channel or vPC; <b>Bulk text</b> takes a list. `
            + 'The page <b>Interfaces</b> shows which ports are free.',
          do: [['untip'], ['click', '@[data-tool="range"]'], ['show', 'tool-range'], ['type', 'rgNode', String(first.node)], ['type', 'rgFrom', first.interface],
            ...(second ? [['type', 'rgTo', second.interface]] : [])]},
        {title: 'A free VLAN', text: 'Suggest free VLAN reads the VLAN pools of the EPG\'s domains on APIC: the VLANs no other EPG or L3Out uses. A VLAN in use elsewhere turns the row red.',
          do: [['click', '@[data-suggest="rgVlan"]'], ['show', 'gsuggest'],
            ...(suggest.free.length ? [['click', `@[data-g="gsuggest"] [data-vlan="${vlan}"]`]] : [['wait', 1200]]), ['hide', 'gsuggest'],
            ['type', 'rgVlan', vlan], ['click', 'rgAdd'], ['hide', 'tool-range'], ['set', '@[data-g="physicalTable"] tbody', rowsHtml],
            ['set', 'physicalCount', String(rows.length)], ['set', 'spCount', plural(rows.length, 'binding')], ['attr', 'spReviewBtn', 'disabled', null],
            ['tip', '@[data-g="physicalTable"] tbody tr', 'Pod, node, interface, VLAN, mode (trunk) and immediacy: every cell can still be changed']]},
        {title: 'Review & apply', text: `The review asks APIC what each path has now: <b>New</b>, <b>Changed</b> (with the values before) or <b>Unchanged</b>. Nothing is sent before <b>Apply</b>.`,
          do: [['untip'], ['click', 'spReviewBtn'], ['show', 'reviewDialog'], ['move', '@[data-g="reviewBody"] table'], ['click', 'reviewConfirm'], ['hide', 'reviewDialog'], ['show', 'gtoast']]},
        {title: 'Recorded, and undoable', text: 'Every change is recorded in <b>History</b> before it is sent, with the user and the APIC answer; a static-port change can be undone from there.',
          do: [['tip', '@[data-g="gtoast"] .toast', 'History → the change → Undo this change…'], ['wait', 1500], ['untip'], ['hide', 'gtoast']]},
      );
      return {html: copy.outerHTML, overlay: [review, GA.toast('success', `Static port bindings applied to ${site}.`, 'gtoast')], scenes};

      function port(name) { const m = /^eth(\d+)\/(\d+)/.exec(name); return m ? Number(m[1]) * 1000 + Number(m[2]) : 0; }
    },
  },

  // ---------------------------------------------------------------- Interfaces (fabric)
  fabric: {
    title: 'find a port for a static port or a vPC',
    width: 1000,
    async build() {
      const site = Site.current;
      if (!site || !Site.info(site).configured) return null;
      const d = await GA.fabric();
      const rows = d.interfaces || [];
      if (!rows.length) return null;
      const copy = GA.panel('fabric');
      const tbody = $('[data-g="fbTable"] tbody', copy);
      // the rows of a leaf with a mix of uses, as Read from APIC shows them (all leaves, the first ones of one)
      const leaf = (d.nodes.find(n => ['access', 'free'].every(s => rows.some(r => r.node === n.id && r.status === s))) || d.nodes[0]).id;
      const of = list => M.rows(list.slice(0, 7).map(r => Fabric.rowHtml(r)).join(''));
      const first = rows.filter(r => r.node === leaf);
      const free = rows.find(r => r.status === 'free' && r.node === leaf) || rows.find(r => r.status === 'free');
      const same = free ? rows.filter(r => r.interface === free.interface) : [];
      const vpc = rows.find(r => r.status === 'vpc' && r.use);
      const pair = (d.vpc_pairs || []).find(p => p.free_both.length);
      const both = pair ? rows.filter(r => r.interface === pair.free_both[0] && pair.nodes.includes(r.node)) : [];
      $('[data-g="fbKpis"]', copy).innerHTML = M.frag(Fabric.kpisHtml(null, ''));
      tbody.innerHTML = GA.emptyRow(9, 'network', 'Not read yet', `Read from APIC reads every leaf port of ${site}.`);
      $('[data-g="fbShown"]', copy).textContent = '';
      $('[data-g="fbSearch"]', copy).value = '';
      $('[data-g="fbPairsCard"]', copy).hidden = true;
      $('[data-g="fbPairs"]', copy).innerHTML = M.frag(Fabric.pairsHtml(d.vpc_pairs || []));
      $('[data-g="fbAddSel"]', copy).disabled = true;
      const key = r => `@[data-g="fbTable"] [data-port="${r.node} ${r.interface}"]`;
      const addBtn = r => `@[data-g="fbTable"] [data-add="${r.node} ${r.interface}"]`;
      const scenes = [
        {title: 'Read every port', text: `<b>Read from APIC</b> reads every port of every leaf of <b>${esc(site)}</b>: state and speed, what uses it, what is connected (LLDP/CDP) and its static paths. Only reads.`,
          do: [['click', 'fbLoad'], ['set', 'fbKpis', M.frag(Fabric.kpisHtml(d, ''))], ['set', '@[data-g="fbTable"] tbody', of(first)],
            ['set', 'fbShown', `Showing ${rows.length} of ${plural(rows.length, 'port')}`], ['show', 'fbPairsCard'],
            ['tip', '@[data-g="fbKpis"] .kpi:nth-child(2)', 'Free: no interface policy yet; Access, Port-channel, vPC: in use; Uplink: fabric links']]},
      ];
      if (free) {
        scenes.push({title: `Where is ${free.interface}?`, text: 'Type an interface, a server name, a policy group, an EPG or a VLAN: the port of every leaf that matches, and what it is.',
          do: [['untip'], ['type', 'fbSearch', free.interface], ['set', '@[data-g="fbTable"] tbody', of(same)],
            ['set', 'fbShown', `Showing ${same.length} of ${plural(rows.length, 'port')}`],
            ['tip', `@[data-g="fbTable"] tr:has([data-port="${free.node} ${free.interface}"]) .badge-change`, esc(free.note)]]});
        scenes.push({title: 'To Static Port', text: 'The <b>Static port</b> button puts the right path in the Static Port table: the port itself, its port-channel, or its vPC (once for both leaves).',
          do: [['untip'], ['click', addBtn(free)], ['show', 'gtoast1'], ['wait', 1800], ['hide', 'gtoast1']]});
      }
      if (vpc) {
        scenes.push({title: 'A port in a vPC', text: `A member of a vPC is bound through the vPC: <span class="mono">${esc(vpc.use.tdn)}</span>.`,
          do: [['untip'], ['set', 'fbSearch', ''], ['type', 'fbSearch', vpc.channel], ['set', '@[data-g="fbTable"] tbody', of(rows.filter(r => r.channel === vpc.channel))],
            ['set', 'fbShown', `Showing ${rows.filter(r => r.channel === vpc.channel).length} of ${plural(rows.length, 'port')}`],
            ['check', key(vpc)], ['attr', 'fbAddSel', 'disabled', null], ['set', 'fbSelInfo', '1 port ticked.'],
            ['tip', 'fbAddSel', 'Ticked ports go to Static Port together']]});
      }
      if (pair && both.length) {
        scenes.push({title: 'Ports for a new vPC', text: '<b>vPC pairs</b>: for each pair of leaves, its vPCs and the ports free on both leaves. <b>Create vPC</b> on a pair (or on free ports ticked on both of its leaves) opens Create vPC with them.',
          do: [['untip'], ['move', 'fbPairsCard'], ['click', `@[data-g="fbPairs"] [data-find="${pair.free_both[0]}"]`], ['set', 'fbSearch', pair.free_both[0]],
            ['set', '@[data-g="fbTable"] tbody', of(both)], ['set', 'fbShown', `Showing ${both.length} of ${plural(rows.length, 'port')}`], ['tip', '@[data-g="fbTable"] tbody tr', `${esc(pair.free_both[0])} is free on leaves ${pair.nodes.join(' and ')}`],
            ['untip'], ['move', `@[data-g="fbPairs"] [data-vpc="${pair.nodes.join('-')}"]`], ['tip', `@[data-g="fbPairs"] [data-vpc="${pair.nodes.join('-')}"]`, 'Opens Create vPC with this pair']]});
      }
      scenes.push({title: 'Export', text: '<b>Export CSV</b> saves the ports shown, with the path to use for a static port.',
        do: [['untip'], ['move', 'fbExport'], ['tip', 'fbExport', `interfaces-${esc(site)}.csv`]]});
      const toast = GA.toast('success', 'Added 1 path to Static Port: choose the EPG and enter the VLAN.'
        + (free ? ' 1 port has no interface policy yet: APIC raises a fault on the binding until one is set.' : ''), 'gtoast1');
      return {html: copy.outerHTML, overlay: [toast], scenes};
    },
  },

  // ---------------------------------------------------------------- Report
  report: {
    title: 'see every static binding',
    width: 1100,
    async build() {
      const site = Site.current;
      if (!site || !Site.info(site).configured) return null;
      const rows = Report.loaded ? Report.rows : (await api('/api/report?' + qs({tenant: '', app: '', epg: ''}))).items;
      const copy = GA.panel('report');
      const tbody = $('[data-g="rpTable"] tbody', copy);
      ['rpTenant', 'rpApp', 'rpEpg'].forEach(k => { $(`[data-g="${k}"]`, copy).selectedIndex = 0; });
      $('[data-g="rpSearch"]', copy).value = '';
      $('[data-g="rpKpis"]', copy).innerHTML = M.frag(Report.kpisHtml([], ''));
      tbody.innerHTML = GA.emptyRow(12, 'table', 'No data yet', 'Choose filters (or leave them empty for everything), then click Show.');
      $('[data-g="rpShown"]', copy).textContent = '';
      const draw = list => M.rows(list.slice(0, 6).map(r => Report.rowHtml(r)).join('')) || GA.emptyRow(12, 'search', 'No results found', 'Change the search terms or select another type or source.');
      const vpc = rows.filter(r => r['Binding Type'] === 'vPC');
      const word = rows[0]?.VLAN ? String(rows[0].VLAN) : '';
      const scenes = [
        {title: 'Show', text: `Leave the filters empty for every binding of <b>${esc(site)}</b>, or choose a tenant, application profile or EPG.`,
          do: [['move', 'rpTenant'], ['tip', 'rpTenant', 'Empty = all tenants'], ['wait', 900], ['untip'], ['click', 'rpShowBtn'],
            ['set', 'rpKpis', M.frag(Report.kpisHtml(rows, ''))], ['set', '@[data-g="rpTable"] tbody', draw(rows)],
            ['set', 'rpShown', `Showing ${rows.length} of ${plural(rows.length, 'binding')}`]]},
      ];
      if (vpc.length) {
        scenes.push({title: 'Only one type', text: 'The cards count the bindings per type and keep one type: physical, port-channel or vPC.',
          do: [['click', '@[data-g="rpKpis"] [data-type="vPC"]'], ['set', 'rpKpis', M.frag(Report.kpisHtml(rows, 'vPC'))], ['set', '@[data-g="rpTable"] tbody', draw(vpc)],
            ['set', 'rpShown', `Showing ${vpc.length} of ${plural(rows.length, 'binding')}`]]});
      }
      if (word) {
        const hits = rows.filter(r => Report.searchText(r).includes(word.toLowerCase()));
        scenes.push({title: 'Search', text: 'Any word of a row: tenant, EPG, VLAN, node, interface, path.',
          do: [['click', '@[data-g="rpKpis"] [data-type=""]'], ['set', 'rpKpis', M.frag(Report.kpisHtml(rows, ''))], ['type', 'rpSearch', word],
            ['set', '@[data-g="rpTable"] tbody', draw(hits)], ['set', 'rpShown', `Showing ${hits.length} of ${plural(rows.length, 'binding')}`]]});
      }
      scenes.push({title: 'Where it comes from', text: '<b>Source</b>: set from this portal (with its change in History), outside the portal (on APIC), or changed outside after the portal set it.',
        do: [['move', '@[data-g="rpTable"] thead [data-sort="Source"]'], ['tip', '@[data-g="rpTable"] thead [data-sort="Source"]', 'Portal / Outside portal / Changed outside portal']]});
      scenes.push({title: 'Export', text: '<b>Export Excel</b> and <b>Export CSV</b> save the bindings of the filters.',
        do: [['untip'], ['move', '@[data-export="xlsx"]'], ['tip', '@[data-export="xlsx"]', 'The same rows, as a file']]});
      return {html: copy.outerHTML, scenes};
    },
  },

  // ---------------------------------------------------------------- IP usage
  ips: {
    title: 'find free IP addresses',
    width: 1000,
    async build() {
      const site = Site.current;
      if (!site || !Site.info(site).configured) return null;
      const data = IpUsage.loaded ? {items: IpUsage.rows, recent_days: IpUsage.recentDays} : await api('/api/ip-usage?' + qs({tenant: '', app: '', epg: ''}));
      const rows = data.items.map((r, i) => ({r, i})).filter(({r}) => r.scope === 'public' && r.learned);
      const copy = GA.panel('ips');
      ['ipTenant', 'ipApp', 'ipEpg'].forEach(k => { $(`[data-g="${k}"]`, copy).selectedIndex = 0; });
      $('[data-g="ipKpis"]', copy).innerHTML = M.frag(IpUsage.kpisHtml([]));
      $('[data-g="ipTable"] tbody', copy).innerHTML = GA.emptyRow(6, 'globe', 'No data yet', 'Choose filters (or leave them empty for everything), then click Show.');
      $('[data-g="ipShown"]', copy).textContent = '';
      const withFree = rows.find(({r}) => r.suggest.length) || rows[0];
      const scenes = [
        {title: 'Show', text: `The IPs learned on the EPGs of <b>${esc(site)}</b> (Client Endpoints) and the free addresses of their subnets. Public subnets with learned IPs first.`,
          do: [['click', 'ipShowBtn'], ['set', 'ipKpis', M.frag(IpUsage.kpisHtml(rows.map(x => x.r)))],
            ['set', '@[data-g="ipTable"] tbody', M.rows(rows.slice(0, 6).map(({r, i}) => IpUsage.rowHtml(r, i)).join(''))],
            ['set', 'ipShown', `Showing ${rows.length} of ${plural(data.items.length, 'row')}`]]},
      ];
      if (withFree) {
        const r = withFree.r;
        const dlg = M.dialog('#ipDialog');
        $('[data-g="ipDialogTitle"]', dlg).textContent = `${r.epg} · ${r.subnet || 'no subnet'}`;
        $('[data-g="ipDialogBody"]', dlg).innerHTML = M.frag(IpUsage.dialogHtml(r));
        if (r.suggest.length) {
          scenes.push({title: 'A free IP', text: 'Suggested free IPs: not a gateway, not learned on any endpoint of the fabric, not seen in the last days. A click copies one.',
            do: [['move', `@[data-g="ipTable"] tr[data-id="${withFree.i}"] [data-copy]`], ['click', `@[data-g="ipTable"] tr[data-id="${withFree.i}"] [data-copy]`],
              ['show', 'gtoast'], ['wait', 1300], ['hide', 'gtoast']]});
        }
        scenes.push({title: 'Every address of a subnet', text: 'A row opens its learned IPs (with MAC and interface), the addresses seen recently, and every free address.',
          do: [['click', `@[data-g="ipTable"] tr[data-id="${withFree.i}"] td`], ['show', 'ipDialog'], ['move', 'ipDialogBody'], ['wait', 1600], ['hide', 'ipDialog']]});
        scenes.push({title: 'Export', text: '<b>Export CSV</b> saves the rows of the filters.', do: [['move', 'ipExportBtn'], ['tip', 'ipExportBtn', 'ip-usage.csv']]});
        return {html: copy.outerHTML, overlay: [dlg, GA.toast('success', `${r.suggest[0] || ''} copied to the clipboard.`, 'gtoast')], scenes};
      }
      return {html: copy.outerHTML, scenes};
    },
  },

  // ---------------------------------------------------------------- History
  audit: {
    title: 'see a change and undo it',
    width: 1100,
    async build() {
      const items = Audit.stale ? (await api('/api/audit?' + qs({limit: 100, offset: 0}))).items : Audit.items;
      const copy = GA.panel('audit');
      const tbody = $('[data-g="auTable"] tbody', copy);
      tbody.innerHTML = M.rows(items.slice(0, 6).map(x => Audit.rowHtml(x)).join(''))
        || GA.emptyRow(8, 'clock', 'No changes yet', 'Every change applied from this Web UI is recorded here.');
      const scenes = [
        {title: 'Every change, before it is sent', text: 'Each change made from this Web UI, by every user on every site: who, where, what, and the result APIC gave.',
          do: [['move', 'auTable'], ['tip', '@[data-g="auTable"] thead', 'Time · status · user · site · action · product · target · summary']]},
        {title: 'Filter', text: 'User, site, action (Static Port, Provisioning, Product template), status and dates; the search box takes any word.',
          do: [['untip'], ['pick', 'auAction', 'Static Port']]},
      ];
      const x = items.find(i => i.action === 'static-port' && i.status === 'success' && !i.undone_by && !i.undo_of) || items[0];
      if (!x) return {html: copy.outerHTML, scenes};
      const full = (await api(`/api/audit/${x.id}`)).item;
      const dlg = M.dialog('#auditDialog');
      $('[data-g="auditTitle"]', dlg).textContent = `Change #${full.id}`;
      $('[data-g="auditBody"]', dlg).innerHTML = M.frag(Audit.bodyHtml(full));
      scenes.push({title: 'Open a change', text: 'A row shows the change: who and from where, the APIC account, and every path that was sent with its values before.',
        do: [['click', `@[data-g="auTable"] tr[data-id="${x.id}"] td`], ['show', 'auditDialog'], ['move', 'auditBody']]});
      if ($('[data-act="undo"]', dlg)) {
        scenes.push({title: 'Undo it', text: 'Undo deletes the paths the change added and puts back the values it changed; paths changed since are left alone. You review it before anything is sent.',
          do: [['move', '@[data-g="auditBody"] [data-act="undo"]'], ['tip', '@[data-g="auditBody"] [data-act="undo"]', 'Opens the review of the undo'], ['wait', 1500], ['untip'], ['hide', 'auditDialog']]});
      } else {
        scenes.push({title: 'Undo', text: 'A static-port change can be undone by an administrator or by the user who made it, from its details here.',
          do: [['move', 'auditBody'], ['wait', 1200], ['hide', 'auditDialog']]});
      }
      return {html: copy.outerHTML, overlay: [dlg], scenes};
    },
  },

  // ---------------------------------------------------------------- Provisioning
  provision: {
    title: 'create an EPG (tenant, VRF, bridge domain)',
    width: 1000,
    async build() {
      const site = Site.current;
      if (!site || !Site.info(site).configured) return null;
      const copy = GA.panel('provision');
      const tenants = [...$('#pvTenant').options].map(o => o.value).filter(Boolean);
      const tenant = $('#pvTenant').value || tenants[0];
      if (!tenant) return null;
      const objects = (await api('/api/discover?' + qs({kind: 'tenant_objects', tenant}))).items;
      const vrf = objects.vrfs[0] || '', app = objects.apps[0] || '';
      $('[data-g="pvTenant"]', copy).selectedIndex = 0;
      GA.options($('[data-g="pvVrf"]', copy), objects.vrfs, 'Select a VRF');
      GA.options($('[data-g="pvApp"]', copy), objects.apps, 'Select an app profile');
      $$('input[type=radio]', copy).forEach(r => { r.checked = r.defaultChecked; });
      $$('input[type=checkbox]', copy).forEach(c => { c.checked = false; });
      ['pvBdNew', 'pvEpg', 'pvTenantNew', 'pvVrfNew', 'pvAppNew'].forEach(k => { const x = $(`[data-g="${k}"]`, copy); if (x) x.value = ''; });
      $('[data-g="pvReviewBtn"]', copy).disabled = true;
      const html = copy.outerHTML;
      const bd = 'acme-flex-186-bd', epg = 'acme-flex-186-epg', subnet = '10.241.0.1/24';
      const domain = $('#pvDomains input[type=checkbox]');
      const domainDn = domain?.value || '';
      const steps = [{object: 'Tenant', name: tenant, kind: 'use', action: 'use existing'},
        ...(vrf ? [{object: 'VRF', name: vrf, kind: 'use', action: 'use existing'}] : []),
        {object: 'Bridge domain', name: bd, kind: 'new', action: 'create'},
        ...(vrf ? [{object: 'BD → VRF', name: `${bd} → ${vrf}`, kind: 'link', action: 'relation'}] : []),
        {object: 'Subnet', name: `${subnet} (public)`, kind: 'new', action: 'create / update'},
        ...(app ? [{object: 'Application profile', name: app, kind: 'use', action: 'use existing'}] : []),
        {object: 'EPG', name: epg, kind: 'new', action: 'create'},
        {object: 'EPG → BD', name: `${epg} → ${bd}`, kind: 'link', action: 'relation'},
        ...(domainDn ? [{object: 'EPG → Domain', name: domainDn, kind: 'link', action: 'deployment immediate, resolution immediate'}] : [])];
      const payload = {fvTenant: {attributes: {dn: `uni/tn-${tenant}`}, children: [
        {fvBD: {attributes: {name: bd, arpFlood: 'no', unkMacUcastAct: 'proxy'}, children: [...(vrf ? [{fvRsCtx: {attributes: {tnFvCtxName: vrf}}}] : []),
          {fvSubnet: {attributes: {ip: subnet, scope: 'public'}}}]}},
        {fvAp: {attributes: {name: app}, children: [{fvAEPg: {attributes: {name: epg}, children: [{fvRsBd: {attributes: {tnFvBDName: bd}}},
          ...(domainDn ? [{fvRsDomAtt: {attributes: {tDn: domainDn, instrImedcy: 'immediate', resImedcy: 'immediate'}}}] : [])]}}]}}]}};
      const review = M.dialog('#reviewDialog');
      $('[data-g="reviewTitle"]', review).textContent = 'Review provisioning';
      $('[data-g="reviewBody"]', review).innerHTML = M.frag(Provision.planHtml({site, tenant_dn: `uni/tn-${tenant}`, steps, warnings: [], payload}));
      $('[data-g="reviewConfirmLabel"]', review).textContent = `Apply to ${site}`;
      $('[data-g="reviewConfirm"]', review).className = 'btn btn-primary';
      $('[data-g="reviewConfirm"]', review).disabled = false;
      $('[data-g="reviewConfirm"]', review).hidden = false;
      const scenes = [
        {title: 'Tenant and VRF', text: 'Use an existing tenant and VRF of the site, or create them: each section has <b>Use existing</b> / <b>Create new</b>.',
          do: [['do', GA.when], ['pick', 'pvTenant', tenant], ...(vrf ? [['pick', 'pvVrf', vrf]] : [])]},
        {title: 'Bridge domain and subnet', text: 'A new bridge domain with its gateway subnet, L2 unknown unicast (hardware proxy) and ARP flooding; or an existing one.',
          do: [['type', 'pvBdNew', bd], ['click', 'pvSubnetAdd'],
            ['set', 'pvSubnets', M.frag(Provision.subnetsHtml([{ip: '', scope: 'public', preferred: false, virtual: false}]))],
            ['type', '@[data-g="pvSubnets"] [data-k="ip"]', subnet]]},
        {title: 'Application profile and EPG', text: 'The EPG is always named here; its application profile can be an existing one or a new one.',
          do: [...(app ? [['pick', 'pvApp', app]] : []), ['type', 'pvEpg', epg]]},
      ];
      if (domain) {
        scenes.push({title: 'Domains', text: 'The physical and VMM domains of the EPG (bare metal, VMware, OpenStack), with deployment and resolution immediacy.',
          do: [['check', '@[data-g="pvDomains"] input[type=checkbox]'], ['attr', 'pvReviewBtn', 'disabled', null]]});
      }
      scenes.push({title: 'Review & apply', text: 'The review lists every object (use existing, create, relation) and the JSON sent to APIC in one transaction. The portal never deletes objects.',
        do: [['attr', 'pvReviewBtn', 'disabled', null], ['click', 'pvReviewBtn'], ['show', 'reviewDialog'], ['move', '@[data-g="reviewBody"] table'], ['click', 'reviewConfirm'],
          ['hide', 'reviewDialog'], ['show', 'gtoast'], ['wait', 1500], ['hide', 'gtoast']]});
      return {html, overlay: [review, GA.toast('success', `Provisioning applied to ${site}.`, 'gtoast')], scenes};
    },
  },

  // ---------------------------------------------------------------- Create vPC
  vpc: {
    title: 'create a vPC (policy group and interface selector)',
    width: 1100,
    async build() {
      const site = Site.current;
      if (!site || !Site.info(site).configured) return null;
      const d = Vpc.data || await api('/api/vpc/options');
      const free = (p, n, i) => (d.ports[String(n)] || []).some(x => x.interface === i && x.status === 'free');
      // the pair on the page, else the first pair with a port free on both leaves; that port
      const usable = p => (d.ports[String(p.nodes[0])] || []).find(x => x.status === 'free' && free(p, p.nodes[1], x.interface));
      const p = [Vpc.pair(), ...d.pairs].filter(Boolean).find(usable);
      if (!p) return null;
      const [a, b] = p.nodes, port = usable(p).interface, key = p.nodes.join('-');
      const own = d.groups.filter(g => g.pair === key), copyFrom = own[0] || d.groups[0];
      // a name in the style of the vPCs of this pair (the next letter), else the one typed on the page
      const taken = new Set(d.names);
      const m = (copyFrom?.name || '').match(/^(.*[-_])([A-Z])(-PG)?$/);
      const guess = m ? [...'ABCDEFGHIJKLMNOPQRSTUVWXYZ'].map(c => `${m[1]}${c}${m[3] || ''}`).find(n => !taken.has(n)) : '';
      const name = $('#vpName').value.trim() || guess || 'SERVER-01-PG';
      const copy = GA.panel('vpc');
      $('[data-g="vpNoPerm"]', copy).hidden = true;
      $('[data-g="vpPair"]', copy).innerHTML = '<option value="">Choose a vPC pair</option>' + d.pairs.map(x => `<option value="${x.nodes.join('-')}">${esc(x.name)} · leaves ${x.nodes.join(' and ')}</option>`).join('');
      $('[data-g="vpPorts"] tbody', copy).innerHTML = M.rows(Vpc.portsHtml(d, null, {}, true, true));
      $('[data-g="vpPairVpcs"]', copy).innerHTML = '<span class="muted">—</span>';
      $('[data-g="vpPairInfo"]', copy).textContent = '';
      $('[data-g="vpCopy"]', copy).innerHTML = '<option value="">Nothing (choose below)</option>' + d.groups.map(g => `<option value="${esc(g.name)}">${esc(g.name)}</option>`).join('');
      VP_SETTINGS.forEach(([k, label, required]) => {
        $(`[data-g="vp${k[0].toUpperCase()}${k.slice(1)}"]`, copy).innerHTML = (required ? `<option value="">Choose the ${esc(label)}</option>` : '<option value="">(APIC default)</option>')
          + d.policies[k].map(n => `<option value="${esc(n)}">${esc(n)}</option>`).join('');
      });
      ['vpName', 'vpDescr', 'vpSelector'].forEach(k => { $(`[data-g="${k}"]`, copy).value = ''; });
      $('[data-g="vpProfile"]', copy).innerHTML = '—';
      $('[data-g="vpContext"]', copy).innerHTML = '<span class="muted">Choose a vPC pair, the ports and a policy group name</span>';
      $('[data-g="vpReviewBtn"]', copy).disabled = true;
      $('[data-g="vpLeafA"]', copy).textContent = 'Leaf';
      $('[data-g="vpLeafB"]', copy).textContent = 'Leaf';
      const picked = {[a]: new Set([port]), [b]: new Set([port])};
      const settings = Object.fromEntries(VP_SETTINGS.map(([k]) => [k, copyFrom?.[k] || '']).filter(([, v]) => v));
      const selector = name.replace(/-PG$/, '');
      // what Review shows, from these values (the page asks APIC for it; the guide sends nothing)
      const ifps = p.profiles.pair.length ? [{name: p.profiles.pair[0], nodes: [a, b]}]
        : p.profiles.leaf[a].length && p.profiles.leaf[b].length ? [{name: p.profiles.leaf[a][0], nodes: [a]}, {name: p.profiles.leaf[b][0], nodes: [b]}] : [];
      const num = port.split('/')[1], pg = `uni/infra/funcprof/accbundle-${name}`, path = `topology/pod-${p.pod}/protpaths-${a}-${b}/pathep-[${name}]`;
      const rel = {aaep: ['infraRsAttEntP', 'tDn', v => `uni/infra/attentp-${v}`], link: ['infraRsHIfPol', 'tnFabricHIfPolName'], lacp: ['infraRsLacpPol', 'tnLacpLagPolName'],
        cdp: ['infraRsCdpIfPol', 'tnCdpIfPolName'], lldp: ['infraRsLldpIfPol', 'tnLldpIfPolName'], mcp: ['infraRsMcpIfPol', 'tnMcpIfPolName']};
      const payload = {infraInfra: {attributes: {dn: 'uni/infra'}, children: [
        {infraFuncP: {attributes: {dn: 'uni/infra/funcprof'}, children: [{infraAccBndlGrp: {attributes: {name, lagT: 'node'},
          children: Object.entries(settings).map(([k, v]) => ({[rel[k][0]]: {attributes: {[rel[k][1]]: rel[k][2] ? rel[k][2](v) : v}}}))}}]}},
        ...ifps.map(t => ({infraAccPortP: {attributes: {dn: `uni/infra/accportprof-${t.name}`}, children: [{infraHPortS: {attributes: {name: selector, type: 'range'}, children: [
          {infraPortBlk: {attributes: {name: 'block2', fromCard: '1', toCard: '1', fromPort: num, toPort: num}}}, {infraRsAccBaseGrp: {attributes: {tDn: pg}}}]}}]}}))]}};
      const labels = Object.fromEntries(VP_SETTINGS.map(([k, label]) => [k, label]));
      const plan = {site, pair: key, pair_name: p.name, nodes: [a, b], name, path, ports: {[a]: [port], [b]: [port]}, blocked: [], warnings: [],
        steps: [{object: 'vPC policy group', name: pg, kind: 'new', action: 'Create'},
          ...Object.entries(settings).map(([k, v]) => ({object: labels[k], name: k === 'aaep' ? `uni/infra/attentp-${v}` : v, kind: 'link', action: 'Link'})),
          ...ifps.flatMap(t => [{object: 'Interface selector', name: `uni/infra/accportprof-${t.name}/hports-${selector}-typ-range`, kind: 'new', action: 'Create'},
            {object: 'Port blocks', name: `${port} on ${t.nodes.map(n => `leaf ${n}`).join(' and ')}`, kind: 'new', action: 'Create'}]),
          {object: 'vPC path (made by APIC)', name: path, kind: 'new', action: 'Appears'}],
        checks: [{ok: true, text: `Leaves ${a} and ${b} are vPC pair ${p.name} (vPC protection group).`}, {ok: true, text: `Policy group name ${name} is not used yet.`},
          ...[a, b].map(n => ({ok: true, text: `${port} on leaf ${n} is in no interface selector.`})),
          ...Object.entries(settings).map(([k, v]) => ({ok: true, text: `${labels[k]} ${v} exists.`})),
          ...ifps.map(t => ({ok: true, text: `Selector ${selector} is new in interface profile ${t.name} (${t.nodes.map(n => `leaf ${n}`).join(' and ')}).`}))],
        payload};
      const review = M.dialog('#reviewDialog');
      $('[data-g="reviewTitle"]', review).textContent = 'Review new vPC';
      $('[data-g="reviewBody"]', review).innerHTML = M.frag(Vpc.planHtml(plan));
      $('[data-g="reviewConfirmLabel"]', review).textContent = `Create vPC on ${site}`;
      $('[data-g="reviewConfirm"]', review).className = 'btn btn-primary';
      $('[data-g="reviewConfirm"]', review).hidden = false;
      $('[data-g="reviewConfirm"]', review).disabled = false;
      const done = M.frag(Vpc.planHtml({...plan, applied: true, path_ready: true}));
      const box = n => `@[data-g="vpPorts"] input[data-node="${n}"][value="${port}"]`;
      const scenes = [
        {title: 'The leaf pair', text: `<b>Read from APIC</b> reads the vPC pairs of <b>${esc(site)}</b> (vPC protection groups), their ports, the vPC policy groups and the interface policies. Choose the pair the server is connected to.`,
          do: [['click', 'vpLoad'], ['pick', 'vpPair', `${p.name} · leaves ${a} and ${b}`], ['set', 'vpPairInfo', `Pod ${p.pod} · ${plural(p.vpcs.length, 'vPC')}`],
            ['set', 'vpPairVpcs', M.frag(p.vpcs.map(v => `<span class="chip chip-own">${esc(v)}</span>`).join('') || '<span class="muted">none yet</span>')],
            ['set', 'vpLeafA', `Leaf ${a}`], ['set', 'vpLeafB', `Leaf ${b}`], ['set', '@[data-g="vpPorts"] tbody', M.rows(Vpc.portsHtml(d, p, {}, true, true))],
            ['tip', 'vpPairVpcs', 'Its vPCs: their names show the convention']]},
        {title: 'The ports', text: `The ports of both leaves side by side; only the free ones (in no interface selector) can be ticked. With <b>Same ports on both leaves</b> one tick takes ${esc(port)} on leaf ${a} and on leaf ${b}. A port that is up or has a neighbour is usually the server already connected: check its name.`,
          do: [['untip'], ['click', box(a)], ['set', '@[data-g="vpPorts"] tbody', M.rows(Vpc.portsHtml(d, p, picked, true, true))],
            ['set', 'vpPicked', `1 on leaf ${a}, 1 on leaf ${b}`], ['tip', box(b), `${esc(port)} on leaf ${b} too`]]},
        {title: 'The policy group', text: `Its name (the vPC path gets it) and the settings, copied from a vPC of this pair: the <b>AAEP</b> holds the domains of the EPGs (their VLAN pool), <b>LACP</b> the port-channel mode; link level, CDP, LLDP and MCP as the other vPCs.`,
          do: [['untip'], ['type', 'vpName', name], ['pick', 'vpCopy', copyFrom?.name || 'Nothing (choose below)'],
            ['do', s => VP_SETTINGS.forEach(([k]) => { const sel = $(`[data-g="vp${k[0].toUpperCase()}${k.slice(1)}"]`, s); sel.value = settings[k] || ''; })],
            ['tip', 'vpAaep', settings.aaep ? `${esc(settings.aaep)}: as ${esc(copyFrom.name)}` : 'Choose the AAEP']]},
        {title: 'The interface selector', text: 'The selector (the policy group name without -PG, or your own) goes into the interface profile the leaf profiles give these leaves: one profile for the pair, or one for each leaf.',
          do: [['untip'], ['move', 'vpSelector'], ['attr', 'vpSelector', 'placeholder', selector], ['set', 'vpProfile', M.frag(Vpc.profileHtml(p, true))],
            ['set', 'vpContext', M.frag(crumbs([p.name, '2 ports', name]))], ['attr', 'vpReviewBtn', 'disabled', null], ['tip', 'vpProfile', 'Chosen from the leaf profiles of APIC']]},
        {title: 'Review & apply', text: `Review checks everything on APIC again (pair, free ports, name, policies, selector) and shows the objects, the path and the JSON. <b>Create vPC</b> sends it in one transaction, recorded in History first${Vpc.canCreate ? '' : ' (an administrator, or an account with <b>ACI: create vPCs</b>)'}.`,
          do: [['untip'], ['click', 'vpReviewBtn'], ['show', 'reviewDialog'], ['move', '@[data-g="reviewBody"] table'], ['tip', '@[data-g="reviewBody"] p.mono', 'The vPC path APIC makes'],
            ['untip'], ['move', 'reviewConfirm'], ['tip', 'reviewConfirm', 'One APIC transaction']]},
        {title: 'Then bind it', text: 'Once created, the ports show as a vPC on Interfaces, and <b>Bind on Static Port</b> puts the vPC path in the Static Port table: choose the EPG and the VLAN there.',
          do: [['untip'], ['click', 'reviewConfirm'], ['set', 'reviewBody', done], ['attr', 'reviewConfirm', 'hidden', ''],
            ['tip', '@[data-g="reviewBody"] [data-vp-static]', 'To Static Port'], ['wait', 1600], ['untip'], ['hide', 'reviewDialog']]},
      ];
      return {html: copy.outerHTML, overlay: [review], scenes};
    },
  },

  // ---------------------------------------------------------------- Product templates
  templates: {
    title: 'keep the paths of a product',
    width: 1000,
    async build() {
      const site = Site.current;
      if (!site || !Products.list.length) return null;
      if (!Templates.productId) await Templates.open(Products.list[0].id);   // the same as choosing the first product
      const copy = GA.panel('templates');
      $$('.tool-panel', copy).forEach(p => { p.hidden = true; });
      const edit = Templates.canEdit;
      const vpc = $('[data-g="tpPhysicalTable"]', copy).hidden;   // the table of the sub-tab that is open (a product with only vPCs: vPC / Path TDN)
      const table = vpc ? 'tpPathsTable' : 'tpPhysicalTable';
      const scenes = [
        {title: 'Choose a product', text: `A product (a kind of server) has groups of paths per site; Static Port fills them in when the product is picked on <b>${esc(site)}</b>.`,
          do: [['move', 'tpPicker'], ['tip', '@[data-g="tpPicker"] label', 'Its groups and paths open below']]},
        {title: 'Groups', text: 'A group is a set of paths (for example the ports of one server); ticked groups are filled in at once, the others on request.',
          do: [['untip'], ['move', 'tpGroupsTable'], ['tip', '@[data-g="tpGroupsTable"] tbody tr', 'On Static Port: ticked by default or optional']]},
        {title: 'Paths', text: 'The ports, port-channels and vPCs of each group. The APIC column says whether the path exists in the fabric of this site.',
          do: [['untip'], ['move', 'tpPathsCard'], ['tip', `@[data-g="${table}"] thead`, vpc ? 'Group · path TDN (vPC) · exists on APIC' : 'Group · pod · node · interface · exists on APIC']]},
      ];
      if (edit) {
        scenes.push({title: 'Change and save', text: 'Add paths with Search APIC, Interface range or Bulk text; <b>Review & save</b> shows what changes. A template never changes APIC; the change is in History.',
          do: [['untip'], ['move', '@[data-tp-tool="search"]'], ['move', 'tpReviewBtn'], ['tip', 'tpReviewBtn', 'Review & save']]});
      }
      return {html: copy.outerHTML, scenes};
    },
  },
};

PortalGuide.mount(GUIDES, {page: name => document.querySelector(`#tab-${name}`)});

'use strict';
/* Guides of Nessus, one per page (data-page): each built from the page as it is now, with the page's own functions and
   dialog. The player is the portal's (static/guide.js, PortalGuide). A guide only reads (the GET requests the page makes
   itself) and never launches, stops or syncs anything. */
const {M} = PortalGuide;

const NG = {
  head(page) { return M.clone($('section.pf-m-light', page)); },
  main(page) { return M.clone($('section:not(.pf-m-light)', page)); },
  // the dialog of a launch, stop or Verify fix, filled as ScanDialog.show() fills it
  dialog(mode, scan, host = null) {
    const d = ScanDialog.content(mode, scan, host);
    const box = M.dialog('#scanDialog');
    $('[data-g="sdTitle"]', box).textContent = d.title;
    $('[data-g="sdRisk"]', box).innerHTML = M.frag(d.risk);
    $('[data-g="sdWhere"]', box).innerHTML = M.frag(d.where);
    $('[data-g="sdScope"]', box).textContent = d.scope;
    $('[data-g="sdScope"]', box).hidden = !d.scope;
    $('[data-g="sdConfirmName"]', box).textContent = d.expected;
    $('[data-g="sdError"]', box).hidden = true;
    const scans = host ? host.verify.scans : [];
    $('[data-g="sdScanGroup"]', box).hidden = !host;
    $('[data-g="sdScan"]', box).innerHTML = scans.map(s => `<option>${esc(s.name)}</option>`).join('');
    const b = $('[data-g="sdRun"]', box);
    b.className = `pf-btn ${d.danger ? 'pf-m-danger' : 'pf-m-primary'}`;
    b.innerHTML = `${icon(mode === 'stop' ? 'minus-circle' : mode === 'verify' ? 'refresh' : 'play')}${esc(d.button)}`;
    return {box, expected: d.expected};
  },
  sync(head) {
    return {title: 'Sync now', text: 'Reads from Tenable what changed since the last sync (the first one: the last 90 days). It runs on the portal '
      + `server; ${Session.syncHours > 0 ? `a page that opens also starts it when the last sync is older than ${Session.syncHours} hours` : 'only by hand here'}.`,
    do: [['untip'], ['move', '@[data-sync-now]'], ['tip', '@[data-sync-now]', esc(Sync.text())]], head};
  },
};

const GUIDES = {
  // ---------------------------------------------------------------- Overview
  overview: {
    title: 'read the state of every site',
    width: 1140,
    build() {
      const d = Overview.data;
      if (!d || !d.sites.length) return null;
      const page = $('#page-overview');
      const head = NG.head(page);
      const main = NG.main(page);
      $('[data-g="ovNotice"]', main).innerHTML = '';
      // the cards of the guide: the first three, and the first one with networks seen (administrators)
      const withSeen = d.sites.find(s => s.seen);
      $$('.ns-site-card', main).forEach((card, i) => {
        if (i >= 3 && !(withSeen && card.dataset.siteCard === withSeen.name)) card.remove();
      });
      const site = d.sites.find(s => SEVERITIES.some(k => (s.active || {})[k])) || d.sites[0];
      const card = `@[data-site-card="${site.name}"]`;
      const worst = SEVERITIES.find(k => (site.active || {})[k]) || 'high';
      const total = SEVERITIES.reduce((n, k) => n + ((site.active || {})[k] || 0), 0);
      const scenes = [
        {title: 'One card per site', text: `What the Nessus scanner of each site found on its management networks, as the portal keeps it. Here <b>${esc(site.name)}</b>: `
          + `${total} open finding${total === 1 ? '' : 's'}.`, do: [['move', `${card} .pf-card__actions`], ['tip', `${card} .pf-card__actions`, 'The scanner of the site in Tenable: online or offline']]},
        {title: 'Open findings per severity', text: 'Critical, High, Medium and Low that are open or came back. A tile opens the Findings of the site with that severity and above.',
          do: [['untip'], ['move', `${card} [data-kpi="${worst}"]`], ['tip', `${card} [data-kpi="${worst}"]`, `Opens the ${esc(SEVERITY[worst][0])} findings of ${esc(site.name)}`]]},
        {title: 'Remediation', text: '<b>Reopened</b>: fixed before and found again. <b>Fixed (30 days)</b>: what Tenable saw fixed. The trend has one bar per sync, the newest on the right.',
          do: [['untip'], ['move', `${card} .pf-dl`], ['tip', `${card} .ns-spark`, 'Open findings after each sync']]},
        NG.sync(head),
      ];
      const seen = d.sites.find(s => s.seen && $(`[data-site-card="${s.name}"] [data-seen]`, main));
      if (seen) {   // administrators: what the scanner of a site found outside the networks of sites.yml
        scenes.splice(3, 0, {title: 'Networks seen (administrators)', text: `The /24 networks of the hosts the scanner of <b>${esc(seen.name)}</b> found `
          + 'that sites.yml does not list yet, with a line to copy. Only a suggestion: scans are launched only inside the networks '
          + 'of sites.yml, so check them first, then write the line under the site.',
        do: [['untip'], ['move', `@[data-site-card="${seen.name}"] [data-seen]`],
          ['tip', `@[data-site-card="${seen.name}"] [data-seen] .pf-code-block`, 'Copy, check, then put it in sites.yml']]});
      }
      return {html: head.outerHTML + main.outerHTML, scenes};
    },
  },

  // ---------------------------------------------------------------- Findings
  findings: {
    title: 'find what to fix first',
    width: 1180,
    async build() {
      const d = Findings.data;
      if (!d) return null;
      const page = $('#page-findings');
      const head = NG.head(page);
      const main = NG.main(page);
      const plugins = d.view === 'plugins' ? d.items : [];
      const first = plugins[0];
      const table = $('[data-g="fdTable"]', main);
      if (first) {
        // the hosts of the first plugin, read as the page reads them when its row opens
        const {site, severity, state, q} = Findings.params();
        const hosts = Findings.hostsOf[first.plugin_id]
          || (await api(`/api/findings?${qs({site, severity, state, q, plugin: first.plugin_id})}`)).items;
        // and the fix plan of its first host, as the open row reads it (GET /api/findings/<id>)
        const fix = hosts.length ? await Findings.plan(hosts[0].id) : null;
        table.innerHTML = Findings.head('plugins') + plugins.slice(0, 5).map(p => Findings.pluginRow(p)).join('');
        M.clean(table);
        $$('tr.ns-detail', table).forEach(x => { x.hidden = true; });
        $$('tr.ns-row', table).forEach(x => x.classList.toggle('is-expanded', false));
        $(`[data-g="fdd-${first.plugin_id}"] td:last-child`, table).innerHTML = M.frag(Findings.detailHtml(first, hosts, fix));
      } else {
        M.keep(main, '[data-g="fdTable"] tbody', 5);
      }
      const row = first ? `@[data-g="fdTable"] tr.ns-row[data-plugin="${first.plugin_id}"]` : 'fdTable';
      const word = first ? (first.cves[0] || first.plugin_name.split(/\s+/).find(w => w.length > 3) || first.plugin_name) : '';
      const scenes = [
        {title: 'One row per vulnerability', text: `The plugins of Tenable that found something on <b>${esc(Site.title(Site.current))}</b>, the worst first `
          + '(severity, then VPR), with how many hosts have it and how many are open, reopened or fixed.',
        do: [['move', first ? `${row} .ns-name` : row], ['tip', first ? `${row} .ns-name` : row, 'The worst first']]},
      ];
      if (first) {
        scenes.push({title: 'Its hosts', text: 'A row opens the hosts that have it; a host opens its findings with the output of the scanner and the solution.',
          do: [['untip'], ['click', `${row} [data-toggle]`], ['cls', row, 'is-expanded'], ['show', `fdd-${first.plugin_id}`],
            ['attr', `${row} [data-toggle]`, 'aria-expanded', 'true'], ['tip', `@[data-g="fdd-${first.plugin_id}"] .ns-hosts`, 'Each address opens the host']]});
        scenes.push({title: 'How to fix it', text: 'Under the hosts: the fix of the first host, step by step, with where each step runs and its '
          + 'commands (copy button), the versions, the vendor links and Tenable\'s own solution. The portal only shows them: the '
          + 'operator runs them, in a window when customers can notice.',
        do: [['untip'], ['move', `@[data-g="fdd-${first.plugin_id}"] [data-fix]`],
          ['tip', `@[data-g="fdd-${first.plugin_id}"] .ns-fix__title`, 'Each host page has the plan of its own versions']]});
        scenes.push({title: 'Search and filter', text: 'Search a host, an address, a plugin or a CVE; keep a severity and above, or a state (Fixed: what was remediated).',
          do: [['untip'], ['type', 'fdQ', word], ['pick', 'fdSeverity', 'High and above'], ['pick', 'fdState', 'Open and reopened']]});
      }
      scenes.push({title: 'Every finding, and CSV', text: '<b>Every finding</b> lists one row per host and plugin (a row opens its fix). <b>Export CSV</b> downloads the findings of the filter with synopsis, solution, the fixed version and the fix in short, for the ticket or the owner of the devices.',
        do: [['untip'], ['move', '@[data-g="fdView"] label:nth-child(2)'], ['click', 'fdExport'], ['tip', 'fdExport', 'Nessus_Findings_&lt;site&gt;.csv']]});
      scenes.push(NG.sync(head));
      return {html: head.outerHTML + main.outerHTML, scenes};
    },
  },

  // ---------------------------------------------------------------- Hosts
  hosts: {
    title: 'see which hosts need work',
    build() {
      const d = Hosts.data;
      if (!d) return null;
      const page = $('#page-hosts');
      const head = NG.head(page);
      const main = NG.main(page);
      M.keep(main, '[data-g="hsList"] tr', 6);
      const first = d.items[0];
      const scenes = [
        {title: 'The worst first', text: `Every address of <b>${esc(Site.title(Site.current))}</b> with findings, with its open findings per severity, what came back and what was fixed in 30 days.`,
          do: [['move', first ? `@[data-g="hsList"] tr[data-ip="${first.ipv4}"]` : 'hsList'], ['tip', first ? `@[data-g="hsList"] tr[data-ip="${first.ipv4}"] td:nth-child(2)` : 'hsList', 'Critical first, then High, Medium, Low']]},
        {title: 'Filter', text: 'Search an address, a host name, a plugin or a CVE; keep a severity and above; <b>Fixed</b> shows the hosts that were remediated.',
          do: [['untip'], ['pick', 'hsSeverity', 'High and above'], ['move', 'hsState']]},
      ];
      if (first) {
        scenes.push({title: 'Open a host', text: 'A row opens its findings with the output of the scanner and the solution; there, Verify fix scans it again.',
          do: [['untip'], ['click', `@[data-g="hsList"] tr[data-ip="${first.ipv4}"]`], ['tip', `@[data-g="hsList"] tr[data-ip="${first.ipv4}"] a`, `Opens ${esc(first.ipv4)}`]]});
      }
      return {html: head.outerHTML + main.outerHTML, scenes};
    },
  },

  // ---------------------------------------------------------------- One host
  host: {
    title: 'fix a host, then verify it',
    width: 1100,
    build() {
      const d = HostPage.data;
      if (!d) return null;
      const page = $('#page-host');
      const head = NG.head(page);
      const main = NG.main(page);
      const table = $('[data-g="hoTable"]', main);
      const open = d.items.filter(f => f.state !== 'FIXED').slice(0, 4);
      const shown = open.length ? open : d.items.slice(0, 4);
      table.innerHTML = HostPage.head() + shown.map(f => HostPage.row(f)).join('');
      M.clean(table);
      $$('tr.ns-detail', table).forEach(x => { x.hidden = true; });
      $$('tr.ns-row', table).forEach(x => x.classList.toggle('is-expanded', false));
      $('[data-g="hoShown"]', main).textContent = `${shown.length} of ${d.items.length}`;
      const first = shown[0];
      const row = first ? `@[data-g="hoTable"] tr.ns-row[data-id="${first.id}"]` : 'hoTable';
      const scenes = [
        {title: 'What is open on this host', text: 'Every finding the portal has of it, open first; <b>Reopened</b> came back after a fix.',
          do: [['move', row], ['tip', row, 'Severity, state, port, when it was found']]},
      ];
      if (first) {
        const steps = (first.plan?.steps || []).length;
        scenes.push({title: 'How to fix it', text: `A row opens its fix for this host: ${steps} step${steps === 1 ? '' : 's'} on `
          + `${esc(first.plan?.platform?.label || 'this platform')}, each with where it runs and its commands (values of this host: `
          + 'its address, packages, versions), the versions, the patch and exploit facts and the vendor links. Shown only: the operator runs them.',
        do: [['untip'], ['click', `${row} [data-toggle]`], ['cls', row, 'is-expanded'], ['show', `hod-${first.id}`],
          ['move', `@[data-g="hod-${first.id}"] [data-fix]`], ['tip', `@[data-g="hod-${first.id}"] .ns-fix__title`, esc(first.plan?.title || 'The fix')]]});
        if ($(`[data-g="hod-${first.id}"] [data-copy]`, main)) {
          scenes.push({title: 'Copy the commands', text: 'The copy button takes the commands of a step; paste them on the host or device'
            + ((d.shell || []).length ? ': <b>Open a terminal</b> opens Shell, where you pick this host.' : '.'),
          do: [['untip'], ['click', `@[data-g="hod-${first.id}"] [data-copy]`], ['tip', `@[data-g="hod-${first.id}"] [data-copy]`, 'Copied']]});
        }
        scenes.push({title: 'Output and details', text: 'Below the fix: what the scanner saw (its output, as Tenable keeps it, up to 8 KB) and the details of the plugin.',
          do: [['untip'], ['move', `@[data-g="hod-${first.id}"] .ns-details-title`]]});
      }
      const overlay = [];
      const v = HostPage.verifyState(d);
      if (v.show && v.ok) {
        const scan = {...d.verify.scans[0], site: d.site};
        const {box, expected} = NG.dialog('verify', scan, d);
        overlay.push(box);
        scenes.push({title: 'Verify fix', text: `After the fix, <b>Verify fix</b> launches a scan of ${esc(d.site)} for <b>${esc(d.ip)}</b> only (its other targets are not scanned). `
          + 'The address is typed to confirm: a scan can load the device.',
        do: [['untip'], ['click', 'hoVerify'], ['show', 'scanDialog'], ['move', 'sdRisk'], ['type', 'sdConfirm', expected],
          ['tip', 'sdRun', 'Launches the scan for this host only'], ['wait', 900], ['untip'], ['hide', 'scanDialog']]});
        scenes.push({title: 'Then sync', text: 'When the scan has ended in Tenable, <b>Sync now</b> on Overview, Findings or Hosts: what was fixed shows as <b>Fixed</b> here.',
          do: [['move', 'hoState'], ['pick', 'hoState', 'Fixed']]});
      } else if (v.show) {
        scenes.push({title: 'Verify fix', text: `Verify fix is not possible for this host now: ${esc(v.why)}`, do: [['untip'], ['move', 'hoVerify'], ['tip', 'hoVerify', 'Not possible now']]});
      } else {
        scenes.push({title: 'Verify fix', text: 'An administrator, or an operator with the permission <b>Vulnerability Scans: launch and stop scans</b>, can scan the host again after the fix (Verify fix).',
          do: [['untip'], ['move', 'hoState']]});
      }
      return {html: head.outerHTML + main.outerHTML, overlay, scenes};
    },
  },

  // ---------------------------------------------------------------- Scans
  scans: {
    title: 'launch or stop a scan',
    width: 1140,
    build() {
      const items = Scans.items;
      if (!Scans.items || Router.page !== 'scans') return null;
      const page = $('#page-scans');
      const head = NG.head(page);
      const main = NG.main(page);
      $('[data-g="scNotice"]', main).innerHTML = '';
      M.keep(main, '[data-g="scList"] tr', 5);
      const ok = items.find(s => s.can_launch);
      const inside = items.find(s => s.guard.ok);
      const bad = items.find(s => !s.guard.ok);
      const scenes = [];
      if (inside) {
        scenes.push({title: 'Management networks only', text: `The scanners scan only the management networks of their site. <b>Management only</b>: every target of the scan is inside the networks of ${esc(inside.site)} in sites.yml.`,
          do: [['move', `@[data-g="scList"] tr[data-scan="${inside.id}"] td:nth-child(3)`], ['tip', `@[data-g="scList"] tr[data-scan="${inside.id}"] td:nth-child(3)`, esc(inside.guard.reason)]]});
      }
      if (bad) {
        scenes.push({title: 'Not launchable', text: 'A scan with a target outside those networks (even partly), a host name, or no target list is never launched from the portal, also not by an administrator.',
          do: [['untip'], ['move', `@[data-g="scList"] tr[data-scan="${bad.id}"] td:nth-child(3)`], ['tip', `@[data-g="scList"] tr[data-scan="${bad.id}"] td:nth-child(3)`, 'Change its targets in Tenable']]});
      }
      const overlay = [];
      if (Session.canScan && ok) {
        const {box, expected} = NG.dialog('launch', ok);
        overlay.push(box);
        scenes.push({title: 'Launch', text: 'The dialog says what will be scanned and that a scan can load the devices; the scan name is typed to confirm. Everything is in the activity log.',
          do: [['untip'], ['click', `@[data-g="scList"] tr[data-scan="${ok.id}"] [data-act="launch"]`], ['show', 'scanDialog'], ['move', 'sdScope'],
            ['type', 'sdConfirm', expected], ['tip', 'sdRun', 'Tenable starts the scan on the scanner of the site'], ['wait', 900], ['untip'], ['hide', 'scanDialog']]});
        scenes.push({title: 'Stop', text: 'A running scan has <b>Stop</b> instead (always allowed: stopping is safe), also with the scan name typed. The page follows its status.',
          do: [['move', 'scRefresh'], ['tip', 'scRefresh', 'Reads Tenable again']]});
      } else {
        scenes.push({title: 'Launch and stop', text: Session.canScan
          ? '<b>Launch</b> asks for the scan name and warns that a scan can load the devices; a running scan has <b>Stop</b> instead (always allowed). Scans are made and changed in Tenable.'
          : 'An administrator, or an operator with the permission <b>Vulnerability Scans: launch and stop scans</b> (Users page), launches and stops existing scans here. Scans are made and changed in Tenable.',
        do: [['untip'], ['move', 'scRefresh']]});
      }
      return {html: head.outerHTML + main.outerHTML, overlay, scenes};
    },
  },

  // ---------------------------------------------------------------- One scan
  scan: {
    title: 'read one scan',
    build() {
      const s = ScanPage.scan;
      if (!s) return null;
      const page = $('#page-scan');
      const head = NG.head(page);
      const main = NG.main(page);
      M.keep(main, '[data-g="snHosts"] tr', 5);
      M.keep(main, '[data-g="snHistory"] tr', 4);
      const scenes = [
        {title: 'Targets and scope', text: 'What the scan scans, and whether all of it is inside the management networks of its site (else the portal never launches it).',
          do: [['move', '@[data-g="snDetail"] .pf-dl'], ['tip', '@[data-g="snDetail"] .pf-dl dd:nth-of-type(3)', esc(s.guard.reason)]]},
        {title: 'Hosts of the last run', text: 'The open findings per host as Tenable counts them; an address with findings in the portal opens its host page.',
          do: [['untip'], ['move', 'snHosts']]},
        {title: 'History', text: 'Every run, by the schedule or by hand (in Tenable or from the portal).', do: [['move', 'snHistory']]},
      ];
      return {html: head.outerHTML + main.outerHTML, scenes};
    },
  },
};

PortalGuide.mount(GUIDES, {page: name => document.querySelector(`[data-page="${name}"]`)});

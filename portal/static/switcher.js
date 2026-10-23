'use strict';
/* Ops Portal: application launcher in the masthead (PatternFly "Application launcher", as in the OpenShift console:
   grid toggle -> menu of the portal home, the modules this account may use, and Administration for administrators).

   A page includes /static/switcher.css and /static/switcher.js and puts <div id="portalLauncher" data-current="<module id>">
   in its masthead. PortalLauncher.signIn() sends the browser to the portal sign-in and back to this page afterwards. */
(function () {
  const SVG = (body, filled = false) => `<svg viewBox="${filled ? '0 0 32 32' : '0 0 24 24'}" aria-hidden="true">${body}</svg>`;
  const ICONS = {
    // PatternFly "th" (grid) icon of the application launcher toggle
    grid: SVG('<path d="M2 2h8v8H2zM12 2h8v8h-8zM22 2h8v8h-8zM2 12h8v8H2zM12 12h8v8h-8zM22 12h8v8h-8zM2 22h8v8H2zM12 22h8v8h-8zM22 22h8v8h-8z"/>', true),
    home: SVG('<path d="M3.5 11L12 4l8.5 7"/><path d="M6 9.5V20h12V9.5"/>'),
    network: SVG('<rect x="9" y="3" width="6" height="5" rx="1"/><rect x="3" y="16" width="6" height="5" rx="1"/><rect x="15" y="16" width="6" height="5" rx="1"/><path d="M12 8v4M6 16v-2h12v2"/>'),
    database: SVG('<ellipse cx="12" cy="5.5" rx="7.5" ry="2.8"/><path d="M4.5 5.5v13c0 1.5 3.4 2.8 7.5 2.8s7.5-1.3 7.5-2.8v-13M4.5 12c0 1.5 3.4 2.8 7.5 2.8s7.5-1.3 7.5-2.8"/>'),
    checklist: SVG('<rect x="4.5" y="3.5" width="15" height="17" rx="1.5"/><path d="M8 8.5l1.5 1.5 3-3M8 14.5l1.5 1.5 3-3M15 9h1.5M15 15h1.5"/>'),
    users: SVG('<circle cx="9" cy="8" r="3.5"/><path d="M2.5 19.5c.6-3.4 3.2-5.5 6.5-5.5s5.9 2.1 6.5 5.5"/><path d="M15.5 4.8a3.5 3.5 0 0 1 0 6.4M17.5 14.3c2.1.6 3.6 2.4 4 5.2"/>'),
    key: SVG('<circle cx="8" cy="15.5" r="4.5"/><path d="M11.3 12.2L20 3.5M16.5 7l2.5 2.5M14 9.5l2 2"/>'),
  };
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));

  const Launcher = {
    root: null,
    status: null,
    get current() { return this.root.dataset.current || ''; },
    init() {
      this.root = document.getElementById('portalLauncher');
      if (!this.root) return;
      this.root.classList.add('pf-app-launcher');
      this.root.innerHTML = `<button type="button" class="pf-app-launcher__toggle" aria-label="Application launcher" aria-haspopup="menu"`
        + ` aria-expanded="false" title="Portal modules">${ICONS.grid}</button><div class="pf-app-launcher__menu" role="menu" hidden></div>`;
      this.toggle = this.root.querySelector('.pf-app-launcher__toggle');
      this.menu = this.root.querySelector('.pf-app-launcher__menu');
      this.toggle.addEventListener('click', () => (this.menu.hidden ? this.open() : this.close()));
      document.addEventListener('click', e => { if (!this.menu.hidden && !this.root.contains(e.target)) this.close(); });
      this.root.addEventListener('keydown', e => this.keys(e));
      this.root.addEventListener('focusout', e => { if (!this.root.contains(e.relatedTarget)) this.close(); });
      this.refresh();
    },
    async refresh() {
      try {
        const status = await (await fetch('/api/session', {headers: {Accept: 'application/json'}})).json();
        this.render(status);
        return status;
      } catch (e) {
        return null;
      }
    },
    render(status) {
      this.status = status;
      const user = status && status.user;
      this.root.hidden = !user;
      if (!user) return;
      const item = (href, icon, title, description = '', current = false, disabled = false) => `<li role="none">`
        + `<a class="pf-app-launcher__item" role="menuitem" href="${disabled ? '#' : esc(href)}"${current ? ' aria-current="page"' : ''}`
        + `${disabled ? ' aria-disabled="true" tabindex="-1"' : ''}><span class="pf-app-launcher__item-icon">${ICONS[icon] || ICONS.checklist}</span>`
        + `<span class="pf-app-launcher__item-text">${esc(title)}</span>`
        + (description ? `<span class="pf-app-launcher__item-description">${esc(description)}</span>` : '') + '</a></li>';
      const modules = (status.modules || []).filter(m => m.allowed);
      let html = `<section class="pf-app-launcher__group"><h1 class="pf-app-launcher__group-title">${esc(status.title || 'Ops Portal')}</h1>`
        + `<ul class="pf-app-launcher__list" role="none">${item('/#/home', 'home', 'Home', 'All modules', this.current === 'home')}</ul></section>`
        + '<section class="pf-app-launcher__group"><h1 class="pf-app-launcher__group-title">Modules</h1><ul class="pf-app-launcher__list" role="none">'
        + modules.map(m => item(m.url, m.icon, m.title, m.description, m.id === this.current)).join('') + '</ul></section>';
      if (user.role === 'admin') {
        html += '<section class="pf-app-launcher__group"><h1 class="pf-app-launcher__group-title">Administration</h1><ul class="pf-app-launcher__list" role="none">'
          + item('/#/users', 'users', 'Users', 'Accounts, roles and module access, activity', this.current === 'users')
          + item('/#/credentials', 'key', 'Credentials', 'Service accounts of every module', this.current === 'credentials') + '</ul></section>';
      }
      this.menu.innerHTML = html;
    },
    items() { return [...this.menu.querySelectorAll('.pf-app-launcher__item:not([aria-disabled="true"])')]; },
    open() {
      if (this.status) this.render(this.status);   // the current page may have changed since the last render
      this.menu.hidden = false;
      this.toggle.setAttribute('aria-expanded', 'true');
      (this.items().find(a => a.getAttribute('aria-current') === 'page') || this.items()[0])?.focus();
    },
    close() {
      this.menu.hidden = true;
      this.toggle.setAttribute('aria-expanded', 'false');
    },
    keys(e) {
      if (this.menu.hidden) return;
      const items = this.items();
      const at = items.indexOf(document.activeElement);
      if (e.key === 'Escape') {
        e.preventDefault();
        this.close();
        this.toggle.focus();
      } else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        e.preventDefault();
        const next = e.key === 'ArrowDown' ? (at + 1) % items.length : (at - 1 + items.length) % items.length;
        items[next]?.focus();
      } else if (e.key === 'Home' || e.key === 'End') {
        e.preventDefault();
        items[e.key === 'Home' ? 0 : items.length - 1]?.focus();
      }
    },
  };

  window.PortalLauncher = {
    refresh: () => Launcher.refresh(),
    // No (more) portal session: sign in on the portal home page, then come back here.
    signIn() {
      location.assign(`/?next=${encodeURIComponent(location.pathname + location.search + location.hash)}`);
    },
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => Launcher.init());
  else Launcher.init();
})();

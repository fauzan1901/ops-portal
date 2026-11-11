'use strict';
/* Guide of Status (one page): built from the page as it is now. The player is the portal's (static/guide.js, PortalGuide).
   A guide only reads (the GET request the page makes itself) and never starts a round. */
const {M} = PortalGuide;

const GUIDES = {
  overview: {
    title: 'the health of a site',   // the player puts "Guide:" before it
    build() {
      const page = $('[data-page="overview"]');
      const d = Overview.data;
      if (!page || !d) return null;
      const head = M.clone($('section.pf-m-light', page));
      const main = M.clone($('section:not(.pf-m-light)', page));
      const card = $('.hc-card.is-clickable', main) || $('.hc-card', main);
      const row = $('.hc-detail-section:not([hidden]) tr.hc-row', main);
      const scenes = [
        {title: 'One site at a time', text: 'The tabs at the top choose the site; this page shows its products from the last round.',
          do: [['move', 'hcWhen'], ['tip', 'hcWhen', 'When the last round ran, and when the next one runs by itself.']]},
        {title: 'The summary of each product', text: 'OpenStack, NetApp ONTAP, VMware Cloud and the hardware of every BMC: Safe when every check is OK, else Needs attention '
          + 'or Not safe, with how many checks found a problem, a warning, could not run, or are OK.',
          do: [['untip'], ...(card ? [['move', card]] : [])]},
        {title: 'Click a product', text: 'Below the cards, its checks that are not healthy, worst first; the other checks are named under them.',
          do: card ? [['click', card], ['tip', card, 'Click again to close it.']] : []},
        ...(row ? [{title: 'Click a check', text: 'What it found, its recommendations (a fix is asked for on its run: pre-check, then an '
          + 'engineer\'s review) and the checks to run next.', do: [['untip'], ['move', row], ['click', row]]}] : []),
        {title: 'Run now', text: 'Starts the round of this site now: the same read-only checks, one after the other; the page fills in as each ends.',
          do: [['untip'], ['move', 'hcRun'], ['tip', 'hcRun', 'Read only: nothing is changed.']]},
      ];
      return {html: head.outerHTML + main.outerHTML, scenes};
    },
  },
};

PortalGuide.mount(GUIDES, {page: name => document.querySelector(`[data-page="${name}"]`)});

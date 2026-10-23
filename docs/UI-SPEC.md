# Handoff Spec: ACI Web UI (Static Port · Provisioning · Report · History)

Implementation:
- `aci_webui/templates/index.html` — page skeleton;
- `aci_webui/static/app.css` — tokens and components;
- `aci_webui/static/app.js` — behavior;
- `aci_webui/static/fonts/` — Red Hat fonts, OFL 1.1 license.

The style follows **PatternFly v5 as used in AWX / Ansible Automation Platform**, the same as the ONTAP Restore Web UI. The tokens (`--pf-*`) are identical in both apps, so operators see the same patterns in both tools.

References:
- PatternFly: patternfly.org, github.com/patternfly/patternfly (MIT).
- AWX UI: github.com/ansible/ansible-ui.

No PatternFly code is used. All CSS is written in-house so it runs offline without a CDN. All values below refer to the CSS tokens in `:root`; do not write raw colors or sizes in new components.

## Overview

Internal tool for network engineers who change the Cisco ACI configuration at three sites (DCB, DCA, DCC). The biggest risks are **changing the wrong site** or **unknowingly changing an existing binding**. The design aims to reduce both risks:

1. **The site is always visible.** The site name appears in:
   - the site selector in the masthead;
   - the browser tab title (`[DCA] ACI Web UI`);
   - the page description;
   - the site label in the action bar (in the site color);
   - the site banner on the Review screen (left border and name box in the site color).

   The site color is only an extra cue; the site name is always written out.
2. **One path to the APIC.** The only way to send changes is the **Review & Apply** button, which opens the Review screen with a diff before confirmation.
3. **Mistakes are caught early.** Fields are checked as you type. A wrong field gets a red underline, and the reason appears in a tooltip.
4. **Fast input for large data.** Available:
   - searchable dropdowns;
   - multi-select from APIC search results;
   - interface ranges and bulk text;
   - copy from an existing binding;
   - product templates (Acme Flex, Acme Prime, RHOSO).

The main users work from a desktop browser on the jumphost (1366–1920px). Narrow screens still work (the sidebar collapses) but are not optimized.

## Layout

```
┌ Masthead (sticky, 64px, --pf-masthead-bg) ─────────────────────────────────┐
│ ☰ [logo] ACI Web UI              [● DCB][● DCA][○ DCC ×]   DE demo  ⇥ Logout│
├──────────────── busy line 3px (--pf-nav-accent) during a request ──────────┤
│ FABRIC        │ Page title + description (names the active site) + actions  │
│ ▌Static Port  ├─────────────────────────────────────────────────────────────┤
│  Provisioning │ Card 1..n (numbered steps) on --pf-bg-page                  │
│  Report       │                                                             │
│ AUDIT         │                                                             │
│  History      ├ Action bar (sticky bottom, white, top shadow) ──────────────┤
│ ● DCB host    │ (● DCA) CLOUD-1 › MGMT-InBand › EPG · 6 binding [Review &…] │
└───────────────┴─────────────────────────────────────────────────────────────┘
  sidebar 250px (sticky)   content: minmax(0, 1fr)
```

- **`.pf-page`:** 2-column grid (`250px | 1fr`). The masthead spans the full width and sticks to the top. The sidebar sticks below the masthead with a height of `100vh - 64px`.
- **Each menu (`.tabpanel`):**
  - white title section `.pf-page__section.pf-m-light`, containing a 24px title, a description, and the page action button (Export) on the right;
  - content section `.pf-page__section`, padding `--pf-space-lg`;
  - action bar (Static Port and Provisioning).
- **Form grid:** `.grid-3` and `.grid-2`, gap `--pf-space-md` (rows) × `--pf-space-lg` (columns).
- **Card:** white, `--pf-shadow-sm`, no radius, padding `--pf-space-lg`. Gap between cards `--pf-space-lg`.
- **Action bar:** `position: sticky; bottom: 0` inside its menu, so it is always visible when scrolling.

## Design Tokens

**Base colors and text**

| Token | Value (light / dark) | Usage |
|-------|------------------------|------------|
| `--pf-bg-page` | #f0f0f0 / #0f1214 | Content area background |
| `--pf-bg` | #ffffff / #1b1d21 | Card, modal, input, title section, action bar |
| `--pf-bg-muted` | #f0f0f0 / #26292d | Tool panel, subpanel, code block, site banner |
| `--pf-bg-hover` | #f5f5f5 / #26292d | Table row hover, dropdown option |
| `--pf-border` / `-light` | #d2d2d2, #f0f0f0 / #444548, #2f3033 | Toggle group, checklist, table header / table row line, input sides |
| `--pf-border-input` | #8a8d90 / #6a6e73 | Input underline |
| `--pf-text` / `-secondary` / `-disabled` | #151515, #6a6e73, #8a8d90 / #e0e0e0, #aaabac, #6a6e73 | Main text / description, hint / disabled |

**Accent colors**

| Token | Value (light / dark) | Usage |
|-------|------------------------|------------|
| `--pf-primary` / `-hover` / `-soft` | #0066cc, #004080, #e7f1fa / #1fa7f8, #73c5fa, #1a2f40 | Primary button, link, focus, step number, selected choice |
| `--pf-success` / `-soft` / `-text` | #3e8635, #f3faf2, #1e4f18 | Label "New" / "Success", success status |
| `--pf-warning` / `-soft` / `-text` | #f0ab00, #fdf7e7, #795600 | Label "Changed" / "Uncertain", warning alert |
| `--pf-danger` / `-soft` / `-text` | #c9190b, #faeae8, #7d1007 | Invalid input, error, delete button |

**Masthead, sidebar, and site**

| Token | Value (light / dark) | Usage |
|-------|------------------------|------------|
| `--pf-masthead-bg` / `--pf-sidebar-bg` | #151515 / #212427 | Masthead / sidebar |
| `--pf-nav-current` / `--pf-nav-accent` | #4f5255 / #73bcf7 | Active menu (background + 4px left bar), selected site, busy line |
| `--site` / `--site-soft` | site color / 14% alpha | Set by JS to match the active site (site label in the action bar) |
| Site palette | #0066cc, #3e8635, #6753ac, #8f4700, #a30000, #005f60 | Order follows `ACI_SITES`: DCB blue, DCA green, DCC purple |

**Typography**

| Token | Value | Usage |
|-------|-------|------------|
| `--pf-font-text` | Red Hat Text 400/500/700 | All text |
| `--pf-font-heading` | Red Hat Display 400/700 | Page title, card, modal, KPI |
| `--pf-font-mono` | Red Hat Mono 13px | TDN path, DN, IP, bulk text, payload |
| `--pf-font-xs/sm/md/lg/xl/2xl` | 12/14/16/18/20/24px | Table header, label / body / card title / brand / product VLAN / page title, modal |

**Spacing, shape, and shadow**

| Token | Value | Usage |
|-------|-------|------------|
| `--pf-space-xs/sm/md/lg/xl` | 4/8/16/24/32px | All spacing |
| `--pf-radius` / `-pill` | 3px / 30em | Button, toggle group, site name box / label (badge, pill, count) |
| `--pf-shadow-sm/md/lg/xl/top` | see CSS | Card / dropdown, tile hover / toast / modal, login card / action bar |

Contrast (WCAG AA ≥ 4.5:1), calculated:
- Secondary text: 5.13:1 on white and 4.5:1 on #f0f0f0.
- White text on the site palette: 4.5–8.2:1 (green 4.5; blue 5.57; purple 6.16; orange 6.84; cyan 7.48; red 8.21).
- Label/alert text (`-text` on `-soft`): 6.2–12.8:1.
- Link/primary on white: 5.57:1.
- Menu text on the sidebar: 13.7:1.

## Components

**Frame and navigation**

| Component | Variant | Markup | Notes |
|----------|--------|--------|---------|
| Masthead | — | `.pf-masthead`: nav toggle, `.pf-brand`, site selector, avatar + username, Logout (`.btn-appbar`) | Sticks to the top. Busy line `.progress` on the bottom edge. |
| Site selector | selected, normal, login failed, locked | `role="radiogroup"`, `<input type=radio name=site>` + `.site-chip` (dark toggle group) | Selected: `--pf-nav-accent` border. Login failed: disabled, empty dot, yellow × icon, reason in a tooltip. Locked (`.is-locked`) while the site data is loading. |
| Sidebar | active menu, normal | `nav#tabs` containing `a.pf-nav__link[data-tab]` + `aria-current="page"`, "Fabric" and "Audit" sections, site list `#navSites` | The last menu is saved per browser tab (sessionStorage) and in the URL hash (`#static`, `#provision`, `#report`, `#audit`). |

**Form and buttons**

| Component | Variant | Markup | Notes |
|----------|--------|--------|---------|
| Button | primary, secondary, ghost (link), danger, link-inline; sm, lg, block | `.btn .btn-*` | Primary only for the main page action (Review & Apply, Apply, Show, Search, Login). `.btn-danger` for confirmations that clear input. `.is-loading` shows a spinner and disables the button. |
| Input | normal, hover, focus, invalid, disabled, mono, sm | `.input` | PatternFly style: 1px underline (focus 2px primary, invalid 2px danger). |
| Combobox (typeahead) | normal, open, disabled, loading | `combo(select)` wraps the native `<select>` | The native select remains the source of the value and the `change` event. The list is a menu with a shadow; the selected option is shown in primary color. Maximum 200 options; the rest is shown as "n more — type to narrow down". Matching words are highlighted with `<mark>`. |
| Toggle group | 2–3 options | `.segmented` + radio | Modes: use existing / create new / none, immediacy, unknown unicast. |
| Switch | on, off | `.switch` + checkbox | Track 40×22px; on = primary. Used for ARP Flooding. |
| Checklist | flat, grouped | `.checklist .check-item`, `.check-group-title` | Domain, L3Out, and path search results. |

**Static Port**

| Component | Variant | Markup | Notes |
|----------|--------|--------|---------|
| Product selector | selected, normal, unavailable | radio `name=product` + `.product-card` (selectable tile) | Selected: primary border and inner shadow, primary-soft background, white icon in a primary box. The subtitle gives the composition per site ("VMware · 22 ports + 3 vPC"). |
| Template group | checked, optional, path missing | `.tpl-group` + checkbox `data-group`, ▾ button `aria-expanded` | Optional groups get the label "optional". Paths that do not exist in the fabric are struck through in red. |
| Binding sub-tab | active, normal | `.subtabs [role=tab]` + `.count` | 3px primary underline on the active tab (PatternFly tab). |
| Edit table | normal, invalid, empty | `.table-edit`, 32px input per cell with `data-k` | Row number; the Duplicate/Delete actions are icon buttons with `aria-label`. |
| Tool panel | search, range, bulk | `.tool-panel` (3px primary left line) | Only one is open at a time; toolbar buttons get `aria-expanded` and `.is-active`. |
| Action bar | normal, has errors | `.actionbar` | Contains the site label (`.site-tag`, site color), the target breadcrumb, and the binding count. The error count uses `.is-warning`. |

**Tables, labels, and feedback**

| Component | Variant | Markup | Notes |
|----------|--------|--------|---------|
| Data table | hover, sort | `.table-data`, header `.th-sort` | PatternFly compact table without zebra stripes; 12px bold header, sticky inside `.table-wrap`. Long columns in History may wrap (`td.wrap`). |
| Label | gray, green, gold, red | `.badge`, `.pill` (+ `-new`, `-change`, `-danger`) | Diff status (New/Changed/Same), provisioning action, history status. |
| KPI | normal, active | `.kpi` button + `aria-pressed` | Selectable card; the number uses the 24px heading font. Click = filter the report table. |
| Inline alert | info, success, warning, danger | `.alert.alert-*` | 2px top line in the matching color, soft background, colored icon. The `<b>` part uses the alert text color. |

**Modal and toast**

| Component | Variant | Markup | Notes |
|----------|--------|--------|---------|
| Review modal | review, applying, success, failed | `<dialog id=reviewDialog>` | Buttons in the left footer: Apply (primary), then Cancel (link); initial focus on Cancel. Contents: site banner, summary labels, warnings, diff table, payload (provisioning). |
| Site banner | — | `.site-banner` + `--opt` | 4px left line and name box in the site color, APIC host, target DN. |
| Confirmation modal | normal, danger | `<dialog id=confirmDialog>` + `confirmDialog({title, body, confirmLabel, danger})` | Replaces the browser's built-in `confirm()` (replace the table with a template, delete all rows, clear the form). Initial focus on Cancel; Esc = cancel. |
| History detail | — | `<dialog id=auditDialog>` | Metadata (`.meta-grid`, bold labels), error, binding/step table, payload. |
| Toast | success, info, error, with action | `.toast-*` in `#toasts` (alert group) | Top right below the masthead: white background, colored top line. Disappears by itself after 5 seconds (10 seconds for errors). Toasts with an action (for example "Reload" when the Web UI is updated) stay visible until dismissed. |

**Login**

| Component | Variant | Markup | Notes |
|----------|--------|--------|---------|
| Login | normal, error, loading | `.pf-login`: dark left column (brand, description, list of sites + hosts), white card on the right | Advanced options (TLS validation) inside `<details>`. |

## States and Interactions

**Site and navigation**

| Element | State | Behavior |
|---------|-------|---------|
| Site selector | Click another site | The site label in the action bar and the browser tab title change. Tenant/domain data is reloaded. The Tenant/App/EPG selections are kept if the same names also exist on the new site. The contents of the binding table are **not** cleared, so they can be applied again to another site. |
| Site selector | Loading | All options are disabled (`.is-locked`, opacity .6) until the new site data has finished loading, to prevent request races. |
| Sidebar menu | Click | Active menu: `--pf-nav-current` background + 4px `--pf-nav-accent` left bar. The page scrolls back to the top. History is loaded when first opened or after an Apply. |
| ☰ | Click | Desktop: the sidebar collapses/expands (`is-nav-collapsed`). Screen ≤1000px: the sidebar opens/closes (`is-nav-open`). `aria-expanded` follows. |

**Static Port**

| Element | State | Behavior |
|---------|-------|---------|
| Product selector | Click a product | The template for the active site is loaded. The binding table is **replaced** with the paths of the checked groups, then "14 paths will be installed (0 ports, 14 vPC)" is shown. If the table contains manual rows, a confirmation modal appears first. |
| Product VLAN | Change EPG / type | The number at the end of the EPG name (1–4094) becomes the VLAN. Typing changes all rows; values outside 1–4094 are marked red. |
| Combobox | Focus / type / ↑↓ Enter Esc | The list opens with the text selected. Typing filters (substring, case-insensitive). Arrows move between options, Enter selects, Esc closes without changing. |
| Table input | Invalid | 2px danger underline, `aria-invalid="true"`, reason in `title`. The number of invalid rows is shown in the action bar. |
| Add from search | Button | Disabled until a path is checked **and** the VLAN is valid. The label states the count: "Add 3 paths". |
| Range / Bulk | Input | Range: live preview, maximum 200 interfaces. Bulk: valid rows are added, invalid rows are listed in a yellow alert. |

**Review and Apply**

| Element | State | Behavior |
|---------|-------|---------|
| Review & Apply | Disabled | If the target is incomplete or the table is empty. |
| Review & Apply | Has invalid rows | The modal does not open. The page scrolls to the first invalid cell (to the center, so the action bar does not cover it), focus moves to that cell, and an error toast appears. |
| Review modal | Open | Button loading → server preview → modal. Initial focus on **Cancel**. |
| Review modal | No changes | The Apply button is disabled with the label "No changes", plus an info alert. |
| Review modal | Applying | Label "Applying…" + spinner. Cancel, ✕, and Esc do not work until it finishes. |
| Review modal | Success | Success status (green alert with a ✓ icon) and the history record number. The Apply button disappears; Cancel becomes "Close". A success toast appears. |
| Review modal | Failed | A red alert above the contents shows the APIC message. Apply is enabled again to retry. |

**Report, history, and session**

| Element | State | Behavior |
|---------|-------|---------|
| Report | Click header / KPI | Header: sorts ascending, then descending (`aria-sort`), the active column is shown in primary color. KPI: filters by binding type; click "Total binding" to clear the filter. |
| Export | Click | Button loading. The file is downloaded through `fetch`; errors are shown as a toast. |
| History | Click row / Enter | Opens the change detail. The Status column comes after Time (like the AWX Jobs list) so it is always visible. |
| Login | Submit | Button "Log in to all sites…" + spinner. Inline errors in the card (per site, one per line). The username is remembered in the browser (localStorage); the password is never stored. |
| New version on the server | Detected | An info toast "Reload" that does not disappear by itself (not the browser's built-in `confirm()`). |

## Responsive Behavior

| Breakpoint | Change |
|------------|------------|
| > 1200px | Default layout: 3-column grid, report filter 3 columns + button, KPI 4 columns, history filter 6 columns. |
| 1001–1200px | `.grid-3` becomes 2 columns, `.grid-2` 1 column, KPI 2×2, history filter 3 columns. |
| ≤ 1000px | The sidebar is hidden by default (☰ opens it). The username is hidden (the avatar stays). Login is 1 column. Product fields are 1 column. The edit table scrolls horizontally (min. 720px). |

Tested at 1366×768 and 1440×900. The History table fits without horizontal scroll at 1366px with the sidebar open.

## Edge Cases

- **Very many tenants (hundreds):** combobox with search, and only the first 200 options are rendered.
- **More than 300 path search results:** the server caps the result at 300, and the UI shows "capped at 300 — narrow the keyword".
- **Long TDN paths:**
  - in data tables: mono font `nowrap`, the table scrolls horizontally;
  - in checklists, history, and description lists: the text may break (`overflow-wrap: anywhere`).
- **Site login failed:** the site is still shown in the site selector and the sidebar, but it is disabled with the reason in a tooltip. Other sites remain usable.
- **Site token expired / session ended:** a 401 request updates the site status. A keepalive that finds the session ended returns to the login page with a toast.
- **Slow connection:** busy line below the masthead, loading buttons, and dropdown "Loading…".
- **Empty states:** a centered PatternFly empty state (48px icon, title, hint) for the binding table, report (not loaded / empty / no match), and history (empty / no filter match). Domain, L3Out, and subnet have their own empty text.
- **No internet:** no CDN. The Red Hat fonts and SVG icons are bundled in the app.

## Animation / Motion

| Element | Trigger | Animation | Duration | Easing |
|---------|---------|-----------|----------|--------|
| Busy line | A request is in progress | Blue block moves left → right | 1s loop | linear |
| Spinner | Loading | Rotation | 800ms loop | linear |
| Switch | Click | Knob slides 18px | 150ms | ease-out |

Modals, toasts, and panels appear without animation (calm PatternFly style). All animations are turned off when `prefers-reduced-motion: reduce`.

## Accessibility Notes

**Focus order.** Masthead (☰ → site selector → Logout) → sidebar menu → page content from top to bottom → action bar. Modals trap focus natively (`<dialog>.showModal()`).

**Keyboard:**
- sidebar menu: Tab/Enter (plain links);
- site selector and toggle group: arrows (native radio);
- combobox: ↑/↓/Enter/Esc;
- search field: Enter to search;
- history row: Enter to open the detail;
- modal: Esc to close (except while applying; Esc in a confirmation = cancel);
- login: Enter to submit.

**ARIA:**
- the active menu uses `aria-current="page"`;
- ☰ uses `aria-expanded`;
- combobox uses `role=combobox`, `aria-expanded`, `aria-controls`, `aria-activedescendant`, and options use `role=option` + `aria-selected`;
- report headers use `aria-sort`;
- KPI uses `aria-pressed`;
- tool buttons use `aria-expanded`;
- loading buttons use `aria-busy`;
- each menu is a section with `aria-labelledby` pointing to its title.

**Labels.** All inputs have a `<label>` or `aria-label`. Table cells use labels based on the row number, for example "VLAN row 3". Icon buttons have an `aria-label`, for example "Delete row 3".

**Announcements.** Toasts are in an `aria-live="polite"` region: error toasts use `role=alert`, other toasts use `role=status`. The range preview and the report result count use `aria-live="polite"`. Login errors use `role=alert`.

**Color is not the only cue.** The site name is always written out. Diff status uses text (New/Changed/Same). Invalid inputs have a reason tooltip and `aria-invalid`.

**Visible focus.** 2px `--pf-primary` outline (white on the masthead and sidebar). Inputs show a 2px primary underline.

/* Guides of the Ops Portal (shared by the modules): at the bottom of a page, a fold "Guide" shows with a short
   animation how that page is used. The animation plays on a miniature of the page AS IT IS NOW: a copy of its own elements,
   dialogs and data, drawn with the page's own functions by the guide definitions of each module (modules/<id>/static/
   guides.js). A cursor moves, clicks, types and picks; the steps are written next to it and each can be replayed. Nothing
   is sent: the miniature is a copy that cannot be clicked (inert), and a guide never calls an API.

   The miniature is drawn W px wide (880 unless the guide says otherwise) and as high as the page gets in any step (never
   cut), then scaled to the card; while it plays, the window follows the cursor (scrolling by hand stops that). It is
   built again each time the guide starts; another page or another site closes the open guides. It plays when the fold is
   opened and stops when it is closed; with "reduce motion" it does not play by itself and shows the end state of a step.

   A module mounts its guides:  PortalGuide.mount({<page>: {title, width?, build()}, ...}, {page: name => <element>})
   Two guides on one page: {page: '<page>', when: () => <shown now?>} on each; PortalGuide.refresh() shows the one that
   applies when the page changes its state (for example the step of a wizard).
   build() (may be async: it may read with the same GET requests the page itself makes, never more) returns
   {title?, html, overlay: [elements], scenes} for the page now, or null (nothing to show yet).
   A scene is {title, text, do: [action, ...]}; an action is [verb, key, ...]. key: the data-g of an element of the copy
   (the ids of the page become data-g, so a key is the id on the page), "@css" for a selector, or an element.
     move key            the cursor goes to the element           click key           the cursor clicks it
     type key text       click, then type into an input            pick key text       choose an option of a select
     check key           tick a checkbox / choose a radio          show key / hide key show or hide an element
     set key html        new content                               cls key name [on]   add (or remove: on=false) a class
     attr key name value an attribute (null: removed)              do fn               fn(screen): any other change
     tip key text        a note next to the element                untip               remove the note
     fill key pct [now]  a progress bar                            count key from to text   a counter (text with {n})
     wait ms             a pause
   PortalGuide.M copies the page: M.clone(el), M.frag(html), M.rows(tr html), M.el(html), M.row(tr html), M.dialog('#id'),
   M.keep(root, sel, n), M.key(el, key). */
(() => {
'use strict';
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
const ICON = {
  play: '<svg class="pg-icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M4 2.5v11l9-5.5z" fill="currentColor"/></svg>',
  pause: '<svg class="pg-icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M4 2.5h3v11H4zM9 2.5h3v11H9z" fill="currentColor"/></svg>',
  again: '<svg class="pg-icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M13 8a5 5 0 1 1-1.5-3.6M13 2.5v3h-3" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  info: '<svg class="pg-icon" viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="6.5" fill="none" stroke="currentColor" stroke-width="1.4"/><path d="M8 7v4.5M8 4.6v.1" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>'
};
const GUIDE_W = 880;
const GUIDE_MAX_W = 2400;   // wider content is drawn smaller, never cut
const GUIDE_T = {move: 600, click: 240, char: 42, typeMax: 1300, gap: 360, hold: 2000, pick: 520};
const CURSOR = '<svg viewBox="0 0 20 24" width="20" height="24" aria-hidden="true"><path d="M2 1.5v18.2l4.6-4.3 3 6.9 3.1-1.3-3-6.8h6.4z" '
  + 'fill="#fff" stroke="#151515" stroke-width="1.4" stroke-linejoin="round"/></svg>';

/* ---------------------------------------------------------------- copies of the page */
const M = {
  n: 0,
  // A copy that does nothing: ids become data-g (inside an SVG they stay: markers refer to them), no focus, no autofill,
  // radios in their own group, fields back to the values of the page source.
  clean(root) {
    const n = ++this.n;
    $$('.pg-section, [data-guide]', root).forEach(x => x.remove());
    [root, ...$$('*', root)].forEach(x => {
      if (x.id && !x.closest('svg')) {
        if (!x.hasAttribute('data-g')) x.setAttribute('data-g', x.id);
        x.removeAttribute('id');
      }
      ['for', 'aria-controls', 'aria-labelledby', 'aria-describedby', 'autofocus', 'required'].forEach(a => x.removeAttribute(a));
      if (x.matches('input[type=radio]')) x.setAttribute('name', `g${n}-${x.getAttribute('name') || 'r'}`);
      else x.removeAttribute('name');
      if (x.matches('a, button, input, select, textarea, summary, [tabindex]')) x.setAttribute('tabindex', '-1');
      if (x.matches('input, textarea')) {
        x.setAttribute('autocomplete', 'off');
        x.setAttribute('data-lpignore', 'true');
        x.setAttribute('data-1p-ignore', '');
        if (x.matches('input[type=checkbox], input[type=radio]')) x.checked = x.defaultChecked;
        else x.value = x.defaultValue;
      }
      if (x.matches('select')) [...x.options].forEach(o => { o.selected = o.defaultSelected; });
    });
    return root;
  },
  clone(el) { return el ? this.clean(el.cloneNode(true)) : null; },
  // markup of the page's own functions, made safe the same way
  frag(markup) {
    const box = document.createElement('div');
    box.innerHTML = markup;
    return this.clean(box).innerHTML;
  },
  el(markup) {
    const box = document.createElement('div');
    box.innerHTML = markup;
    return this.clean(box).firstElementChild;
  },
  row(markup) { return this.el(`<table><tbody>${markup}</tbody></table>`).querySelector('tr'); },
  // table rows of the page's own functions (rows parsed outside a table would lose their cells)
  rows(markup) {
    const table = document.createElement('table');
    table.innerHTML = `<tbody>${markup}</tbody>`;
    return this.clean(table).tBodies[0].innerHTML;
  },
  // a dialog of the page as a box over the miniature (its data-g is the id of the dialog)
  dialog(sel) {
    const d = $(sel);
    const box = document.createElement('div');
    box.className = 'pg-backdrop';
    box.hidden = true;
    box.setAttribute('data-g', d.id);
    const modal = document.createElement('div');
    modal.className = d.className;
    modal.append(...[...(d.querySelector('form') || d).childNodes].map(x => x.cloneNode(true)));
    box.append(modal);
    return this.clean(box);
  },
  keep(root, sel, n) { $$(sel, root).slice(n).forEach(x => x.remove()); },
  key(el, key) { if (el) el.setAttribute('data-g', key); return el; },
};

class GuidePlayer {
  constructor(det, def) {
    this.det = det;
    this.def = def;
    this.g = null;
    this.ready = Promise.resolve();
    this.token = 0;
    this.scene = 0;
    this.playing = false;
    this.k = 1;
    this.W = def.width || GUIDE_W;
    this.H = 450;
    const body = $('.pg-fold__body', det);
    body.innerHTML = '<div class="pg-guide">'
      + '<div class="pg-guide__player"><div class="pg-guide__stage" aria-hidden="true" inert><div class="pg-guide__screen">'
      + '<div class="pg-guide__page"></div><div class="pg-guide__overlay"></div>'
      + `<div class="pg-guide__cursor">${CURSOR}</div><div class="pg-guide__caption" hidden></div></div></div>`
      + '<div class="pg-guide__controls">'
      + `<button type="button" class="pg-btn" data-g-play>${ICON.play}<span>Play</span></button>`
      + `<button type="button" class="pg-btn pg-btn--link" data-g-restart>${ICON.again}Start again</button>`
      + '<span class="pg-guide__track"><span class="pg-guide__fill"></span></span>'
      + '<span class="pg-guide__count" data-g-count aria-live="polite"></span></div></div>'
      + '<ol class="pg-guide__scenes"></ol></div>';
    this.stage = $('.pg-guide__stage', body);
    this.screen = $('.pg-guide__screen', body);
    this.page = $('.pg-guide__page', body);
    this.overlay = $('.pg-guide__overlay', body);
    this.cursor = $('.pg-guide__cursor', body);
    this.caption = $('.pg-guide__caption', body);
    this.list = $('.pg-guide__scenes', body);
    this.playBtn = $('[data-g-play]', body);
    this.playBtn.addEventListener('click', () => {
      if (this.playing) this.stop();
      else if (!this.g || this.scene >= this.g.scenes.length) this.play(0, true);
      else this.play(this.scene, false);
    });
    $('[data-g-restart]', body).addEventListener('click', () => this.play(0, true));
    this.list.addEventListener('click', e => {
      const b = e.target.closest('[data-g-scene]');
      if (b) this.play(Number(b.dataset.gScene), false);
    });
    new ResizeObserver(() => this.fit()).observe(this.stage);
    // while it plays, the window follows the cursor; scrolling by hand stops that until the next play
    this.follow = true;
    const manual = () => { if (this.playing) this.follow = false; };
    ['wheel', 'touchmove'].forEach(ev => window.addEventListener(ev, manual, {passive: true}));
    window.addEventListener('keydown', e => { if (['PageUp', 'PageDown', 'ArrowUp', 'ArrowDown', 'Home', 'End', ' '].includes(e.key)) manual(); });
  }
  // ---------------------------------------------------------------- building
  async load() {
    let g = null;
    this.page.innerHTML = '<div class="pg-empty"><b>Reading the page…</b></div>';
    try { g = await this.def.build(); } catch (e) { console.error('guide', e); }
    this.g = g && g.scenes.length ? g : null;
    this.scene = 0;
    if (!this.g) {
      this.page.innerHTML = '<div class="pg-empty"><b>Nothing to show yet</b><span>Open the guide again once the page has loaded.</span></div>';
      this.overlay.innerHTML = '';
      this.list.innerHTML = '';
      $('[data-g-count]', this.det).textContent = '';
      this.H = 200;
      this.fit();
      return false;
    }
    $('[data-g-title]', this.det).textContent = `Guide: ${this.g.title || this.def.title}`;
    this.list.innerHTML = this.g.scenes.map((s, i) => `<li><button type="button" data-g-scene="${i}">`
      + `<span class="pg-guide__n">${i + 1}</span><span class="pg-guide__text"><b>${esc(s.title)}</b><span>${s.text}</span></span>`
      + '</button></li>').join('');
    this.ready = this.measure();
    return true;
  }
  // as wide and as high as the page gets in any step, so nothing is ever cut
  async measure() {
    this.W = this.def.width || GUIDE_W;
    for (let pass = 0; pass < 3; pass++) {
      const token = ++this.token;
      this.screen.style.width = `${this.W}px`;   // the height follows the width the miniature is drawn at
      this.reset();
      let h = this.height(), w = this.width();
      for (let i = 0; i < this.g.scenes.length; i++) {
        try { await this.runScene(i, token, true); } catch (e) { if (e !== GuidePlayer.STOP) console.error('guide', e); }
        h = Math.max(h, this.height());
        w = Math.max(w, this.width());
      }
      this.H = Math.ceil(Math.max(h, 320));
      if (w <= this.W + 1 || this.W >= GUIDE_MAX_W) break;
      this.W = Math.min(GUIDE_MAX_W, Math.ceil(w + 16));   // wider, then measured again at that width
    }
    this.fit();
    this.reset();
  }
  // the width that shows all of it: a table wider than its box would be cut (its box scrolls sideways on the page)
  width() {
    let w = Math.max(this.W, this.page.scrollWidth);
    for (const el of $$('*', this.screen)) {
      // a dialog keeps its own width: a wider miniature would not change it
      if (el.scrollWidth <= el.clientWidth + 1 || el.closest('pre, textarea, input, .pg-guide__cursor, .pg-guide__overlay')) continue;
      const css = getComputedStyle(el);
      // only boxes that scroll sideways on the page (a wide table); clipped text (…, screen-reader text) is meant
      if (!['auto', 'scroll'].includes(css.overflowX) || css.whiteSpace === 'pre' || el.clientWidth < 40) continue;
      w = Math.max(w, this.W + el.scrollWidth - el.clientWidth);
    }
    return w;
  }
  height() {
    const boxes = $$('.pg-backdrop:not([hidden]) > *, .pg-flowwrap:not([hidden]) .pg-flowcard', this.overlay).map(m => m.scrollHeight + 48);
    return Math.max(this.page.scrollHeight, ...boxes);
  }
  // the whole miniature, as wide as the card (never cut); the window follows the cursor while it plays
  fit() {
    this.k = (this.stage.clientWidth || this.W) / this.W;
    this.screen.style.width = `${this.W}px`;
    this.screen.style.height = `${this.H}px`;
    this.screen.style.transform = `scale(${this.k})`;
    this.stage.style.height = `${Math.round(this.H * this.k)}px`;
  }
  // the part of the miniature in the window (its own pixels)
  band() {
    const s = this.stage.getBoundingClientRect();
    const top = Math.min(this.H, Math.max(0, (70 - s.top) / this.k));
    const bottom = Math.max(top + 240, Math.min(this.H, (window.innerHeight - s.top) / this.k));
    return {top, bottom: Math.min(this.H, bottom)};
  }
  // keep a part of the miniature in the window while it plays: all of it when it fits, else its top
  async view(p, token) {
    if (!this.follow) return;
    const s = this.stage.getBoundingClientRect();
    const top = 70, room = window.innerHeight - top - 40;
    const y = s.top + p.y * this.k, h = p.h * this.k;
    if (y >= top && y + Math.min(h, room) <= top + room) return;
    const to = h <= room ? y - top - (room - h) / 2 : y - top;
    window.scrollBy({top: to, behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth'});
    let last = NaN, still = 0;   // on once the window stands still (a smooth scroll takes its time)
    for (let i = 0; i < 50 && still < 3; i++) {
      await this.sleep(50, token);
      if (Math.abs(window.scrollY - last) < 1) still++; else { still = 0; last = window.scrollY; }
    }
  }
  reset() {
    this.page.innerHTML = this.g ? this.g.html : '';
    this.overlay.replaceChildren(...(this.g?.overlay || []).map(x => x.cloneNode(true)));
    $$('.pg-tip, .pg-menu, .pg-ring', this.screen).forEach(x => x.remove());
    this.place(this.W * 0.7, Math.min(this.H, 500) * 0.7, true);
    this.caption.hidden = true;
  }
  // ---------------------------------------------------------------- playing
  async play(from = 0, rebuild = false) {
    if ((rebuild || !this.g) && !(await this.load())) return;
    await this.ready;
    const token = ++this.token;
    const n = this.g.scenes.length;
    const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
    this.playing = true;
    this.follow = true;
    this.buttons();
    try {
      this.reset();
      for (let i = 0; i < from; i++) await this.runScene(i, token, true);
      for (let i = from; i < n; i++) {
        this.scene = i;
        this.mark(i, true);
        this.say(i);
        await this.runScene(i, token, reduced);
        this.progress((i + 1) / n);
        await this.sleep(reduced ? 3500 : GUIDE_T.hold, token);
      }
      this.scene = n;
      this.mark(n, false);
      this.caption.hidden = true;
    } catch (e) {
      if (e !== GuidePlayer.STOP) console.error('guide', e);
      return;
    }
    this.playing = false;
    this.buttons();
  }
  stop() {
    this.token++;
    this.playing = false;
    this.buttons();
  }
  // the page changed (another check, run or site): built again from it when the guide opens
  forget() {
    this.stop();
    this.g = null;
    this.scene = 0;
  }
  async showEnd(i) {   // reduced motion, on opening: the end state of the first step, nothing moves
    if (!(await this.load())) return;
    await this.ready;
    const token = ++this.token;
    this.reset();
    try { await this.runScene(i, token, true); } catch (e) { return; }
    this.mark(i, false);
    this.say(i);
    this.buttons();
  }
  buttons() {
    const end = !this.g || this.scene >= this.g.scenes.length;
    this.playBtn.innerHTML = this.playing ? `${ICON.pause}<span>Pause</span>`
      : `${ICON.play}<span>${end && this.g ? 'Play again' : this.scene > 0 ? 'Continue' : 'Play'}</span>`;
  }
  mark(i, running) {
    const n = this.g.scenes.length;
    $$('[data-g-scene]', this.list).forEach((b, k) => {
      b.parentElement.classList.toggle('is-done', k < i);
      b.parentElement.classList.toggle('is-current', k === i && i < n);
      if (k === i && i < n) b.setAttribute('aria-current', 'step'); else b.removeAttribute('aria-current');
    });
    $('[data-g-count]', this.det).textContent = i >= n ? `Done: ${n} steps` : `Step ${i + 1} of ${n}`;
    this.progress((running ? i + 0.15 : i) / n);
  }
  progress(x) { $('.pg-guide__fill', this.det).style.width = `${Math.max(0, Math.min(1, x)) * 100}%`; }
  say(i) {
    this.caption.innerHTML = `<b>${i + 1}</b>${esc(this.g.scenes[i].title)}`;
    this.caption.hidden = false;
  }
  sleep(ms, token, fast = false) {
    if (fast) return token === this.token ? Promise.resolve() : Promise.reject(GuidePlayer.STOP);
    return new Promise((resolve, reject) => setTimeout(() => {
      if (token !== this.token) return reject(GuidePlayer.STOP);
      if (!this.det.open || !this.det.offsetParent) {   // closed, or another page: stop where it is
        this.stop();
        return reject(GuidePlayer.STOP);
      }
      resolve();
    }, ms));
  }
  async runScene(i, token, fast) {
    for (const a of this.g.scenes[i].do) {
      await this.act(a, token, fast);
      if (!fast && !['wait', 'do', 'set', 'cls', 'attr', 'hide', 'untip'].includes(a[0])) await this.sleep(GUIDE_T.gap, token);
    }
  }
  // ---------------------------------------------------------------- actions
  el(key) {
    const el = key instanceof Element ? key
      : this.screen.querySelector(String(key).startsWith('@') ? String(key).slice(1) : `[data-g="${key}"]`);
    if (!el) throw new Error(`guide "${this.def.title}": no element ${key}`);
    return el;
  }
  // what the user sees of a field: a select the page draws as another field (a searchable combobox on a hidden select),
  // a radio or checkbox hidden in its label (toggle buttons)
  face(el) {
    if (el.offsetWidth > 4 || !el.matches('select, input')) return el;
    if (el.tagName === 'SELECT') return el.parentElement.querySelector('input:not([type=hidden]), button, [role=combobox]') || el;
    return el.closest('label') || el.parentElement || el;
  }
  async act(a, token, fast) {
    const [verb, key, ...args] = a;
    const sleep = ms => this.sleep(ms, token, fast);
    if (verb === 'wait') return sleep(key);
    if (verb === 'do') return key(this.screen);
    if (verb === 'untip') return $$('.pg-tip', this.screen).forEach(x => x.remove());
    const el = this.el(key);
    switch (verb) {
      case 'move':
        return this.reach(this.face(el), token, fast);
      case 'click':
      case 'check':
        await this.reach(this.face(el), token, fast);
        await this.press(this.face(el), token, fast);
        if (el.matches('input[type=radio]')) el.checked = true;
        else if (el.matches('input[type=checkbox]')) el.checked = !el.checked;
        return;
      case 'type': {
        await this.reach(el, token, fast);
        await this.press(el, token, fast);
        const text = String(args[0]);
        el.classList.add('pg-focus');
        if (fast) el.value = text;
        else {
          el.value = '';
          const per = Math.min(GUIDE_T.char, GUIDE_T.typeMax / Math.max(1, text.length));
          for (let n = 1; n <= text.length; n++) {
            el.value = text.slice(0, n);
            if (el.scrollWidth > el.clientWidth) el.scrollLeft = el.scrollWidth;
            await sleep(per);
          }
        }
        el.classList.remove('pg-focus');
        return;
      }
      case 'pick': {
        const value = args[0];
        const face = this.face(el);
        if (face !== el && face.matches('input')) {   // the field says what its list holds now, as the page's own does
          face.disabled = false;
          face.placeholder = [...el.options].find(o => !o.value)?.text || face.placeholder;
        }
        await this.reach(face, token, fast);
        await this.press(face, token, fast);
        if (!fast) {   // the list opens under the field, as a select does
          const menu = document.createElement('div');
          menu.className = 'pf-menu pg-menu';
          const options = [...el.options];
          const at = Math.max(0, options.findIndex(o => o.text === value) - 6);
          menu.innerHTML = options.slice(at, at + 8).map(o => `<div class="pf-menu__item${o.text === value ? ' pg-pick' : ''}">${esc(o.text)}</div>`).join('');
          const p = this.box(face);
          Object.assign(menu.style, {left: `${p.x}px`, top: `${p.y + p.h + 2}px`, minWidth: `${p.w}px`});
          this.screen.insertBefore(menu, this.cursor);
          await sleep(GUIDE_T.pick);
          const target = $('.pg-pick', menu);
          if (target) {
            await this.reach(target, token, fast);
            target.classList.add('is-hover');
            await this.press(target, token, fast);
          }
          menu.remove();
        }
        [...el.options].forEach(o => { o.selected = o.text === value; });
        if (face !== el && face.matches('input')) face.value = value;
        return;
      }
      case 'show':
        el.hidden = false;
        if (!fast && el.matches('.pg-backdrop, .pg-flowwrap')) {
          const b = this.band(), h = el.firstElementChild.offsetHeight;
          el.style.paddingTop = `${Math.max(12, Math.min(this.H - h - 12, b.top + (b.bottom - b.top - h) / 2))}px`;
          await this.view(this.box(el.firstElementChild), token);
        }
        if (!fast && el.matches('.pg-toast')) el.style.top = `${this.band().top + 12}px`;
        if (!fast) {
          el.classList.remove('pg-in');
          void el.offsetWidth;
          el.classList.add('pg-in');
        }
        return;
      case 'hide':
        el.hidden = true;
        return;
      case 'set':
        el.innerHTML = args[0];
        return;
      case 'cls':
        el.classList.toggle(args[0], args[1] !== false);
        return;
      case 'attr':
        if (args[1] === null) el.removeAttribute(args[0]); else el.setAttribute(args[0], args[1]);
        return;
      case 'tip': {
        $$('.pg-tip', this.screen).forEach(x => x.remove());
        if (fast || !args[0]) return;
        const tip = document.createElement('div');
        const p = this.box(this.face(el));
        tip.className = 'pg-tip';
        tip.innerHTML = args[0];
        this.screen.insertBefore(tip, this.cursor);
        const below = p.y + p.h + tip.offsetHeight + 16 < this.H || p.y < tip.offsetHeight + 16;
        tip.classList.add(below ? 'is-below' : 'is-above');
        const at = p.x + Math.min(p.w, 160) / 2;
        const left = Math.max(8, Math.min(this.W - tip.offsetWidth - 8, at - 24));
        tip.style.left = `${left}px`;
        tip.style.top = below ? `${p.y + p.h + 10}px` : `${p.y - tip.offsetHeight - 10}px`;
        tip.style.setProperty('--arrow', `${Math.max(12, Math.min(tip.offsetWidth - 12, at - left))}px`);
        return this.view({y: Math.min(p.y, parseFloat(tip.style.top)), h: p.h + tip.offsetHeight + 10}, token);
      }
      case 'fill': {
        const box = el.closest('[data-g-progress], .wi-progress, .pf-progress, .progress') || el;   // a progress bar of the page
        const bar = $('[data-fill], .wi-progress__fill, .pf-progress__indicator, .progress__fill, .progress-bar', box) || box;
        bar.style.width = `${args[0]}%`;
        const pct = $('[data-pct], .wi-progress__pct, .pf-progress__measure', box);
        if (pct) pct.textContent = `${args[0]}%`;
        if (args[1] && $('[data-now]', box)) $('[data-now]', box).textContent = args[1];
        return sleep(650);
      }
      case 'count': {
        const [from, to, text] = args;
        if (fast) { el.textContent = text.replace('{n}', to); return; }
        const steps = Math.max(1, Math.min(Math.abs(from - to), 15));
        for (let s = 0; s <= steps; s++) {
          el.textContent = text.replace('{n}', Math.round(from + (to - from) * s / steps));
          await sleep(1800 / steps);
        }
        return;
      }
      default:
        throw new Error(`guide: unknown action ${verb}`);
    }
  }
  box(el) {   // the element in the miniature's own pixels
    const s = this.screen.getBoundingClientRect(), r = el.getBoundingClientRect(), k = this.k || 1;
    return {x: (r.left - s.left) / k, y: (r.top - s.top) / k, w: r.width / k, h: r.height / k};
  }
  place(x, y, fast) {
    this.cursor.classList.toggle('is-instant', !!fast);
    this.cursor.style.transform = `translate(${Math.round(x)}px, ${Math.round(y)}px)`;
    if (fast) void this.cursor.offsetWidth;
  }
  async reach(el, token, fast) {
    if (fast) return this.sleep(0, token, true);
    if (el.matches('.pf-toggle-group input')) el = el.nextElementSibling;   // the input itself is hidden
    const body = el.closest('.pf-modal__body, .modal-body');   // a long dialog: its body scrolls to the field
    if (body) {
      const b = this.box(body), p = this.box(el);
      if (p.y < b.y || p.y + p.h > b.y + b.h) {
        body.scrollTop += p.y - b.y - 16;
        await this.sleep(250, token);
      }
    }
    const p = this.box(el);
    const modal = el.closest('.pg-backdrop > *');   // in a dialog: keep the whole dialog in view
    await this.view(modal && modal.offsetHeight * this.k < window.innerHeight - 110 ? this.box(modal) : p, token);
    const small = el.matches('input[type=radio], input[type=checkbox]');
    const x = small ? p.x + p.w / 2 : p.x + Math.min(p.w / 2, el.matches('input, select, textarea') ? 36 : 80);
    this.place(x - 2, p.y + Math.min(p.h / 2, 18) - 2, false);
    await this.sleep(GUIDE_T.move, token);
  }
  async press(el, token, fast) {
    if (fast) return;
    const p = this.box(this.cursor);
    const ring = document.createElement('span');
    ring.className = 'pg-ring';
    Object.assign(ring.style, {left: `${p.x + 2}px`, top: `${p.y + 2}px`});
    this.screen.insertBefore(ring, this.cursor);
    el.classList.add('pg-pressed');
    await this.sleep(GUIDE_T.click, token);
    el.classList.remove('pg-pressed');
    setTimeout(() => ring.remove(), 500);
  }
}
GuidePlayer.STOP = Symbol('stop');

const Guide = {
  players: {},
  defs: {},
  // another page, check, run or site: the open guides close (their copy is of the page before)
  changed() {
    $$('details[data-guide][open]').forEach(d => { d.open = false; });
    Object.values(this.players).forEach(p => p.forget());
  },
  // guides with when(): shown only while it applies; one that is hidden closes
  refresh() {
    Object.entries(this.defs).forEach(([name, def]) => {
      const det = def.when && $(`details[data-guide="${name}"]`);
      if (!det) return;
      const on = Boolean(def.when());
      if (det.parentElement.hidden !== on) return;
      det.parentElement.hidden = !on;
      if (!on && det.open) det.open = false;
      if (!on) this.players[name]?.forget();
    });
  },
  mount(defs, {page}) {
    Object.assign(this.defs, defs);
    const start = () => Object.entries(defs).forEach(([name, def]) => {
      const host = page(def.page || name);
      if (!host || $(`[data-guide="${name}"]`, host)) return;
      const section = document.createElement('section');
      section.className = 'pf-page__section pg-section';
      section.hidden = Boolean(def.when) && !def.when();
      section.innerHTML = `<details class="pg-fold" data-guide="${name}"><summary><span class="pg-fold__title">${ICON.info}`
        + `<span data-g-title>Guide: ${esc(def.title)}</span></span><span class="pg-fold__meta">Animated, on this page as it is now</span></summary>`
        + '<div class="pg-fold__body"></div></details>';
      host.appendChild(section);   // last, also after a sticky action bar (which then never covers it)
      const det = section.firstElementChild;
      det.addEventListener('toggle', () => {
        if (!det.open) return this.players[name]?.stop();
        const player = this.players[name] || (this.players[name] = new GuidePlayer(det, def));
        requestAnimationFrame(() => det.scrollIntoView({block: 'start', behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth'}));
        if (matchMedia('(prefers-reduced-motion: reduce)').matches) player.showEnd(0);
        else player.play(0, true);
      });
    });
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
  },
  init() {
    window.addEventListener('hashchange', () => this.changed());
    document.addEventListener('change', e => { if (e.target.closest('#siteSwitch')) this.changed(); });
  },
};
Guide.init();
window.PortalGuide = {M, Player: GuidePlayer, mount: (defs, opts) => Guide.mount(defs, opts), changed: () => Guide.changed(), refresh: () => Guide.refresh()};
})();

// Minimal Chrome DevTools Protocol driver for the WI screenshots (headless Chrome, Node 22 WebSocket, no packages).
// Usage: node tools/wi/cdp.mjs <scenario.mjs> <output folder>
import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const sleep = ms => new Promise(r => setTimeout(r, ms));

export async function launch({ port = 9333, width = 1440, height = 900 } = {}) {
  const profile = mkdtempSync(join(tmpdir(), 'cdp-'));
  const proc = spawn(CHROME, [
    '--headless=new', '--disable-gpu', '--hide-scrollbars', '--no-first-run', '--no-default-browser-check',
    `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`, `--window-size=${width},${height}`,
    '--force-device-scale-factor=1', '--lang=en-US', '--ignore-certificate-errors', 'about:blank',
  ], { stdio: 'ignore' });
  let targets = [];
  for (let i = 0; i < 100; i++) {
    try {
      targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      if (targets.some(t => t.type === 'page')) break;
    } catch { /* not up yet */ }
    await sleep(100);
  }
  const page = targets.find(t => t.type === 'page');
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((ok, fail) => { ws.onopen = ok; ws.onerror = fail; });
  let id = 0;
  const waiting = new Map();
  ws.onmessage = ev => {
    const msg = JSON.parse(ev.data);
    if (msg.id && waiting.has(msg.id)) {
      const { ok, fail } = waiting.get(msg.id);
      waiting.delete(msg.id);
      if (msg.error) fail(new Error(`${msg.error.message} ${msg.error.data || ''}`)); else ok(msg.result);
    }
  };
  const send = (method, params = {}) => new Promise((ok, fail) => {
    const mid = ++id;
    waiting.set(mid, { ok, fail });
    ws.send(JSON.stringify({ id: mid, method, params }));
  });
  await send('Page.enable');
  await send('Runtime.enable');
  await send('Network.enable');
  await send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: false });
  await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: 'light' }] });

  const b = {
    send, width, height, sleep,
    async close() { try { ws.close(); } catch { /* ignore */ } proc.kill('SIGKILL'); },
    async cookie(url, name, value) { await send('Network.setCookie', { url, name, value, path: '/' }); },
    async goto(url, settle = 800) {
      await send('Page.navigate', { url });
      await b.waitFor('document.readyState === "complete"', 15000);
      await sleep(settle);
    },
    async eval(expression) {
      const r = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
      if (r.exceptionDetails) throw new Error(`eval failed: ${r.exceptionDetails.exception?.description || r.exceptionDetails.text}\n${expression.slice(0, 300)}`);
      return r.result.value;
    },
    async waitFor(condition, timeout = 20000) {
      const until = Date.now() + timeout;
      while (Date.now() < until) {
        try { if (await b.eval(`Boolean(${condition})`)) return true; } catch { /* page changing */ }
        await sleep(200);
      }
      throw new Error(`timeout waiting for: ${condition}`);
    },
    // Red outline + numbered badge (the WI steps refer to the numbers). A badge of an element in a modal dialog goes
    // inside the dialog: the dialog is drawn in the top layer, above anything in <body>.
    async mark(items) {
      await b.eval(`(() => {
        for (const [sel, label] of ${JSON.stringify(items)}) {
          const el = document.querySelector(sel);
          if (!el) throw new Error('mark: not found ' + sel);
          el.dataset.wiMark = '1';
          el.style.outline = '3px solid #d9001b';
          el.style.outlineOffset = '2px';
          if (!label) continue;
          const r = el.getBoundingClientRect();
          const dlg = el.closest('dialog[open]');
          const host = dlg || document.body;
          const o = dlg ? dlg.getBoundingClientRect() : {left: -window.scrollX, top: -window.scrollY};
          const sx = dlg ? dlg.scrollLeft - dlg.clientLeft : 0, sy = dlg ? dlg.scrollTop - dlg.clientTop : 0;
          const tag = document.createElement('div');
          tag.className = 'wi-badge';
          tag.textContent = label;
          Object.assign(tag.style, {position: 'absolute', left: Math.max(2, r.left - o.left + sx - 14) + 'px',
            top: Math.max(2, r.top - o.top + sy - 14) + 'px', width: '26px', height: '26px', borderRadius: '50%',
            background: '#d9001b', color: '#fff', font: '700 14px/26px Arial, sans-serif', textAlign: 'center',
            zIndex: 99999, boxShadow: '0 0 0 2px #fff'});
          host.appendChild(tag);
        }
      })()`);
    },
    async unmark() {
      await b.eval(`(() => { document.querySelectorAll('.wi-badge').forEach(e => e.remove());
        document.querySelectorAll('[data-wi-mark]').forEach(e => { e.style.outline = ''; e.style.outlineOffset = ''; delete e.dataset.wiMark; }); })()`);
    },
    // Page coordinates from the top of `top` to the top of `bottom` (or the bottom of `top`), across `frame`.
    async area(frame, top, bottom = null, pad = 12) {
      return b.eval(`(() => { const q = s => { const e = document.querySelector(s); if (!e) throw new Error('area: not found ' + s); return e.getBoundingClientRect(); };
        const f = q(${JSON.stringify(frame)}), t = q(${JSON.stringify(top)}), e = ${JSON.stringify(bottom)} ? q(${JSON.stringify(bottom)}) : null;
        const y0 = t.top + window.scrollY - ${pad}, y1 = (e ? e.top : t.bottom) + window.scrollY + (e ? -4 : ${pad});
        return {x: Math.max(0, f.left + window.scrollX - ${pad}), y: Math.max(0, y0), width: f.width + 2 * ${pad}, height: y1 - Math.max(0, y0)}; })()`);
    },
    // Screenshot of the viewport, of the box of a selector (page coordinates, with padding), of a page area (page:
    // true) or of an explicit viewport clip. Page captures scroll to the top and hide bars that stick to the viewport.
    async shot(path, { selector, pad = 12, clip, full = false, page = false, maxHeight = 2400, hide = ['.actionbar', '#toasts'] } = {}) {
      let c = clip;
      if (selector || full || page) {
        await b.eval(`(() => { window.scrollTo(0, 0); for (const s of ${JSON.stringify(hide)}) document.querySelectorAll(s).forEach(e => { e.dataset.wiHidden = e.style.visibility; e.style.visibility = 'hidden'; }); })()`);
        await sleep(150);
      }
      if (selector) {
        c = await b.eval(`(() => { const el = document.querySelector(${JSON.stringify(selector)}); if (!el) return null;
          const r = el.getBoundingClientRect(); return {x: r.left + window.scrollX, y: r.top + window.scrollY, width: r.width, height: r.height}; })()`);
        if (!c) throw new Error('shot: not found ' + selector);
        c = { x: Math.max(0, c.x - pad), y: Math.max(0, c.y - pad), width: c.width + 2 * pad, height: Math.min(maxHeight, c.height + 2 * pad) };
      } else if (full) {
        c = { x: 0, y: 0, width: b.width, height: await b.eval(`Math.min(document.documentElement.scrollHeight, ${maxHeight})`) };
      }
      const params = { format: 'png', captureBeyondViewport: Boolean(c) };
      if (c) params.clip = { ...c, scale: 1 };
      const r = await send('Page.captureScreenshot', params);
      writeFileSync(path, Buffer.from(r.data, 'base64'));
      await b.eval(`document.querySelectorAll('[data-wi-hidden]').forEach(e => { e.style.visibility = e.dataset.wiHidden; delete e.dataset.wiHidden; })`);
      return path;
    },
  };
  return b;
}

// Run a scenario module: export default async (b, out) => { ... }
if (process.argv[1] && process.argv[1].endsWith('cdp.mjs') && process.argv[2]) {
  const scenario = (await import(pathToFileURL(resolve(process.argv[2])).href)).default;
  const out = process.argv[3];
  mkdirSync(out, { recursive: true });
  const b = await launch({ port: Number(process.env.CDP_PORT || 9333) });
  try {
    await scenario(b, out);
  } catch (e) {
    console.error('SCENARIO FAILED:', e.message);
    try { await b.shot(join(out, '_error.png')); } catch { /* ignore */ }
    process.exitCode = 1;
  } finally {
    await b.close();
  }
}

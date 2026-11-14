// @vitest-environment jsdom
// NOTE: an http(s) URL on purpose. A chrome-extension:// origin is opaque in jsdom and makes the
// environment throw "localStorage is not available for opaque origins" on Node 20 (what CI runs).
// @vitest-environment-options {"url":"http://localhost/blocked.html?reason=user-blocklist&host=evil.test"}
import { describe, it, expect, beforeEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { loadCore } from './helpers/load-core.js';

const root = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'blocked.html'), 'utf8');
const script = fs.readFileSync(path.join(root, 'blocked.js'), 'utf8');

const INFO = {
  host: 'evil.test', trusted: false, inBlocklist: true,
  auto: { at: 1, reason: 'auto-blocked at risk 82% (threshold 75%)' },
  report: { risk: 82, verdict: 'malicious', flagged: 3, malicious: 9, suspicious: 2, categories: [], scannedAt: 1 },
  thresholds: { autoBlock: 75 }, profile: null
};

function boot({ framed = false, confirmAnswer = true, response = { ok: true, steps: [] } } = {}) {
  document.documentElement.innerHTML = html.replace(/<script[\s\S]*?<\/script>/g, '');
  const sent = [];
  const chromeMock = { runtime: {
    sendMessage: async (msg) => {
      sent.push(msg);
      if (msg.type === 'get-block-info') return { ok: true, info: INFO };
      if (msg.type === 'block-page-action') return response;
      return { ok: true };
    },
    getURL: (p) => 'chrome-extension://abc/' + p
  } };
  const self = {};
  const win = { top: framed ? {} : self, self, confirm: () => confirmAnswer, CorsairI18n: undefined };

  // jsdom does not let a test forge `isTrusted`, so capture the click handlers and call them
  // with a "real" ({isTrusted:true}) or a "script-made" ({isTrusted:false}) event.
  const handlers = {};
  const orig = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function (type, fn, o) { if (type === 'click' && this.id) handlers[this.id] = fn; return orig.call(this, type, fn, o); };
  try {
    new Function('window', 'document', 'location', 'history', 'chrome', 'setTimeout', script)(win, document, window.location, window.history, chromeMock, (fn) => 0);
  } finally { EventTarget.prototype.addEventListener = orig; }
  current = handlers;
  return { sent, win, handlers };
}
let current = {};

const click = async (id, trusted = true) => {
  const h = current[id];
  if (h) await h({ isTrusted: trusted });
  await new Promise(r => setTimeout(r, 15));
};

describe('block page: explanation', () => {
  it('explains an automatic block with the real numbers', async () => {
    boot();
    await new Promise(r => setTimeout(r, 30));
    const text = document.getElementById('whyList').textContent;
    expect(text).toContain('82%');
    expect(text).toContain('75%');
    expect(text).toContain('3 engine(s)');
    expect(text).toContain('malicious');
  });

  it('shows the three actions plus leave / dashboard', () => {
    boot();
    for (const id of ['proceedBtn', 'fpBtn', 'wipeBtn', 'escapeBtn', 'dashboardBtn']) expect(document.getElementById(id), id).not.toBeNull();
    expect(document.getElementById('choices').hidden).toBe(false);
  });
});

describe('block page: actions', () => {
  beforeEach(() => {});

  it('"back to the site, Fortress ON" sends the right message for the shown host', async () => {
    const { sent } = boot();
    await click('proceedBtn');
    expect(sent.filter(m => m.type === 'block-page-action')).toEqual([{ type: 'block-page-action', action: 'proceed-fortress', host: 'evil.test' }]);
  });

  it('false positive and block+wipe ask for confirmation first', async () => {
    let r = boot({ confirmAnswer: false });
    await click('fpBtn'); await click('wipeBtn');
    expect(r.sent.some(m => m.type === 'block-page-action')).toBe(false);

    r = boot({ confirmAnswer: true });
    await click('fpBtn');
    expect(r.sent.find(m => m.type === 'block-page-action')).toMatchObject({ action: 'false-positive', host: 'evil.test' });
    r = boot({ confirmAnswer: true });
    await click('wipeBtn');
    expect(r.sent.find(m => m.type === 'block-page-action')).toMatchObject({ action: 'block-wipe', host: 'evil.test' });
  });

  it('SECURITY: a click synthesised by a script (isTrusted=false) does nothing', async () => {
    const { sent } = boot();
    for (const id of ['proceedBtn', 'fpBtn', 'wipeBtn']) await click(id, false);
    expect(sent.some(m => m.type === 'block-page-action')).toBe(false);
  });

  it('SECURITY: framed inside another page, the actions are hidden, ignored and never reach the background', async () => {
    const { sent } = boot({ framed: true });
    await new Promise(r => setTimeout(r, 30));
    expect(document.getElementById('choices').hidden).toBe(true);
    expect(document.getElementById('statusBox').textContent).toMatch(/opened by itself/);
    for (const id of ['proceedBtn', 'fpBtn', 'wipeBtn']) await click(id);
    expect(sent.some(m => m.type === 'block-page-action' || m.type === 'get-block-info')).toBe(false);
  });

  it('reports a failure instead of pretending it worked', async () => {
    boot({ response: { ok: false, error: 'unblock: dnr-sync-failed', steps: [] } });
    await click('proceedBtn');
    const box = document.getElementById('statusBox');
    expect(box.className).toContain('bad');
    expect(box.textContent).toContain('dnr-sync-failed');
    expect(document.getElementById('proceedBtn').disabled).toBe(false);
  });

  it('keeps the page open and lists the failed step when the wipe did not fully work', async () => {
    boot({ response: { ok: true, newTab: true, navigated: false, steps: [{ name: 'block', ok: true }, { name: 'wipe-site-data', ok: false, error: 'browsingData-unavailable' }] } });
    await click('wipeBtn');
    const box = document.getElementById('statusBox');
    expect(box.className).toContain('warn');
    expect(box.textContent).toContain('wipe-site-data');
  });
});

describe('who may trigger block-page actions (core/block-actions.js)', () => {
  beforeEach(() => loadCore('core/block-actions.js'));
  const base = 'chrome-extension://abc/blocked.html';
  const opts = { baseUrl: base, normalizeHostname: (h) => String(h || '').toLowerCase().replace(/^www\./, '') };
  const ok = { frameId: 0, tab: { id: 4 }, url: `${base}?reason=user-blocklist&host=evil.test` };

  it('accepts the top frame of our block page for the host it shows', () => {
    expect(CorsairBlockActions.isBlockPageSender(ok, 'evil.test', opts)).toBe(true);
    expect(CorsairBlockActions.isBlockPageSender(ok, 'WWW.evil.test', opts)).toBe(true);
  });

  it('refuses frames, other pages, other hosts and lookalike URLs', () => {
    const f = (s, h = 'evil.test') => CorsairBlockActions.isBlockPageSender(s, h, opts);
    expect(f({ ...ok, frameId: 3 })).toBe(false);                                        // iframe
    expect(f({ ...ok, tab: undefined })).toBe(false);                                    // not in a tab
    expect(f({ ...ok, url: 'chrome-extension://abc/dashboard.html?host=evil.test' })).toBe(false);
    expect(f({ ...ok, url: 'chrome-extension://other/blocked.html?host=evil.test' })).toBe(false);
    expect(f({ ...ok, url: `${base}.evil.example/?host=evil.test` })).toBe(false);        // blocked.html.evil...
    expect(f({ ...ok, url: 'https://evil.test/' })).toBe(false);                         // a web page
    expect(f(ok, 'bank.example')).toBe(false);                                           // action for another host
    expect(f(ok, '')).toBe(false);
    expect(f(null)).toBe(false);
  });
});

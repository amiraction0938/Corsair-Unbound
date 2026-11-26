import { describe, it, expect, beforeEach } from 'vitest';
import vm from 'node:vm';
import { installChromeMock } from './helpers/chrome-mock.js';
import { loadCore, readSource } from './helpers/load-core.js';

function installUserScriptsMock() {
  const regs = new Map();
  const calls = [];
  const executed = [];
  globalThis.chrome.userScripts = {
    async getScripts() { return Array.from(regs.values()).map(r => ({ ...r })); },
    async register(list) {
      for (const r of list) {
        if (regs.has(r.id)) throw new Error('Duplicate script ID');
        regs.set(r.id, r);
        calls.push(['register', r.id]);
      }
    },
    async update(list) {
      for (const r of list) {
        if (!regs.has(r.id)) throw new Error('Nonexistent script ID');
        regs.set(r.id, r);
        calls.push(['update', r.id]);
      }
    },
    async unregister(filter) {
      for (const id of (filter && filter.ids) || []) {
        regs.delete(id);
        calls.push(['unregister', id]);
      }
    },
    async execute(injection) { executed.push(injection); },
    async configureWorld() {}
  };
  return { regs, calls, executed };
}

describe('MV3 CSP safety & unrestricted script execution', () => {
  it('core/userscripts.js never calls eval, Function, or AsyncFunction (MV3 CSP safe)', () => {
    const src = readSource('core/userscripts.js');
    expect(src).not.toMatch(/\bnew\s+Function\s*\(/);
    expect(src).not.toMatch(/\bnew\s+AsyncFunction\s*\(/);
    expect(src).not.toMatch(/\beval\s*\(/);
  });

  it('auto-detects GM_* grants when @grant is omitted and respects explicit @grant none', () => {
    installChromeMock();
    loadCore('core/userscripts.js');
    const code = '// ==UserScript==\n// @name Auto\n// @match *://*/*\n// ==/UserScript==\nGM_setValue("a", 1); GM_xmlhttpRequest({ url: "https://x.test" });';
    const { meta } = CorsairUserScripts.parseMetadata(code);
    expect(CorsairUserScripts.chooseWorld(meta, code)).toBe('USER_SCRIPT');
    const src = CorsairUserScripts.buildSource({ id: 'cu-auto', code, meta }, CorsairUserScripts.buildPlan(meta));
    expect(src).toContain('GM_setValue');
    expect(src).toContain('GM_xmlhttpRequest');

    const noneCode = '// ==UserScript==\n// @name None\n// @match *://*/*\n// @grant none\n// ==/UserScript==\nGM_setValue("a", 1);';
    const { meta: noneMeta } = CorsairUserScripts.parseMetadata(noneCode);
    expect(CorsairUserScripts.chooseWorld(noneMeta, noneCode)).toBe('MAIN');
  });
});

describe('Redgifs SyntaxError diagnostics & non-blocking registration', () => {
  let mock;
  beforeEach(() => {
    installChromeMock();
    mock = installUserScriptsMock();
    globalThis.fetch = async (url) => {
      if (String(url).includes('html-404')) return { ok: true, text: async () => '<!DOCTYPE html><html><body>Not found</body></html>', headers: { get: () => 'text/html' }, arrayBuffer: async () => new ArrayBuffer(0) };
      return { ok: true, text: async () => 'var depLoaded = "VideoOK";', headers: { get: () => 'application/javascript' }, arrayBuffer: async () => new ArrayBuffer(0) };
    };
    loadCore('core/userscripts.js');
  });

  it('pinpoints uncommented header line ("Video") to line 2 advisory-only without blocking registration', async () => {
    const broken = [
      '// ==UserScript==',
      'Redgifs Video Downloader',
      '// @name Redgifs Helper',
      '// @match https://*.redgifs.com/*',
      '// ==/UserScript==',
      'console.log("ok");'
    ].join('\n');

    const res = await CorsairUserScripts.save({ code: broken });
    expect(res.ok).toBe(true);
    expect(res.syntax).not.toBeNull();
    expect(res.syntax.source).toBe('user-script');
    expect(res.syntax.line).toBe(2);
    expect(res.syntax.formatted).toContain('Redgifs Helper');
    expect(res.syntax.formatted).toContain('line 2');
    // Advisory only — never blocks user scripts from registering!
    expect(mock.regs.size).toBe(1);

    // AND executing the built source succeeds cleanly (sanitizeExecutableCode neutralizes uncommented header lines)
    const { meta } = CorsairUserScripts.parseMetadata(broken);
    const src = CorsairUserScripts.buildSource({ id: 'cu-rg1', code: broken, meta }, CorsairUserScripts.buildPlan(meta));
    const logs = [];
    const ctx = vm.createContext({
      location: { href: 'https://www.redgifs.com/watch/abc' }, window: {},
      document: { body: {}, head: { appendChild() {} }, documentElement: {}, createElement: () => ({}), addEventListener() {} },
      console: { log: (...a) => logs.push(a.join(' ')), warn() {}, error: (...a) => logs.push('ERR ' + a.join(' ')) },
      MutationObserver: class { observe() {} disconnect() {} }, URL, setTimeout
    });
    vm.runInContext(src, ctx);
    await new Promise(r => setTimeout(r, 25));
    expect(logs).toContain('ok');
  });

  it('executes cleanly even when a pasted plain-text title appears on line 2 before ==UserScript==', async () => {
    const pasted = [
      '',
      'RedGIFs Video Download Button',
      'Adds a download button (HD/MP4) to RedGIFs',
      '// ==UserScript==',
      '// @name RedGIFs Video Download Button',
      '// @match https://*.redgifs.com/*',
      '// ==/UserScript==',
      'console.log("ran-clean");'
    ].join('\n');
    const { meta } = CorsairUserScripts.parseMetadata(pasted);
    const src = CorsairUserScripts.buildSource({ id: 'cu-rg2', code: pasted, meta }, CorsairUserScripts.buildPlan(meta));
    const logs = [];
    const ctx = vm.createContext({
      location: { href: 'https://www.redgifs.com/watch/abc' }, window: {},
      document: { body: {}, head: { appendChild() {} }, documentElement: {}, createElement: () => ({}), addEventListener() {} },
      console: { log: (...a) => logs.push(a.join(' ')), warn() {}, error: (...a) => logs.push('ERR ' + a.join(' ')) },
      MutationObserver: class { observe() {} disconnect() {} }, URL, setTimeout
    });
    vm.runInContext(src, ctx);
    await new Promise(r => setTimeout(r, 25));
    expect(logs).toContain('ran-clean');
  });

  it('legitimate uses of "Video", template literals, quotes, comments, BOM, and CRLF execute cleanly', async () => {
    const code = '\uFEFF// ==UserScript==\r\n// @name Redgifs Video Enhancer\r\n// @match https://*.redgifs.com/*\r\n// ==/UserScript==\r\n' +
      'const Video = { title: `Redgifs "Video" \'test\'`, lines: `a\\nb\\nc` };\r\n' +
      '/* Video block comment */\r\n' +
      '// Video line comment\r\n' +
      'const re = /Video\\s+\\d+/gi;\r\n' +
      'console.log(Video.title, re.test("Video 42"));\r\n';

    const { meta } = CorsairUserScripts.parseMetadata(code);
    expect(meta.name).toBe('Redgifs Video Enhancer');
    expect(CorsairUserScripts.validateScript({ code, meta }).ok).toBe(true);

    const src = CorsairUserScripts.buildSource({ id: 'cu-vid', code, meta }, CorsairUserScripts.buildPlan(meta));
    const logs = [];
    const ctx = vm.createContext({
      location: { href: 'https://www.redgifs.com/watch/webbedorchidtowhee?from=embed' },
      window: {},
      document: { body: {}, head: { appendChild() {} }, documentElement: {}, createElement: () => ({}), addEventListener() {} },
      console: { log: (...a) => logs.push(a.join(' ')), warn() {}, error: (...a) => logs.push('ERR ' + a.join(' ')) },
      MutationObserver: class { observe() {} disconnect() {} },
      URL, setTimeout
    });
    vm.runInContext(src, ctx);
    await new Promise(r => setTimeout(r, 25));
    expect(logs.join('\n')).not.toContain('ERR');
    expect(logs.some(l => l.includes('Redgifs "Video"'))).toBe(true);
  });
});

describe('Metadata parser edge cases, IDN, .tld & inject-anywhere controls', () => {
  let mock;
  beforeEach(() => {
    installChromeMock();
    mock = installUserScriptsMock();
    globalThis.chrome.tabs = { query: async () => [{ id: 12, url: 'https://any-site.test/' }] };
    loadCore('core/userscripts.js');
  });

  it('handles UTF-8 BOM, CRLF, localized keys, unsupported directives, unknown directives, and warnings', () => {
    const code = '\uFEFF// ==UserScript==\r\n' +
      '// @name          First Name\r\n' +
      '// @name          Final Name\r\n' +
      '// @name:en       English Name\r\n' +
      '// @description:fa  توضیحات فارسی\r\n' +
      '// @website       https://site.example\r\n' +
      '// @source        https://src.example\r\n' +
      '// @iconURL       https://site.example/i.png\r\n' +
      '// @grant         GM_cookie\r\n' +
      '// @webRequest    [{"selector":"*"}]\r\n' +
      '// @customFlag    hello\r\n' +
      '// @resource      brokenOnlyName\r\n' +
      '// @include       /[unterminated/\r\n' +
      '// ==/UserScript==\r\n';

    const { meta, hasHeader } = CorsairUserScripts.parseMetadata(code);
    expect(hasHeader).toBe(true);
    expect(meta.name).toBe('Final Name');
    expect(meta.localized['name:en']).toBe('English Name');
    expect(meta.localized['description:fa']).toBe('توضیحات فارسی');
    expect(meta.unsupported.some(u => u.directive === '@grant' && u.value === 'GM_cookie')).toBe(true);
    expect(meta.unsupported.some(u => u.directive === '@webRequest')).toBe(true);
    expect(meta.unknown.some(u => u.key === 'customFlag' && u.value === 'hello')).toBe(true);
    expect(meta.warnings.some(w => w.includes('Duplicate @name'))).toBe(true);
  });

  it('normalizes IDN domains to punycode and supports .tld magic TLD + file:// URLs', () => {
    expect(CorsairUserScripts.toChromeMatch('https://bücher.de/*')).toBe('https://xn--bcher-kva.de/*');
    expect(CorsairUserScripts.toChromeMatch('https://*.bücher.de:8443/*')).toBe('https://*.xn--bcher-kva.de:8443/*');
    expect(CorsairUserScripts.toChromeMatch('https://www.google.tld/*')).toBeNull();

    const { meta: tldMeta } = CorsairUserScripts.parseMetadata('// ==UserScript==\n// @include https://www.google.tld/search*\n// ==/UserScript==');
    expect(CorsairUserScripts.urlMatchesMeta(tldMeta, 'https://www.google.com/search?q=1')).toBe(true);
    expect(CorsairUserScripts.urlMatchesMeta(tldMeta, 'https://www.google.co.uk/search?q=1')).toBe(true);
    expect(CorsairUserScripts.urlMatchesMeta(tldMeta, 'https://www.bing.com/search?q=1')).toBe(false);

    const { meta: fileMeta } = CorsairUserScripts.parseMetadata('// ==UserScript==\n// @match file:///*\n// ==/UserScript==');
    expect(CorsairUserScripts.urlMatchesMeta(fileMeta, 'file:///tmp/test.html')).toBe(true);
  });

  it('supports runEverywhere (<all_urls>), addMatchRule, and executeNow on any tab', async () => {
    const { script } = await CorsairUserScripts.save({ code: 'console.log("free");' });
    expect(mock.regs.size).toBe(0); // no @match yet

    // Toggle runEverywhere -> registers immediately on <all_urls> + allFrames
    const ev = await CorsairUserScripts.setRunEverywhere(script.id, true);
    expect(ev.ok).toBe(true);
    expect(mock.regs.size).toBe(1);
    const reg = mock.regs.get(script.id);
    expect(reg.matches).toEqual(['<all_urls>']);
    expect(reg.allFrames).toBe(true);

    // Execute immediately on active tab
    const runRes = await CorsairUserScripts.executeNow(script.id);
    expect(runRes.ok).toBe(true);
    expect(runRes.tabId).toBe(12);
    expect(mock.executed).toHaveLength(1);

    // Add a site match rule cleanly
    const added = await CorsairUserScripts.addMatchRule(script.id, '*://redgifs.com/*');
    expect(added.ok).toBe(true);
    expect(added.script.matches).toContain('*://redgifs.com/*');
  });
});

describe('Cross-tab sync, SPA navigation, updates, and editor helpers', () => {
  beforeEach(() => {
    installChromeMock();
    installUserScriptsMock();
    globalThis.chrome.tabs = { create: async (o) => ({ id: 77, ...o }), remove: async () => {} };
    globalThis.chrome.downloads = { download: async () => 1, cancel: async () => {} };
    globalThis.chrome.notifications = { create: async () => {}, clear: () => {} };
    globalThis.fetch = async (url) => ({
      ok: true, status: 200, statusText: 'OK', url,
      headers: new Headers({ 'content-type': 'text/plain' }),
      text: async () => '// ==UserScript==\n// @name Remote\n// @version 2.0\n// @match *://*/*\n// ==/UserScript==\nconsole.log("v2");',
      arrayBuffer: async () => new ArrayBuffer(0)
    });
    loadCore('core/userscripts.js');
    loadCore('core/userscript-editor.js');
  });

  it('broadcasts cross-tab value changes via handleGmConnect ports', async () => {
    const { script } = await CorsairUserScripts.save({
      code: '// ==UserScript==\n// @name SyncTest\n// @match *://*/*\n// @grant GM_setValue\n// @grant GM_addValueChangeListener\n// ==/UserScript==\n1;'
    });
    const receivedTab2 = [];
    const receivedTab1 = [];
    const port1 = { name: 'cu-vals:' + script.id, sender: { tab: { id: 1 }, frameId: 0 }, postMessage: (m) => receivedTab1.push(m), onDisconnect: { addListener() {} } };
    const port2 = { name: 'cu-vals:' + script.id, sender: { tab: { id: 2 }, frameId: 0 }, postMessage: (m) => receivedTab2.push(m), onDisconnect: { addListener() {} } };
    CorsairUserScripts.handleGmConnect(port1);
    CorsairUserScripts.handleGmConnect(port2);

    await CorsairUserScripts.handleGmMessage({ __cu: 1, id: script.id, op: 'vals:set', data: { k: 'theme', v: 'dark' } }, { tab: { id: 1 }, frameId: 0 });
    expect(receivedTab1).toHaveLength(0);
    expect(receivedTab2).toEqual([{ type: 'val-change', k: 'theme', v: 'dark', deleted: false }]);
  });

  it('duplicates scripts, protects local edits during remote updates, and survives corrupted storage', async () => {
    const imp = await CorsairUserScripts.importFromUrl('https://example.org/r.user.js');
    expect(imp.ok).toBe(true);

    const dup = await CorsairUserScripts.duplicate(imp.script.id);
    expect(dup.ok).toBe(true);
    expect(dup.script.name).toContain('(Copy)');

    await CorsairUserScripts.save({ id: imp.script.id, code: '// ==UserScript==\n// @name Remote\n// @match *://*/*\n// ==/UserScript==\nconsole.log("local edit");' });
    const blockedUpd = await CorsairUserScripts.updateFromRemote(imp.script.id, false);
    expect(blockedUpd.ok).toBe(false);
    expect(blockedUpd.error).toBe('local-modifications');

    const forcedUpd = await CorsairUserScripts.updateFromRemote(imp.script.id, true);
    expect(forcedUpd.ok).toBe(true);
    expect(forcedUpd.updated).toBe(true);

    await chrome.storage.local.set({ 'cus:index': [imp.script.id, 'cu-corrupt'], 'cus:rec:cu-corrupt': 'not-an-object' });
    expect((await CorsairUserScripts.list()).length).toBeGreaterThanOrEqual(1);
    expect((await CorsairUserScripts.sync()).ok).toBe(true);
  });

  it('supports window.onurlchange for SPA navigation', async () => {
    const code = '// ==UserScript==\n// @name SPA\n// @match *://*/*\n// @grant window.onurlchange\n// ==/UserScript==\nwindow.onurlchange = (e) => console.log("URL", e.url); history.pushState({}, "", "/next");';
    const { meta } = CorsairUserScripts.parseMetadata(code);
    const src = CorsairUserScripts.buildSource({ id: 'cu-spa', code, meta }, CorsairUserScripts.buildPlan(meta));
    const logs = [];
    const loc = { href: 'https://spa.test/start' };
    const win = { addEventListener() {}, dispatchEvent() {} };
    const hist = { pushState(_s, _t, u) { loc.href = 'https://spa.test' + u; }, replaceState() {} };
    const ctx = vm.createContext({
      location: loc, window: win, history: hist,
      CustomEvent: class { constructor(t, o) { this.type = t; this.detail = o && o.detail; } },
      document: { body: {}, head: { appendChild() {} }, documentElement: {}, createElement: () => ({}), addEventListener() {} },
      console: { log: (...a) => logs.push(a.join(' ')), warn() {}, error: (...a) => logs.push('ERR ' + a.join(' ')) },
      MutationObserver: class { observe() {} disconnect() {} }, URL, setTimeout
    });
    vm.runInContext(src, ctx);
    await new Promise(r => setTimeout(r, 25));
    expect(logs).toContain('URL https://spa.test/next');
  });

  it('highlights code safely without XSS and supports editor helpers', () => {
    const html = CorsairUserscriptEditor.highlightCode('// ==UserScript==\n// @name <img src=x onerror=alert(1)>\n// ==/UserScript==\nconst x = GM_getValue("k");');
    expect(html).not.toContain('<img');
    expect(html).toContain('&lt;img');
    expect(html).toContain('tok-kw');
    expect(html).toContain('tok-gm');
    expect(CorsairUserscriptEditor.findMatches('foo Foo FOO', 'foo', { caseSensitive: false })).toHaveLength(3);
  });
});

describe('Tampermonkey 95%+ features: GM_getTab/saveTab/getTabs, checkAllUpdates, storage inspector', () => {
  beforeEach(() => {
    installChromeMock();
    installUserScriptsMock();
    globalThis.fetch = async (url) => ({
      ok: true, status: 200, statusText: 'OK', url,
      headers: new Headers({ 'content-type': 'text/plain' }),
      text: async () => '// ==UserScript==\n// @name AutoUpd\n// @version 2.0\n// @match *://*/*\n// ==/UserScript==\nconsole.log("v2");',
      arrayBuffer: async () => new ArrayBuffer(0)
    });
    loadCore('core/userscripts.js');
  });

  it('persists per-tab objects via GM_saveTab / GM_getTab / GM_getTabs and cleans up on tab close', async () => {
    const { script } = await CorsairUserScripts.save({
      code: '// ==UserScript==\n// @name TabState\n// @match *://*/*\n// @grant GM_getTab\n// @grant GM_saveTab\n// @grant GM_getTabs\n// ==/UserScript==\n1;'
    });
    await CorsairUserScripts.handleGmMessage({ __cu: 1, id: script.id, op: 'tab:save', data: { tab: { step: 3 } } }, { tab: { id: 10 } });
    await CorsairUserScripts.handleGmMessage({ __cu: 1, id: script.id, op: 'tab:save', data: { tab: { step: 7 } } }, { tab: { id: 20 } });

    const t10 = await CorsairUserScripts.handleGmMessage({ __cu: 1, id: script.id, op: 'tab:get' }, { tab: { id: 10 } });
    expect(t10.tab).toEqual({ step: 3 });

    const all = await CorsairUserScripts.handleGmMessage({ __cu: 1, id: script.id, op: 'tab:list' }, { tab: { id: 10 } });
    expect(all.tabs).toEqual({ '10': { step: 3 }, '20': { step: 7 } });

    await CorsairUserScripts.clearTabData(10);
    const afterClose = await CorsairUserScripts.handleGmMessage({ __cu: 1, id: script.id, op: 'tab:list' }, { tab: { id: 20 } });
    expect(afterClose.tabs).toEqual({ '20': { step: 7 } });
  });

  it('checkAllUpdates updates unmodified URL scripts and skips locally edited ones, and getValues/clearValues work', async () => {
    const s1 = await CorsairUserScripts.save({
      code: '// ==UserScript==\n// @name AutoUpd\n// @version 1.0\n// @match *://*/*\n// @updateURL https://cdn.test/u.user.js\n// ==/UserScript==\nconsole.log("v1");',
      sourceUrl: 'https://cdn.test/u.user.js',
      isRemoteUpdate: true
    });
    const res = await CorsairUserScripts.checkAllUpdates();
    expect(res.ok).toBe(true);
    expect(res.checked).toBe(1);
    expect(res.updated).toBe(1);

    await CorsairUserScripts.handleGmMessage({ __cu: 1, id: s1.script.id, op: 'vals:set', data: { k: 'foo', v: 'bar' } }, {});
    expect((await CorsairUserScripts.getValues(s1.script.id)).values).toEqual({ foo: 'bar' });
    await CorsairUserScripts.clearValues(s1.script.id);
    expect((await CorsairUserScripts.getValues(s1.script.id)).values).toEqual({});
  });
});

describe('Backup/restore runEverywhere & editor template generator', () => {
  beforeEach(() => {
    installChromeMock();
    installUserScriptsMock();
    loadCore('core/userscripts.js');
    loadCore('core/userscript-editor.js');
  });

  it('preserves runEverywhere across exportForBackup -> restoreFromBackup round trip', async () => {
    const { script } = await CorsairUserScripts.save({ code: 'console.log("everywhere");', runEverywhere: true });
    const backup = await CorsairUserScripts.exportForBackup();
    expect(backup.scripts[0].runEverywhere).toBe(true);

    await CorsairUserScripts.remove(script.id);
    const res = await CorsairUserScripts.restoreFromBackup(backup);
    expect(res.ok).toBe(true);
    const restored = await CorsairUserScripts.list();
    expect(restored).toHaveLength(1);
    expect(restored[0].runEverywhere).toBe(true);
  });

  it('insertTemplate prepends ==UserScript== header without overwriting existing code', () => {
    const out = CorsairUserscriptEditor.insertTemplate('console.log("hi");');
    expect(out).toContain('// ==UserScript==');
    expect(out).toContain('// ==/UserScript==');
    expect(out).toContain('console.log("hi");');
    expect(CorsairUserscriptEditor.insertTemplate(out)).toBe(out);
  });
});

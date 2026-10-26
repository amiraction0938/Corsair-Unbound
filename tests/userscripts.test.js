import { describe, it, expect, beforeEach } from 'vitest';
import vm from 'node:vm';
import { installChromeMock, uninstallChromeMock } from './helpers/chrome-mock.js';
import { loadCore } from './helpers/load-core.js';

const SAMPLE = `// ==UserScript==
// @name         Sample
// @namespace    https://example.org/
// @version      1.2.3
// @description  A sample
// @author       me
// @match        https://*.example.com/*
// @match        http*://foo.org/path
// @exclude      https://www.example.com/private*
// @grant        GM_getValue
// @grant        GM_setValue
// @require      https://cdn.example.com/lib.js
// @resource     css https://cdn.example.com/a.css
// @run-at       document-start
// @noframes
// ==/UserScript==
console.log('hi');
`;

function installUserScriptsMock() {
  const regs = new Map();
  const calls = [];
  const api = {
    async getScripts() { return Array.from(regs.values()).map(r => ({ ...r })); },
    async register(list) {
      for (const r of list) {
        if (r.matches.some(m => m === 'bad-pattern')) throw new Error('Invalid match pattern');
        if (regs.has(r.id)) throw new Error('Duplicate script ID');
        regs.set(r.id, r); calls.push(['register', r.id]);
      }
    },
    async update(list) {
      for (const r of list) {
        if (!regs.has(r.id)) throw new Error('Nonexistent script ID');
        regs.set(r.id, r); calls.push(['update', r.id]);
      }
    },
    async unregister(filter) {
      for (const id of (filter && filter.ids) || []) { regs.delete(id); calls.push(['unregister', id]); }
    },
    async configureWorld() {}
  };
  globalThis.chrome.userScripts = api;
  return { regs, calls };
}

describe('CorsairUserScripts — metadata', () => {
  beforeEach(() => { installChromeMock(); loadCore('core/userscripts.js'); });

  it('parses a full header', () => {
    const { meta, hasHeader } = CorsairUserScripts.parseMetadata(SAMPLE);
    expect(hasHeader).toBe(true);
    expect(meta.name).toBe('Sample');
    expect(meta.version).toBe('1.2.3');
    expect(meta.match).toEqual(['https://*.example.com/*', 'http*://foo.org/path']);
    expect(meta.exclude).toEqual(['https://www.example.com/private*']);
    expect(meta.grant).toEqual(['GM_getValue', 'GM_setValue']);
    expect(meta.require).toEqual(['https://cdn.example.com/lib.js']);
    expect(meta.resource).toEqual([{ name: 'css', url: 'https://cdn.example.com/a.css' }]);
    expect(meta.runAt).toBe('document-start');
    expect(meta.noframes).toBe(true);
  });

  it('handles scripts without a header', () => {
    const { meta, hasHeader } = CorsairUserScripts.parseMetadata('alert(1)');
    expect(hasHeader).toBe(false);
    expect(meta.match).toEqual([]);
  });

  it('ignores localized keys and unknown run-at values', () => {
    const { meta } = CorsairUserScripts.parseMetadata('// ==UserScript==\n// @name:fa سلام\n// @run-at nonsense\n// ==/UserScript==');
    expect(meta.runAt).toBe('document-idle');
    expect(meta.localized['name:fa']).toBe('سلام');
  });

  it('picks the world from grants and @inject-into', () => {
    const w = (h) => CorsairUserScripts.chooseWorld(CorsairUserScripts.parseMetadata(`// ==UserScript==\n${h}\n// ==/UserScript==`).meta);
    expect(w('// @grant none')).toBe('MAIN');
    expect(w('')).toBe('MAIN');
    expect(w('// @grant GM_setValue')).toBe('USER_SCRIPT');
    expect(w('// @grant GM_setValue\n// @inject-into page')).toBe('MAIN');
    expect(w('// @grant none\n// @inject-into content')).toBe('USER_SCRIPT');
  });
});

describe('CorsairUserScripts — match patterns', () => {
  beforeEach(() => { installChromeMock(); loadCore('core/userscripts.js'); });

  it('converts valid patterns', () => {
    const c = CorsairUserScripts.toChromeMatch;
    expect(c('https://*.example.com/*')).toBe('https://*.example.com/*');
    expect(c('http*://foo.org/path')).toBe('*://foo.org/path');
    expect(c('https://example.com')).toBe('https://example.com/*');
    expect(c('<all_urls>')).toBe('<all_urls>');
    expect(c('http://localhost:3000/*')).toBe('http://localhost:3000/*');
    expect(c('file:///*')).toBe('file:///*');
  });

  it('rejects patterns Chrome cannot express', () => {
    const c = CorsairUserScripts.toChromeMatch;
    expect(c('*://*.google.*/*')).toBeNull();
    expect(c('*://example.com*')).toBeNull();
    expect(c('ftp2://x/*')).toBeNull();
    expect(c('')).toBeNull();
  });

  it('plans plain @match without runtime filtering', () => {
    const { meta } = CorsairUserScripts.parseMetadata(SAMPLE);
    const plan = CorsairUserScripts.buildPlan(meta);
    expect(plan.noMatch).toBe(false);
    expect(plan.matches).toEqual(['https://*.example.com/*', '*://foo.org/path']);
    expect(plan.excludeGlobs).toEqual(['https://www.example.com/private*']);
    expect(plan.runtime).toBeNull();
  });

  it('uses includeGlobs for glob-only @include', () => {
    const { meta } = CorsairUserScripts.parseMetadata('// ==UserScript==\n// @include https://example.com/a*\n// ==/UserScript==');
    const plan = CorsairUserScripts.buildPlan(meta);
    expect(plan.matches).toEqual(['*://*/*']);
    expect(plan.includeGlobs).toEqual(['https://example.com/a*']);
    expect(plan.runtime).toBeNull();
  });

  it('falls back to a runtime filter for regex rules and odd @match', () => {
    const { meta } = CorsairUserScripts.parseMetadata('// ==UserScript==\n// @include /^https:\\/\\/a\\.com\\/.*$/i\n// @match *://*.google.*/*\n// ==/UserScript==');
    const plan = CorsairUserScripts.buildPlan(meta);
    expect(plan.matches).toEqual(['*://*/*']);
    expect(plan.runtime).not.toBeNull();
    expect(plan.runtime.i.length).toBe(2);
  });

  it('reports scripts with no match rules', () => {
    const { meta } = CorsairUserScripts.parseMetadata('// ==UserScript==\n// @name x\n// ==/UserScript==');
    expect(CorsairUserScripts.buildPlan(meta).noMatch).toBe(true);
  });
});

describe('CorsairUserScripts — generated source', () => {
  beforeEach(() => { installChromeMock(); loadCore('core/userscripts.js'); });

  function run(record, href) {
    const { meta } = CorsairUserScripts.parseMetadata(record.code);
    record.meta = meta;
    const plan = CorsairUserScripts.buildPlan(meta);
    const src = CorsairUserScripts.buildSource(record, plan);
    const logs = [];
    const ctx = vm.createContext({
      location: { href },
      document: { body: {}, head: { appendChild() {} }, documentElement: {}, createElement: () => ({}) },
      console: { log: (...a) => logs.push(a.join(' ')), warn: (...a) => logs.push('WARN ' + a.join(' ')), error: (...a) => logs.push('ERR ' + a.join(' ')) },
      MutationObserver: class { observe() {} disconnect() {} },
      window: {}
    });
    vm.runInContext(src, ctx);
    return new Promise(r => setTimeout(() => r(logs), 20));
  }

  it('runs user code and exposes GM_info', async () => {
    const code = '// ==UserScript==\n// @name T\n// @match *://*/*\n// ==/UserScript==\nconsole.log(GM_info.script.name, typeof unsafeWindow);';
    const logs = await run({ id: 'cu-1', code }, 'https://x.com/');
    expect(logs).toContain('T object');
  });

  it('supports top-level await and early return', async () => {
    const code = '// ==UserScript==\n// @name T\n// @match *://*/*\n// ==/UserScript==\nawait Promise.resolve();\nconsole.log("after-await");\nreturn;\nconsole.log("never");';
    const logs = await run({ id: 'cu-1', code }, 'https://x.com/');
    expect(logs).toContain('after-await');
    expect(logs).not.toContain('never');
  });

  it('inlines cached @require libraries before user code', async () => {
    const code = '// ==UserScript==\n// @name T\n// @match *://*/*\n// @require https://cdn.example.com/lib.js\n// ==/UserScript==\nconsole.log(libValue);';
    const logs = await run({ id: 'cu-1', code, requires: { 'https://cdn.example.com/lib.js': 'var libValue = 42;' } }, 'https://x.com/');
    expect(logs).toContain('42');
  });

  it('applies the runtime URL filter', async () => {
    const code = '// ==UserScript==\n// @name T\n// @include /^https:\\/\\/ok\\.com\\//\n// @exclude /private/\n// ==/UserScript==\nconsole.log("ran");';
    expect(await run({ id: 'cu-1', code }, 'https://ok.com/page')).toContain('ran');
    expect(await run({ id: 'cu-1', code }, 'https://other.com/page')).not.toContain('ran');
    expect(await run({ id: 'cu-1', code }, 'https://ok.com/private')).not.toContain('ran');
  });

  it('reports errors thrown by user code instead of crashing', async () => {
    const code = '// ==UserScript==\n// @name Boom\n// @match *://*/*\n// ==/UserScript==\nthrow new Error("nope");';
    const logs = await run({ id: 'cu-1', code }, 'https://x.com/');
    expect(logs.some(l => l.startsWith('ERR') && l.includes('Boom'))).toBe(true);
  });
});

describe('CorsairUserScripts — storage and registration', () => {
  let mock;
  beforeEach(() => {
    installChromeMock();
    mock = installUserScriptsMock();
    globalThis.fetch = async (url) => ({
      ok: true,
      text: async () => `/* body of ${url} */`,
      arrayBuffer: async () => new TextEncoder().encode('data').buffer,
      headers: { get: () => 'text/css' }
    });
    loadCore('core/userscripts.js');
  });

  it('saves, lists, registers and removes a script', async () => {
    const res = await CorsairUserScripts.save({ code: SAMPLE });
    expect(res.ok).toBe(true);
    expect(res.script.name).toBe('Sample');
    expect(mock.regs.size).toBe(1);
    const reg = Array.from(mock.regs.values())[0];
    expect(reg.world).toBe('USER_SCRIPT');
    expect(reg.runAt).toBe('document_start');
    expect(reg.allFrames).toBe(false);
    expect(reg.js[0].code).toContain('body of https://cdn.example.com/lib.js');

    const list = await CorsairUserScripts.list();
    expect(list).toHaveLength(1);

    await CorsairUserScripts.remove(res.script.id);
    expect(await CorsairUserScripts.list()).toHaveLength(0);
    expect(mock.regs.size).toBe(0);
  });

  it('does not lint or limit code (no blocklist, no size cap)', async () => {
    const evil = `// ==UserScript==\n// @name Free\n// @match *://*/*\n// ==/UserScript==\ndocument.cookie; eval("1"); new WebSocket("wss://x"); window.top.x; chrome.runtime;\n` + 'x'.repeat(500000);
    const res = await CorsairUserScripts.save({ code: evil });
    expect(res.ok).toBe(true);
    expect(mock.regs.size).toBe(1);
    const stored = await CorsairUserScripts.get(res.script.id);
    expect(stored.code.length).toBeGreaterThan(500000);
  });

  it('toggles scripts off and on', async () => {
    const { script } = await CorsairUserScripts.save({ code: SAMPLE });
    await CorsairUserScripts.setEnabled(script.id, false);
    expect(mock.regs.size).toBe(0);
    await CorsairUserScripts.setEnabled(script.id, true);
    expect(mock.regs.size).toBe(1);
  });

  it('updates an existing script instead of duplicating (same id)', async () => {
    const { script } = await CorsairUserScripts.save({ code: SAMPLE });
    await CorsairUserScripts.save({ id: script.id, code: SAMPLE.replace('1.2.3', '2.0.0') });
    expect(await CorsairUserScripts.list()).toHaveLength(1);
    expect((await CorsairUserScripts.list())[0].version).toBe('2.0.0');
    expect(mock.regs.size).toBe(1);
  });

  it('URL imports update the script with the same @name/@namespace', async () => {
    globalThis.fetch = async () => ({ ok: true, text: async () => SAMPLE, headers: { get: () => 'text/plain' }, arrayBuffer: async () => new ArrayBuffer(0) });
    await CorsairUserScripts.importFromUrl('https://example.org/sample.user.js');
    await CorsairUserScripts.importFromUrl('https://example.org/sample.user.js');
    expect(await CorsairUserScripts.list()).toHaveLength(1);
  });

  it('rejects non-http(s) import URLs', async () => {
    const r = await CorsairUserScripts.importFromUrl('file:///etc/passwd');
    expect(r.ok).toBe(false);
  });

  it('does not register scripts without match rules', async () => {
    await CorsairUserScripts.save({ code: '// ==UserScript==\n// @name nomatch\n// ==/UserScript==\n1' });
    expect(mock.regs.size).toBe(0);
    expect((await CorsairUserScripts.list())[0].noMatch).toBe(true);
  });

  it('reports availability problems without throwing', async () => {
    delete globalThis.chrome.userScripts;
    const res = await CorsairUserScripts.save({ code: SAMPLE });
    expect(res.ok).toBe(true);
    expect(res.sync.ok).toBe(false);
    expect(res.sync.availability.code).toBe('disabled');
  });

  it('skips re-registering unchanged scripts on later syncs', async () => {
    await CorsairUserScripts.save({ code: SAMPLE });
    const before = mock.calls.length;
    await CorsairUserScripts.sync();
    expect(mock.calls.length).toBe(before);
  });

  it('migrates legacy per-domain scripts once', async () => {
    globalThis.chrome.storage.local._seed({
      customDomainScripts: { 'foo.com': { code: 'console.log(1)', enabled: true } }
    });
    const r1 = await CorsairUserScripts.migrateLegacy();
    expect(r1.migrated).toBe(1);
    const r2 = await CorsairUserScripts.migrateLegacy();
    expect(r2.skipped).toBe(true);
    await CorsairUserScripts.sync();
    const reg = Array.from(mock.regs.values())[0];
    expect(reg.matches).toEqual(['*://foo.com/*', '*://*.foo.com/*']);
    expect(reg.world).toBe('MAIN');
  });
});

describe('CorsairUserScripts — GM_* API end to end', () => {
  let downloads;

  beforeEach(() => {
    installChromeMock();
    installUserScriptsMock();
    downloads = [];
    globalThis.chrome.downloads = { download: async (o) => { downloads.push(o); return 7; } };
    globalThis.chrome.notifications = { create: async () => {}, clear: () => {} };
    globalThis.chrome.tabs = { create: async (o) => ({ id: 99, ...o }), remove: async () => {} };
    globalThis.chrome.runtime.getURL = (p) => 'chrome-extension://x/' + p;
    globalThis.fetch = async (url, init) => {
      if (String(url).includes('fail')) throw new Error('boom');
      return {
        status: 200, statusText: 'OK', url,
        headers: new Headers({ 'content-type': 'application/json', 'x-test': init && init.method || 'GET' }),
        text: async () => '{"hello":"world"}',
        arrayBuffer: async () => new TextEncoder().encode('bin').buffer
      };
    };
    loadCore('core/userscripts.js');
  });

  async function runScript(body, header = '', record = {}) {
    const code = `// ==UserScript==\n// @name GMTest\n// @match *://*/*\n${header}\n// ==/UserScript==\n${body}`;
    const { meta } = CorsairUserScripts.parseMetadata(code);
    const rec = { id: 'cu-test1', code, meta, ...record };
    const plan = CorsairUserScripts.buildPlan(meta);
    const src = CorsairUserScripts.buildSource(rec, plan);
    const logs = [];
    const ctx = vm.createContext({
      location: { href: 'https://site.test/page', },
      document: {
        body: {}, head: { appendChild() {} }, documentElement: {}, createElement: () => ({}),
        addEventListener() {}
      },
      window: {},
      console: { log: (...a) => logs.push(a.map(String).join(' ')), warn: (...a) => logs.push('WARN ' + a.join(' ')), error: (...a) => logs.push('ERR ' + a.join(' ')) },
      chrome: { runtime: { sendMessage: (m) => CorsairUserScripts.handleGmMessage(m, { tab: { id: 5 } }) } },
      URL, URLSearchParams, Response, Blob, TextDecoder, TextEncoder, atob, btoa, setTimeout, clearTimeout,
      MutationObserver: class { observe() {} disconnect() {} }
    });
    vm.runInContext(src, ctx);
    await new Promise(r => setTimeout(r, 60));
    return logs;
  }

  it('GM_setValue / GM_getValue persist between runs', async () => {
    await runScript('GM_setValue("count", 41); GM_setValue("obj", {a:[1,2]});', '// @grant GM_setValue');
    const logs = await runScript('console.log(GM_getValue("count"), JSON.stringify(GM_getValue("obj")), GM_getValue("missing", "dflt"), GM_listValues().join(","));', '// @grant GM_getValue\n// @grant GM_listValues');
    expect(logs).toContain('41 {"a":[1,2]} dflt count,obj');
  });

  it('GM_deleteValue removes stored data and GM_addValueChangeListener fires', async () => {
    const logs = await runScript(
      'GM_addValueChangeListener("k", (n, o, v, remote) => console.log("chg", o, v, remote));' +
      'GM_setValue("k", 1); GM_setValue("k", 2); GM_deleteValue("k"); console.log(GM_getValue("k", "gone"));',
      '// @grant GM_setValue\n// @grant GM_getValue\n// @grant GM_deleteValue\n// @grant GM_addValueChangeListener');
    expect(logs).toContain('chg undefined 1 false');
    expect(logs).toContain('chg 1 2 false');
    expect(logs).toContain('gone');
  });

  it('GM.getValue / GM.setValue return promises', async () => {
    const logs = await runScript('await GM.setValue("p", "x"); console.log("v=" + await GM.getValue("p"));', '// @grant GM.setValue\n// @grant GM.getValue');
    expect(logs).toContain('v=x');
  });

  it('GM_xmlhttpRequest performs a cross-origin request through the extension', async () => {
    const logs = await runScript(
      'GM_xmlhttpRequest({ method: "POST", url: "https://api.other.test/x", data: "a=1", responseType: "json",' +
      ' onload: r => console.log("status", r.status, JSON.stringify(r.response), r.responseHeaders.includes("x-test: POST"), r.finalUrl) });',
      '// @grant GM_xmlhttpRequest');
    expect(logs).toContain('status 200 {"hello":"world"} true https://api.other.test/x');
  });

  it('GM_xmlhttpRequest reports network errors via onerror', async () => {
    const logs = await runScript(
      'GM_xmlhttpRequest({ url: "https://fail.test/", onerror: e => console.log("err", e.status, e.error) });',
      '// @grant GM_xmlhttpRequest');
    expect(logs).toContain('err 0 boom');
  });

  it('GM.xmlHttpRequest resolves a promise', async () => {
    const logs = await runScript(
      'const r = await GM.xmlHttpRequest({ url: "https://api.other.test/y" }); console.log("text", r.responseText);',
      '// @grant GM.xmlHttpRequest');
    expect(logs).toContain('text {"hello":"world"}');
  });

  it('GM_download sanitises the file name', async () => {
    await runScript('GM_download({ url: "https://a.test/f.zip", name: "../../evil/../file.zip" });', '// @grant GM_download');
    expect(downloads).toHaveLength(1);
    expect(downloads[0].filename).toBe('evil/file.zip');
  });

  it('GM_getResourceText returns cached @resource data', async () => {
    const logs = await runScript(
      'console.log(GM_getResourceText("css"), GM_getResourceURL("css"));',
      '// @resource css https://cdn.example.com/a.css\n// @grant GM_getResourceText\n// @grant GM_getResourceURL',
      { resources: { css: { url: 'https://cdn.example.com/a.css', text: 'body{}', dataUrl: 'data:text/css;base64,Ym9keXt9' } } });
    expect(logs).toContain('body{} data:text/css;base64,Ym9keXt9');
  });

  it('only defines the GM_* functions that were granted', async () => {
    const logs = await runScript('console.log(typeof GM_setValue, typeof GM_xmlhttpRequest, typeof GM_info, typeof unsafeWindow);', '// @grant none');
    expect(logs).toContain('undefined undefined object object');
  });

  it('runs scripts that only use local helpers in the page world', async () => {
    const { meta } = CorsairUserScripts.parseMetadata('// ==UserScript==\n// @match *://*/*\n// @grant GM_addStyle\n// @grant GM_setClipboard\n// @grant GM_registerMenuCommand\n// ==/UserScript==');
    expect(CorsairUserScripts.chooseWorld(meta)).toBe('MAIN');
  });

  it('rejects malformed or foreign bridge messages', async () => {
    expect((await CorsairUserScripts.handleGmMessage({ op: 'vals:get', id: 'cu-x' }, {})).ok).toBe(false);
    expect((await CorsairUserScripts.handleGmMessage({ __cu: 1, op: 'vals:get', id: 'other' }, {})).ok).toBe(false);
    expect((await CorsairUserScripts.handleGmMessage({ __cu: 1, op: 'nope', id: 'cu-x' }, {})).ok).toBe(false);
  });

  it('removing a script deletes its stored values', async () => {
    const { script } = await CorsairUserScripts.save({ code: '// ==UserScript==\n// @name V\n// @match *://*/*\n// @grant GM_setValue\n// ==/UserScript==' });
    await CorsairUserScripts.handleGmMessage({ __cu: 1, op: 'vals:set', id: script.id, data: { k: 'a', v: 1 } }, {});
    expect((await CorsairUserScripts.handleGmMessage({ __cu: 1, op: 'vals:get', id: script.id }, {})).values).toEqual({ a: 1 });
    await CorsairUserScripts.remove(script.id);
    expect((await CorsairUserScripts.handleGmMessage({ __cu: 1, op: 'vals:get', id: script.id }, {})).values).toEqual({});
  });
});

describe('CorsairUserScripts — regression tests for fixed bugs', () => {
  beforeEach(() => {
    installChromeMock();
    installUserScriptsMock();
    globalThis.fetch = async () => ({ ok: true, text: async () => '', headers: { get: () => '' }, arrayBuffer: async () => new ArrayBuffer(0) });
    loadCore('core/userscripts.js');
  });

  it('userscripts can redeclare unsafeWindow / GM_info / GM_* with var or function', async () => {
    const code = '// ==UserScript==\n// @name Redecl\n// @match *://*/*\n// @grant GM_addStyle\n// ==/UserScript==\n' +
      'var unsafeWindow = window.unsafeWindow || window;\nvar GM_info = GM_info || {};\nfunction GM_addStyle(c){ return "mine"; }\nconsole.log("ok", typeof unsafeWindow, GM_addStyle("x"));';
    const { meta } = CorsairUserScripts.parseMetadata(code);
    const src = CorsairUserScripts.buildSource({ id: 'cu-r', code, meta }, CorsairUserScripts.buildPlan(meta));
    const logs = [];
    const ctx = vm.createContext({
      location: { href: 'https://x.com/' }, window: {}, console: { log: (...a) => logs.push(a.join(' ')), warn() {}, error: (...a) => logs.push('ERR ' + a.join(' ')) },
      document: { body: {}, head: { appendChild() {} }, documentElement: {}, createElement: () => ({}), addEventListener() {} },
      MutationObserver: class { observe() {} disconnect() {} }, URL, setTimeout
    });
    vm.runInContext(src, ctx);
    await new Promise(r => setTimeout(r, 30));
    expect(logs.join('\n')).not.toMatch(/ERR/);
    expect(logs).toContain('ok object mine');
  });

  it('two header-less scripts imported from different URLs do not overwrite each other', async () => {
    await CorsairUserScripts.save({ code: 'console.log(1)', sourceUrl: 'https://a.test/one.user.js' });
    await CorsairUserScripts.save({ code: 'console.log(2)', sourceUrl: 'https://a.test/two.user.js' });
    expect(await CorsairUserScripts.list()).toHaveLength(2);
  });

  it('re-importing the same URL updates in place even if the @name changed', async () => {
    const v1 = '// ==UserScript==\n// @name Old name\n// @match *://*/*\n// ==/UserScript==';
    const v2 = '// ==UserScript==\n// @name New name\n// @match *://*/*\n// ==/UserScript==';
    await CorsairUserScripts.save({ code: v1, sourceUrl: 'https://a.test/s.user.js' });
    await CorsairUserScripts.save({ code: v2, sourceUrl: 'https://a.test/s.user.js' });
    const list = await CorsairUserScripts.list();
    expect(list).toHaveLength(1);
    expect(list[0].name).toBe('New name');
  });

  it('rapid consecutive saves leave exactly the right registrations', async () => {
    const mk = (n) => `// ==UserScript==\n// @name S${n}\n// @match https://s${n}.test/*\n// ==/UserScript==`;
    await Promise.all([1, 2, 3, 4, 5].map(n => CorsairUserScripts.save({ code: mk(n) })));
    expect(await CorsairUserScripts.list()).toHaveLength(5);
    const regs = await chrome.userScripts.getScripts();
    expect(regs).toHaveLength(5);
  });
});

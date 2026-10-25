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

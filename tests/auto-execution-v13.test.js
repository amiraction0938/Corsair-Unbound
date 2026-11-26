import { describe, it, expect, beforeEach } from 'vitest';
import { loadCore } from './helpers/load-core.js';

function makeChromeEnv(opts = {}) {
  const localStore = {};
  const registered = new Map();
  let apiEnabled = opts.apiEnabled !== false;
  let executeSupported = opts.executeSupported !== false;
  let configuredWorldCalls = 0;
  let executeCalls = [];

  const chromeMock = {
    runtime: {
      id: 'corsairtestext1234567890abcdef',
      getManifest: () => ({ version: '1.13.0' })
    },
    storage: {
      local: {
        async get(keys) {
          if (typeof keys === 'string') return { [keys]: localStore[keys] };
          if (Array.isArray(keys)) {
            const out = {};
            for (const k of keys) if (k in localStore) out[k] = localStore[k];
            return out;
          }
          return { ...localStore };
        },
        async set(obj) { Object.assign(localStore, obj); },
        async remove(keys) {
          for (const k of (Array.isArray(keys) ? keys : [keys])) delete localStore[k];
        }
      }
    },
    userScripts: {
      async getScripts() {
        if (!apiEnabled) throw new Error('User scripts API disabled');
        return Array.from(registered.values());
      },
      async register(arr) {
        if (!apiEnabled) throw new Error('User scripts API disabled');
        for (const s of arr) registered.set(s.id, s);
      },
      async update(arr) {
        if (!apiEnabled) throw new Error('User scripts API disabled');
        for (const s of arr) registered.set(s.id, s);
      },
      async unregister({ ids }) {
        for (const id of ids) registered.delete(id);
      },
      async configureWorld() {
        configuredWorldCalls++;
      },
      ...(executeSupported ? {
        async execute(spec) {
          executeCalls.push(spec);
          return [{ frameId: 0, result: null }];
        }
      } : {})
    }
  };

  return {
    chromeMock,
    registered,
    executeCalls,
    setApiEnabled(v) { apiEnabled = v; },
    clearRegistrations() { registered.clear(); },
    getConfiguredWorldCalls() { return configuredWorldCalls; }
  };
}

describe('Automatic Userscript Execution & Lifecycle (v1.13.0)', () => {
  it('registers scripts automatically on save and restores after Chrome clears registrations on extension update', async () => {
    const env = makeChromeEnv();
    globalThis.chrome = env.chromeMock; loadCore('core/userscripts.js'); const US = globalThis.CorsairUserScripts;

    const code = `// ==UserScript==
// @name        Auto Exec Test
// @match       https://example.com/*
// @run-at      document-start
// @grant       none
// ==/UserScript==
console.log('auto');`;

    const saved = await US.save({ code, enabled: true });
    expect(saved.ok).toBe(true);
    expect(env.registered.size).toBe(1);
    const reg = Array.from(env.registered.values())[0];
    expect(reg.runAt).toBe('document_start');
    expect(reg.matches).toContain('https://example.com/*');

    // Simulate Chrome clearing dynamic registrations on extension update
    env.clearRegistrations();
    expect(env.registered.size).toBe(0);

    // ensureSynced({ force: true }) restores registration automatically without popup click
    const res = await US.ensureSynced({ force: true });
    expect(res.ok).toBe(true);
    expect(res.registered).toBe(1);
    expect(env.registered.size).toBe(1);
  });

  it('recovers automatically when Allow User Scripts is enabled after initial boot', async () => {
    const env = makeChromeEnv({ apiEnabled: false });
    globalThis.chrome = env.chromeMock; loadCore('core/userscripts.js'); const US = globalThis.CorsairUserScripts;

    const firstInit = await US.init();
    expect(firstInit.ok).toBe(false);
    expect(firstInit.availability.code).toBe('disabled');
    expect(firstInit.availability.setupInstructions).toBeTruthy();

    await US.save({
      code: `// ==UserScript==\n// @name Delayed Enable\n// @match https://news.example.org/*\n// ==/UserScript==\nconsole.log(1);`,
      enabled: true
    });
    expect(env.registered.size).toBe(0);

    // User turns ON "Allow User Scripts" in chrome://extensions
    env.setApiEnabled(true);
    const recovered = await US.ensureSynced({ force: true });
    expect(recovered.ok).toBe(true);
    expect(env.registered.size).toBe(1);
  });

  it('preserves all four @run-at timings and @noframes accurately', async () => {
    const env = makeChromeEnv();
    globalThis.chrome = env.chromeMock; loadCore('core/userscripts.js'); const US = globalThis.CorsairUserScripts;

    const cases = [
      ['document-start', 'document_start'],
      ['document-body', 'document_start'],
      ['document-end', 'document_end'],
      ['document-idle', 'document_idle']
    ];
    for (const [metaRunAt, chromeRunAt] of cases) {
      await US.save({
        code: `// ==UserScript==\n// @name Timing ${metaRunAt}\n// @match https://t.example.com/*\n// @run-at ${metaRunAt}\n// @noframes\n// ==/UserScript==\nconsole.log('${metaRunAt}');`,
        enabled: true
      });
    }
    expect(env.registered.size).toBe(4);
    const regs = Array.from(env.registered.values());
    expect(regs.every(r => r.allFrames === false)).toBe(true);
    const bodyReg = regs.find(r => r.js[0].code.includes('Timing document-body'));
    expect(bodyReg.runAt).toBe('document_start');
    expect(bodyReg.js[0].code).toContain('DOMContentLoaded');
  });

  it('does not unregister unrelated third-party script IDs during sync', async () => {
    const env = makeChromeEnv();
    env.registered.set('unrelated_ext_script', { id: 'unrelated_ext_script', matches: ['https://other.test/*'] });
    globalThis.chrome = env.chromeMock; loadCore('core/userscripts.js'); const US = globalThis.CorsairUserScripts;
    await US.sync();
    expect(env.registered.has('unrelated_ext_script')).toBe(true);
  });

  it('executePreview runs one-time targeted preview in USER_SCRIPT world without registering', async () => {
    const env = makeChromeEnv({ executeSupported: true });
    globalThis.chrome = env.chromeMock; loadCore('core/userscripts.js'); const US = globalThis.CorsairUserScripts;

    const prev = await US.executePreview({
      tabId: 42,
      code: `// ==UserScript==\n// @name Preview Only\n// @match https://example.com/*\n// ==/UserScript==\nconsole.log('hi');`,
      world: 'USER_SCRIPT'
    });
    expect(prev.ok).toBe(true);
    expect(prev.method).toBe('userScripts.execute');
    expect(prev.world).toBe('USER_SCRIPT');
    expect(prev.registered).toBe(false);
    expect(env.registered.size).toBe(0);
    expect(env.executeCalls.length).toBe(1);
    expect(env.executeCalls[0].target.tabId).toBe(42);
  });

  it('executePreview reports honest unsupported status on Chrome <135 without userScripts.execute', async () => {
    const env = makeChromeEnv({ executeSupported: false });
    globalThis.chrome = env.chromeMock; loadCore('core/userscripts.js'); const US = globalThis.CorsairUserScripts;
    const prev = await US.executePreview({
      tabId: 42,
      code: `// ==UserScript==\n// @name Preview Only\n// @match https://example.com/*\n// ==/UserScript==\nconsole.log('hi');`
    });
    expect(prev.ok).toBe(false);
    expect(prev.method).toBe('unsupported');
    expect(prev.error).toContain('Chrome 135+');
  });
});

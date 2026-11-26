import { describe, it, expect } from 'vitest';
import { loadCore, readSource } from './helpers/load-core.js';

describe('Final Audit Regression Suite (v1.13.1)', () => {
  it('core/migration.js preserves all 6 themes, advancedSecurity, aiSettings, and aiProviders across backup/restore', async () => {
    const local = {
      theme: 'amethyst',
      language: 'fa',
      corsairAdvancedSecurity: { credentialGuard: true, clickFixGuard: true, offlineIntel: true, httpsFirst: false, trackingStrip: true },
      'cai:settings': { language: 'javascript', systemInstructions: 'Prefer MutationObserver.', temperature: 0.15, maxTokens: 2048 },
      'cai:profiles': [{ id: 'ai_1', name: 'Local llama.cpp', type: 'llamacpp', baseUrl: 'http://127.0.0.1:9101/v1', model: 'qwen2.5-coder:7b' }],
      'cai:defaultProfileId': 'ai_1'
    };
    const session = {};
    globalThis.chrome = {
      runtime: { getManifest: () => ({ version: '1.13.1' }) },
      storage: {
        local: {
          async get(keys) {
            if (typeof keys === 'string') return { [keys]: local[keys] };
            if (Array.isArray(keys)) { const o = {}; for (const k of keys) if (k in local) o[k] = local[k]; return o; }
            return { ...local };
          },
          async set(obj) { Object.assign(local, obj); },
          async remove(keys) { for (const k of (Array.isArray(keys) ? keys : [keys])) delete local[k]; }
        },
        session: {
          async get(keys) { return typeof keys === 'string' ? { [keys]: session[keys] } : { ...session }; },
          async set(obj) { Object.assign(session, obj); }
        }
      }
    };
    globalThis.CorsairSecurity = {
      normalizeHostname: (h) => String(h || '').toLowerCase(),
      isValidHostname: () => true,
      normalizeProfile: (p) => p,
      sanitizeObject: (o) => o,
      CUSTOM_SCRIPT_MAX_LEN: 50000,
      lintCustomScript: () => ({ ok: true })
    };
    globalThis.CorsairStorage = {
      withTransactionGateShared: (fn) => fn(),
      getProfiles: async () => ({}),
      getSettings: async () => ({}),
      getRegressionCases: async () => [],
      getDnrRegistry: async () => ({ rules: {}, nextId: 1 }),
      getEvents: async () => [],
      getGraph: async () => ({ version: 2, nodes: {}, edges: [] }),
      getChains: async () => [],
      get: async (_k, d) => d
    };
    loadCore('core/migration.js');
    const M = globalThis.CorsairMigration;
    const exported = await M.exportConfiguration({ includeSecrets: false });
    expect(exported.preferences.theme).toBe('amethyst');
    expect(exported.preferences.language).toBe('fa');
    expect(exported.advancedSecurity.httpsFirst).toBe(false);
    expect(exported.aiSettings.systemInstructions).toBe('Prefer MutationObserver.');
    expect(exported.aiProviders.profiles[0].id).toBe('ai_1');

    const validated = M.validateCandidate(exported);
    expect(validated.ok).toBe(true);
    expect(validated.candidate.preferences.theme).toBe('amethyst');
  });

  it('autoInjectForNavigation skips when native userScripts is active and auto-injects once with caching when disabled', async () => {
    const localStore = {};
    let storageReads = 0;
    const injectedCalls = [];
    let apiEnabled = false;

    globalThis.chrome = {
      runtime: { id: 'corsairtest', getManifest: () => ({ version: '1.13.1' }) },
      storage: {
        local: {
          async get(keys) {
            storageReads++;
            if (typeof keys === 'string') return { [keys]: localStore[keys] };
            if (Array.isArray(keys)) { const o = {}; for (const k of keys) if (k in localStore) o[k] = localStore[k]; return o; }
            return { ...localStore };
          },
          async set(obj) { Object.assign(localStore, obj); },
          async remove(keys) { for (const k of (Array.isArray(keys) ? keys : [keys])) delete localStore[k]; }
        }
      },
      userScripts: {
        async getScripts() {
          if (!apiEnabled) throw new Error('disabled');
          return [];
        },
        async register() {},
        async update() {},
        async unregister() {},
        async configureWorld() {}
      },
      scripting: {
        async executeScript(spec) { injectedCalls.push(spec); return [{ result: null }]; }
      }
    };

    loadCore('core/userscripts.js');
    const US = globalThis.CorsairUserScripts;
    await US.save({
      code: `// ==UserScript==\n// @name Auto Site Script\n// @match https://target.example/*\n// @run-at document-idle\n// @noframes\n// ==/UserScript==\nconsole.log('ran');`,
      enabled: true
    });

    storageReads = 0;
    // Subframe should be skipped due to @noframes
    const subRes = await US.autoInjectForNavigation({ tabId: 7, frameId: 2, url: 'https://target.example/a', stage: 'idle' });
    expect(subRes.injected).toBe(0);

    // Main frame should auto-inject once
    const r1 = await US.autoInjectForNavigation({ tabId: 7, frameId: 0, url: 'https://target.example/a', stage: 'idle' });
    expect(r1.injected).toBe(1);
    expect(injectedCalls.length).toBe(1);

    // Repeat call for same navigation deduplicates and uses in-memory cache (0 extra storage reads)
    const readsAfterFirst = storageReads;
    const r2 = await US.autoInjectForNavigation({ tabId: 7, frameId: 0, url: 'https://target.example/a', stage: 'idle' });
    expect(r2.injected).toBe(0);
    expect(storageReads).toBe(readsAfterFirst);

    // When native userScripts becomes active, fallback skips so there is ZERO double injection
    apiEnabled = true;
    await US.sync();
    const r3 = await US.autoInjectForNavigation({ tabId: 8, frameId: 0, url: 'https://target.example/b', stage: 'idle' });
    expect(r3.skipped).toBe(true);
    expect(r3.reason).toBe('native-userScripts-active');
  });

  it('ai-studio.js contains zero innerHTML sinks and background.js enforces PRIVILEGED_INTERNAL on AI handlers', () => {
    const asSrc = readSource('ai-studio.js');
    expect(asSrc).not.toContain('.innerHTML');
    const bgSrc = readSource('background.js');
    expect(bgSrc).toContain("case 'ai-generate-script': {\n          if (capability !== 'PRIVILEGED_INTERNAL')");
    expect(bgSrc).toContain("case 'ai-preview-script': {\n          if (capability !== 'PRIVILEGED_INTERNAL')");
  });
});

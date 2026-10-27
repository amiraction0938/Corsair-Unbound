import { describe, it, expect, beforeEach } from 'vitest';
import { installChromeMock } from './helpers/chrome-mock.js';
import { loadCore } from './helpers/load-core.js';

const SCRIPT = `// ==UserScript==
// @name Backup me
// @namespace t
// @match https://example.com/*
// @grant GM_setValue
// @require https://cdn.example.com/lib.js
// ==/UserScript==
console.log(1);`;

function setup() {
  installChromeMock();
  const regs = new Map();
  globalThis.chrome.userScripts = {
    async getScripts() { return Array.from(regs.values()); },
    async register(l) { l.forEach(r => regs.set(r.id, r)); },
    async update(l) { l.forEach(r => regs.set(r.id, r)); },
    async unregister(f) { ((f && f.ids) || []).forEach(i => regs.delete(i)); },
    async configureWorld() {}
  };
  globalThis.chrome.runtime.id = 'testextensionid';
  globalThis.fetch = async (u) => ({ ok: true, text: async () => '/* lib */', headers: { get: () => '' }, arrayBuffer: async () => new ArrayBuffer(0) });
  for (const f of ['core/security.js', 'core/storage.js', 'core/dnr.js', 'core/userscripts.js', 'core/migration.js']) loadCore(f);
}

describe('backup round trip: API keys + userscripts', () => {
  beforeEach(setup);

  it('exports keys and scripts, and restores them into a clean profile', async () => {
    await CorsairStorage.patchSettings({ persistApiKey: true, urlhausAuthKey: 'URLHAUS-KEY-123456' });
    await CorsairStorage.setApiKeySecure('a'.repeat(64));
    const { script } = await CorsairUserScripts.save({ code: SCRIPT });
    await CorsairUserScripts.handleGmMessage({ __cu: 1, op: 'vals:set', id: script.id, data: { k: 'score', v: 42 } }, {});

    const backup = await CorsairMigration.exportConfiguration({ includeSecrets: true });
    expect(backup.apiKeys).toEqual({ virustotal: 'a'.repeat(64), urlhaus: 'URLHAUS-KEY-123456' });
    expect(backup.userscripts.scripts).toHaveLength(1);
    expect(backup.userscripts.values[script.id]).toEqual({ score: 42 });
    expect(backup.settings.urlhausAuthKey).toBeUndefined();
    expect(JSON.stringify(backup.settings)).not.toContain('URLHAUS-KEY');

    // brand-new profile
    setup();
    expect(await CorsairUserScripts.list()).toHaveLength(0);
    expect(await CorsairStorage.getApiKeySecure()).toBeFalsy();

    const res = await CorsairMigration.executeImportTransaction(JSON.parse(JSON.stringify(backup)));
    expect(res.ok, JSON.stringify(res)).toBe(true);
    expect(res.importedUserscripts).toBe(1);
    expect(res.importedApiKeys.sort()).toEqual(['urlhaus', 'virustotal']);

    expect(await CorsairStorage.getApiKeySecure()).toBe('a'.repeat(64));
    expect((await CorsairStorage.getSettings()).urlhausAuthKey).toBe('URLHAUS-KEY-123456');
    const list = await CorsairUserScripts.list();
    expect(list).toHaveLength(1);
    expect(list[0].name).toBe('Backup me');
    const vals = await CorsairUserScripts.handleGmMessage({ __cu: 1, op: 'vals:get', id: list[0].id }, {});
    expect(vals.values).toEqual({ score: 42 });
  });

  it('leaves API keys out when the user opts out, but still keeps userscripts', async () => {
    await CorsairStorage.patchSettings({ persistApiKey: true });
    await CorsairStorage.setApiKeySecure('b'.repeat(64));
    await CorsairUserScripts.save({ code: SCRIPT });
    const backup = await CorsairMigration.exportConfiguration({ includeSecrets: false });
    expect(backup.apiKeys).toEqual({});
    expect(backup.userscripts.scripts).toHaveLength(1);
    expect(JSON.stringify(backup)).not.toContain('b'.repeat(64));
  });

  it('old backups (no userscripts block) still import and convert per-domain scripts', async () => {
    await CorsairStorage.patchSettings({ persistApiKey: true });
    const backup = await CorsairMigration.exportConfiguration({ includeSecrets: false });
    delete backup.userscripts;
    delete backup.apiKeys;
    backup.customDomainScripts = { 'foo.com': { code: 'console.log(1)', enabled: true } };
    setup();
    const res = await CorsairMigration.executeImportTransaction(JSON.parse(JSON.stringify(backup)));
    expect(res.ok, JSON.stringify(res)).toBe(true);
    expect(res.importedUserscripts).toBe(1);
    expect((await CorsairUserScripts.list())[0].migratedFrom).toBe('foo.com');
  });

  it('rejects a malformed userscripts block', async () => {
    const backup = await CorsairMigration.exportConfiguration({ includeSecrets: false });
    backup.userscripts = { scripts: 'nope' };
    const res = await CorsairMigration.executeImportTransaction(JSON.parse(JSON.stringify(backup)));
    expect(res.ok).toBe(false);
  });
});

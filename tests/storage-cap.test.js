import { describe, it, expect, beforeEach } from 'vitest';
import { installChromeMock } from './helpers/chrome-mock.js';
import { loadCore } from './helpers/load-core.js';

function setup() {
  installChromeMock();
  loadCore('core/security.js');
  loadCore('core/storage.js');
}

describe('storage cap: security data is protected from userscript data', () => {
  beforeEach(setup);

  it('the hard cap is 100 MB', () => {
    expect(CorsairStorage.GLOBAL_HARD_CAP).toBe(100 * 1024 * 1024);
  });

  it('userscript keys (cus:*) never count toward the cap', async () => {
    // far more than the cap, all under userscript keys
    const huge = 'x'.repeat(60 * 1024 * 1024);          // ~120 MB by estimateBytes
    await chrome.storage.local.set({ 'cus:rec:cu-big': { code: huge }, 'cus:vals:cu-big': { a: 1 } });
    CorsairStorage.invalidateByteCache();

    const usage = await CorsairStorage.estimateTotalStorageBytes(true);
    expect(usage.total).toBeLessThan(1024 * 1024);
    expect(usage.excluded).toBeGreaterThan(CorsairStorage.GLOBAL_HARD_CAP);
    expect(Object.keys(usage.byKey).some(k => k.startsWith('cus:'))).toBe(false);

    // security writes still go through
    await expect(CorsairStorage.ensureQuotaBudgetBeforeWrite('activityLog', 10_000)).resolves.toBe(true);
    await expect(CorsairStorage.patchSettings({ notifications: false })).resolves.toBeTruthy();
    await expect(CorsairStorage.appendEvent({ type: 'test', severity: 'low', domain: 'a.test', ts: Date.now() })).resolves.not.toThrow();
  });

  it('the cap still protects against runaway SECURITY data', async () => {
    await chrome.storage.local.set({ threatCache: { blob: 'y'.repeat(60 * 1024 * 1024) } });   // ~120 MB
    CorsairStorage.invalidateByteCache();
    await expect(CorsairStorage.ensureQuotaBudgetBeforeWrite('activityLog', 1000))
      .rejects.toThrow(/QuotaExceededError/);
  });

  it('old behaviour regression: 12 MB of userscript data no longer breaks security writes', async () => {
    await chrome.storage.local.set({ 'cus:rec:cu-lib': { requires: { 'https://cdn/x.js': 'z'.repeat(6 * 1024 * 1024) } } });
    CorsairStorage.invalidateByteCache();
    await expect(CorsairStorage.ensureQuotaBudgetBeforeWrite('domainProfiles', 50_000)).resolves.toBe(true);
  });
});

import { describe, it, expect, beforeEach } from 'vitest';
import { installChromeMock } from './helpers/chrome-mock.js';
import { loadCore } from './helpers/load-core.js';

function boot() {
  installChromeMock();
  for (const f of ['core/security.js', 'core/storage.js', 'core/threat-intel.js']) loadCore(f);
}

describe('REGRESSION: a trusted domain must stay trusted after the service worker restarts', () => {
  beforeEach(boot);

  it('a freshly started worker re-reads the trusted list before deciding', async () => {
    await CorsairStorage.set('userTrustedDomains', ['trusted.test']);

    // service worker restarted: new module instance, empty in-memory set
    loadCore('core/threat-intel.js');
    await CorsairThreatIntel.ensureUserTrustedLoaded();

    expect(CorsairThreatIntel.isAllowlisted('trusted.test')).toBe(true);
    expect(CorsairThreatIntel.isAllowlisted('other.test')).toBe(false);
  });

  it('ensureUserTrustedLoaded is cheap when already loaded and survives a storage error', async () => {
    await CorsairStorage.set('userTrustedDomains', ['a.test']);
    await CorsairThreatIntel.refreshUserTrusted();          // what the storage.onChanged listener does
    await CorsairThreatIntel.ensureUserTrustedLoaded();
    await CorsairThreatIntel.ensureUserTrustedLoaded();
    expect(CorsairThreatIntel.isAllowlisted('a.test')).toBe(true);

    // a failing read must keep the previous set instead of wiping it (empty = nothing trusted)
    const orig = CorsairStorage.get;
    CorsairStorage.get = async () => { throw new Error('storage unavailable'); };
    await CorsairThreatIntel.refreshUserTrusted();
    CorsairStorage.get = orig;
    expect(CorsairThreatIntel.isAllowlisted('a.test')).toBe(true);
  });

  it('a storage.onChanged listener keeps the set current (dashboard, import, other contexts)', () => {
    const src = require('node:fs').readFileSync(require('node:path').resolve(__dirname, '../core/threat-intel.js'), 'utf8');
    expect(src).toMatch(/chrome\.storage\.onChanged\.addListener\(\(changes, area\) => \{\s*if \(area === 'local' && changes && changes\.userTrustedDomains\) refreshUserTrusted/);
  });

  it('removeCachedReport forgets only that host', async () => {
    await CorsairStorage.set('threatCache', { 'a.test': { verdict: 'malicious' }, 'b.test': { verdict: 'clean' } });
    expect((await CorsairThreatIntel.removeCachedReport('a.test')).ok).toBe(true);
    const cache = await CorsairStorage.get('threatCache', {});
    expect(cache['a.test']).toBeUndefined();
    expect(cache['b.test']).toBeDefined();
    expect((await CorsairThreatIntel.removeCachedReport('')).ok).toBe(false);
  });
});

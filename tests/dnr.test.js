import { describe, it, expect, beforeEach, beforeAll } from 'vitest';
import { loadCore } from './helpers/load-core.js';
import { installChromeMock } from './helpers/chrome-mock.js';

// Load order matters: dnr.js captures CorsairStorage._unlockedStorageCapability
// at module-load time.
beforeAll(() => {
  loadCore('core/security.js');
});

beforeEach(() => {
  installChromeMock({
    local: { domainProfiles: {}, globalSettings: {} },
    session: {}
  });
  loadCore('core/storage.js');
  loadCore('core/dnr.js');
});

describe('CorsairDNR.makeBlockRule', () => {
  it('produces a valid block rule for a valid source/destination pair', () => {
    const rule = CorsairDNR.makeBlockRule({
      source: 'source.com',
      destination: 'dest.com',
      id: 100001
    });
    expect(rule).toBeTruthy();
    expect(rule.id).toBe(100001);
    expect(rule.priority).toBe(100);
    expect(rule.action).toEqual({ type: 'block' });
    expect(rule.condition.initiatorDomains).toEqual(['source.com']);
    expect(rule.condition.requestDomains).toEqual(['dest.com']);
    expect(rule.condition.resourceTypes).toEqual(['main_frame']);
  });

  it('rejects self-block (source === destination)', () => {
    expect(CorsairDNR.makeBlockRule({
      source: 'same.com', destination: 'same.com', id: 100002
    })).toBeNull();
  });

  it('rejects blocking a subdomain of the source', () => {
    expect(CorsairDNR.makeBlockRule({
      source: 'example.com', destination: 'evil.example.com', id: 100003
    })).toBeNull();
  });

  it('rejects invalid rule IDs (must be > BLOCK_BASE)', () => {
    expect(CorsairDNR.makeBlockRule({
      source: 'a.com', destination: 'b.com', id: 50
    })).toBeNull();
    expect(CorsairDNR.makeBlockRule({
      source: 'a.com', destination: 'b.com', id: null
    })).toBeNull();
  });

  it('rejects malformed hostnames', () => {
    expect(CorsairDNR.makeBlockRule({
      source: 'not a host', destination: 'ok.com', id: 100004
    })).toBeNull();
    expect(CorsairDNR.makeBlockRule({
      source: 'ok.com', destination: '', id: 100005
    })).toBeNull();
  });
});

describe('CorsairDNR.computeNextId — collision handling', () => {
  it('starts at BLOCK_BASE + 1 when nothing is in use', () => {
    const id = CorsairDNR.computeNextId({}, {}, [], 29500);
    expect(id).toBe(CorsairDNR.BLOCK_BASE + 1);
  });

  it('skips IDs that are already present in the current rules', () => {
    const id = CorsairDNR.computeNextId({}, {}, [
      { id: CorsairDNR.BLOCK_BASE + 1 },
      { id: CorsairDNR.BLOCK_BASE + 2 }
    ], 29500);
    expect(id).toBe(CorsairDNR.BLOCK_BASE + 3);
  });

  it('skips IDs that are present in the staged registry map', () => {
    const id = CorsairDNR.computeNextId(
      { 'a>b': CorsairDNR.BLOCK_BASE + 1, 'c>d': CorsairDNR.BLOCK_BASE + 2 },
      { [CorsairDNR.BLOCK_BASE + 1]: 'a>b', [CorsairDNR.BLOCK_BASE + 2]: 'c>d' },
      [],
      29500
    );
    expect(id).toBe(CorsairDNR.BLOCK_BASE + 3);
  });

  it('returns null when the block-ID range is exhausted', () => {
    // Pretend the entire capacity is in use.
    const used = [];
    for (let i = 1; i <= 5; i++) used.push({ id: CorsairDNR.BLOCK_BASE + i });
    const id = CorsairDNR.computeNextId({}, {}, used, 5);
    expect(id).toBeNull();
  });
});

describe('CorsairDNR.getDynamicCapacity', () => {
  it('returns a sane capacity with chrome available', () => {
    const cap = CorsairDNR.getDynamicCapacity('block');
    expect(cap).toBeGreaterThan(0);
    expect(cap).toBeLessThanOrEqual(29500);
  });
});

describe('CorsairDNR — Fortress catch-all sync', () => {
  it('is a no-op for an empty profile map', async () => {
    const r = await CorsairDNR.syncFortressCatchAll({});
    expect(r.ok).toBe(true);
    expect(r.installed).toBe(0);
    expect(r.removed).toBe(0);
    const rules = await CorsairDNR.listFortressCatchAllRules();
    expect(rules).toEqual([]);
  });

  it('installs a catch-all rule for a Fortress-protected profile', async () => {
    await CorsairDNR.syncFortressCatchAll({
      'example.com': { protected: true, mode: 'fortress' }
    });
    const rules = await CorsairDNR.listFortressCatchAllRules();
    expect(rules).toHaveLength(1);
    expect(rules[0].condition.initiatorDomains).toEqual(['example.com']);
    expect(rules[0].condition.domainType).toBe('thirdParty');
    expect(rules[0].action.type).toBe('redirect');
    expect(rules[0].action.redirect.url).toMatch(/blocked\.html\?reason=fortress/);
  });

  it('removes the catch-all rule when a profile is disarmed', async () => {
    await CorsairDNR.syncFortressCatchAll({
      'example.com': { protected: true, mode: 'fortress' }
    });
    // Re-sync with an empty map.
    await CorsairDNR.syncFortressCatchAll({});
    const rules = await CorsairDNR.listFortressCatchAllRules();
    expect(rules).toEqual([]);
  });

  it('skips path-scoped profiles (they are enforced by content-frame-guard)', async () => {
    await CorsairDNR.syncFortressCatchAll({
      'example.com': { protected: true, mode: 'fortress', pathScopes: ['/admin'] }
    });
    const rules = await CorsairDNR.listFortressCatchAllRules();
    expect(rules).toEqual([]);
  });

  it('assigns distinct rule IDs to different hosts (collision-free)', async () => {
    const hosts = ['a.com', 'b.com', 'c.com', 'd.com', 'e.com'];
    const profiles = {};
    for (const h of hosts) profiles[h] = { protected: true, mode: 'fortress' };
    await CorsairDNR.syncFortressCatchAll(profiles);

    const rules = await CorsairDNR.listFortressCatchAllRules();
    const ids = rules.map(r => r.id);
    const idSet = new Set(ids);
    expect(idSet.size).toBe(hosts.length);
  });

  it('is idempotent — re-syncing does not create duplicate rules', async () => {
    const profiles = { 'stable.com': { protected: true, mode: 'fortress' } };
    await CorsairDNR.syncFortressCatchAll(profiles);
    await CorsairDNR.syncFortressCatchAll(profiles);
    await CorsairDNR.syncFortressCatchAll(profiles);
    const rules = await CorsairDNR.listFortressCatchAllRules();
    expect(rules).toHaveLength(1);
  });
});

describe('CorsairDNR — fortress allow rules', () => {
  it('installs an allow rule with priority 200', async () => {
    const r = await CorsairDNR.installFortressAllow('src.com', 'dst.com', 30000);
    expect(r.ok).toBe(true);
    expect(typeof r.ruleId).toBe('number');

    const rules = await CorsairDNR.listFortressAllowRules();
    expect(rules).toHaveLength(1);
    expect(rules[0].priority).toBe(200);
    expect(rules[0].action).toEqual({ type: 'allow' });
  });

  it('is idempotent — same pair reuses the same rule ID', async () => {
    const a = await CorsairDNR.installFortressAllow('src.com', 'dst.com', 30000);
    const b = await CorsairDNR.installFortressAllow('src.com', 'dst.com', 30000);
    expect(b.ruleId).toBe(a.ruleId);
    expect(b.reused).toBe(true);

    const rules = await CorsairDNR.listFortressAllowRules();
    expect(rules).toHaveLength(1);
  });

  it('rejects invalid hostnames', async () => {
    const r = await CorsairDNR.installFortressAllow('', 'dst.com', 30000);
    expect(r.ok).toBe(false);
    expect(r.error).toBe('invalid-domain');
  });

  it('clearFortressAllow removes the rule', async () => {
    await CorsairDNR.installFortressAllow('src.com', 'dst.com', 30000);
    await CorsairDNR.clearFortressAllow('src.com', 'dst.com');
    const rules = await CorsairDNR.listFortressAllowRules();
    expect(rules).toEqual([]);
  });
});

describe('CorsairDNR — user blocklist sync', () => {
  it('installs a session rule per domain with reason=user-blocklist', async () => {
    const r = await CorsairDNR.syncUserBlocklist(['a.com', 'b.com']);
    expect(r.ok).toBe(true);
    expect(r.installed).toBe(2);

    const rules = await CorsairDNR.listUserBlockRules();
    expect(rules).toHaveLength(2);
    for (const rule of rules) {
      expect(rule.action.type).toBe('redirect');
      expect(rule.action.redirect.url).toMatch(/reason=user-blocklist/);
    }
  });

  it('assigns distinct IDs (collision-free)', async () => {
    await CorsairDNR.syncUserBlocklist(['x.com', 'y.com', 'z.com']);
    const rules = await CorsairDNR.listUserBlockRules();
    const ids = new Set(rules.map(r => r.id));
    expect(ids.size).toBe(3);
  });

  it('is idempotent', async () => {
    await CorsairDNR.syncUserBlocklist(['stable.com']);
    await CorsairDNR.syncUserBlocklist(['stable.com']);
    const rules = await CorsairDNR.listUserBlockRules();
    expect(rules).toHaveLength(1);
  });

  it('removes rules when a domain is dropped from the list', async () => {
    await CorsairDNR.syncUserBlocklist(['a.com', 'b.com']);
    await CorsairDNR.syncUserBlocklist(['a.com']);
    const rules = await CorsairDNR.listUserBlockRules();
    expect(rules).toHaveLength(1);
    expect(rules[0].condition.requestDomains).toEqual(['a.com']);
  });

  it('silently skips invalid hostnames', async () => {
    const r = await CorsairDNR.syncUserBlocklist(['a.com', '', null, 'not a host', 'b.com']);
    expect(r.installed).toBe(2);
  });
});
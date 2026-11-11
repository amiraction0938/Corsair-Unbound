import { describe, it, expect, beforeEach } from 'vitest';
import { loadCore } from './helpers/load-core.js';

beforeEach(() => { loadCore('core/autoarm.js'); loadCore('core/block-actions.js'); });

function mkDeps(over = {}) {
  const log = [];
  const state = { blocked: ['evil.test'], trusted: [], profile: null, cache: { 'evil.test': { riskPercentage: 82, verdict: 'malicious', stats: { malicious: 9, suspicious: 2 }, flaggedEngines: ['a', 'b', 'c'] } } };
  const deps = {
    now: () => 5000,
    isTrusted: async (h) => state.trusted.includes(h),
    getBlocked: async () => state.blocked,
    getSettings: async () => ({ autoBlockThreshold: 75 }),
    getReport: async (h) => state.cache[h] || null,
    getProfile: async () => state.profile,
    findAutoBlockEvent: async () => ({ timestamp: 111, reason: 'auto-blocked at risk 82% (threshold 75%)' }),
    patchProfile: async (h, fn) => { state.profile = fn(state.profile); log.push(['patchProfile', state.profile]); return { ok: true }; },
    unblockDomain: async (h) => { state.blocked = state.blocked.filter(x => x !== h); log.push(['unblock', h]); return { ok: true }; },
    blockDomain: async (h) => { state.blocked.push(h); state.trusted = state.trusted.filter(x => x !== h); log.push(['block', h]); return { ok: true }; },
    trustDomain: async (h) => { state.trusted.push(h); state.blocked = state.blocked.filter(x => x !== h); log.push(['trust', h]); return { ok: true }; },
    dropThreatCache: async (h) => { delete state.cache[h]; log.push(['dropCache', h]); },
    forgetAutoArm: async (h) => { log.push(['forgetAutoArm', h]); },
    clearSiteData: async (origins) => { log.push(['wipe', origins]); return { ok: true }; },
    logEvent: async (e) => { log.push(['event', e]); },
    ...over
  };
  return { deps, state, log };
}

describe('explain', () => {
  it('tells why: blocklist membership, auto-block event, scan summary', async () => {
    const { deps } = mkDeps();
    const info = await CorsairBlockActions.explain('evil.test', deps);
    expect(info).toMatchObject({ host: 'evil.test', inBlocklist: true, trusted: false });
    expect(info.report).toMatchObject({ risk: 82, verdict: 'malicious', flagged: 3, malicious: 9 });
    expect(info.auto.reason).toContain('82%');
    expect(info.thresholds.autoBlock).toBe(75);
  });

  it('still answers when nothing is stored', async () => {
    const { deps } = mkDeps({ getReport: async () => null, findAutoBlockEvent: async () => null, getBlocked: async () => [] });
    const info = await CorsairBlockActions.explain('unknown.test', deps);
    expect(info.report).toBeNull();
    expect(info.auto).toBeNull();
    expect(info.inBlocklist).toBe(false);
  });

  it('a failing dependency does not break the explanation', async () => {
    const { deps } = mkDeps({ getReport: async () => { throw new Error('storage down'); } });
    expect((await CorsairBlockActions.explain('evil.test', deps)).report).toBeNull();
  });
});

describe('originsFor', () => {
  it('covers http/https for the host and its www twin, and refuses junk', () => {
    expect(CorsairBlockActions.originsFor('example.com').sort()).toEqual(['http://example.com', 'http://www.example.com', 'https://example.com', 'https://www.example.com']);
    expect(CorsairBlockActions.originsFor('www.example.com')).toHaveLength(4);
    expect(CorsairBlockActions.originsFor('a b')).toEqual([]);
    expect(CorsairBlockActions.originsFor('')).toEqual([]);
    expect(CorsairBlockActions.originsFor('evil.test/../x')).toEqual([]);
  });
});

describe('proceedWithFortress ("back to the site, Fortress ON")', () => {
  it('unblocks, arms Fortress, snoozes auto-block, and returns the URL', async () => {
    const { deps, state } = mkDeps();
    const r = await CorsairBlockActions.proceedWithFortress('evil.test', deps);
    expect(r.ok).toBe(true);
    expect(r.redirectUrl).toBe('https://evil.test/');
    expect(state.blocked).not.toContain('evil.test');
    expect(state.profile).toMatchObject({ protected: true, mode: 'fortress', autoContainRedirects: true, clickbaitGuard: true, autoBlockSnoozeUntil: 5000 + CorsairBlockActions.SNOOZE_MS });
    expect(state.profile.autoArmed).toBeUndefined();
  });

  it('stops (and says so) if the unblock fails; never claims success', async () => {
    const { deps, log } = mkDeps({ unblockDomain: async () => ({ ok: false, error: 'dnr-sync-failed' }) });
    const r = await CorsairBlockActions.proceedWithFortress('evil.test', deps);
    expect(r.ok).toBe(false);
    expect(r.error).toContain('dnr-sync-failed');
    expect(log.find(l => l[0] === 'patchProfile')).toBeUndefined();
    expect(r.redirectUrl).toBeUndefined();
  });

  it('the snooze really stops auto-block from re-blocking the site on the next scan', async () => {
    const { deps, state } = mkDeps();
    await CorsairBlockActions.proceedWithFortress('evil.test', deps);
    const settings = { autoArmFortress: true, autoArmFortressThreshold: 10, autoBlockThreshold: 75 };
    const report = { status: 'analyzed', verdict: 'malicious', riskPercentage: 90 };
    const d = CorsairAutoArm.decide({ settings, report, profile: state.profile, isAllowlisted: false, isBlocked: false, now: 6000 });
    expect(d.action).not.toBe('block');
    expect(d.reason).toBe('already-protected');
    // after the snooze window it can block again
    const later = CorsairAutoArm.decide({ settings, report, profile: state.profile, isAllowlisted: false, isBlocked: false, now: 5000 + CorsairBlockActions.SNOOZE_MS + 1 });
    expect(later.action).toBe('block');
  });
});

describe('markFalsePositive ("it is safe")', () => {
  it('trusts, unblocks, disarms an AUTO-armed profile, forgets the verdict and logs it for tuning', async () => {
    const { deps, state, log } = mkDeps();
    state.profile = { protected: true, mode: 'fortress', autoArmed: true };
    const r = await CorsairBlockActions.markFalsePositive('evil.test', deps);
    expect(r.ok).toBe(true);
    expect(state.trusted).toContain('evil.test');
    expect(state.blocked).not.toContain('evil.test');
    expect(state.profile).toMatchObject({ protected: false, mode: 'standard', autoArmed: false });
    expect(state.cache['evil.test']).toBeUndefined();
    const ev = log.find(l => l[0] === 'event')[1];
    expect(ev).toMatchObject({ type: 'false_positive', domain: 'evil.test' });
    expect(ev.reason).toContain('82%');
    expect(r.redirectUrl).toBe('https://evil.test/');
  });

  it('leaves a profile the USER armed by hand alone', async () => {
    const { deps, state } = mkDeps();
    state.profile = { protected: true, mode: 'fortress' };
    await CorsairBlockActions.markFalsePositive('evil.test', deps);
    expect(state.profile).toEqual({ protected: true, mode: 'fortress' });
  });

  it('fails loudly when trusting fails', async () => {
    const { deps, state } = mkDeps({ trustDomain: async () => ({ ok: false, error: 'unblock-failed' }) });
    const r = await CorsairBlockActions.markFalsePositive('evil.test', deps);
    expect(r.ok).toBe(false);
    expect(state.cache['evil.test']).toBeDefined();           // nothing else was touched
  });

  it('non-critical cleanup failures are reported but do not undo the trust', async () => {
    const { deps } = mkDeps({ dropThreatCache: async () => { throw new Error('quota'); } });
    const r = await CorsairBlockActions.markFalsePositive('evil.test', deps);
    expect(r.ok).toBe(true);
    expect(r.steps.find(s => s.name === 'forget-verdict')).toMatchObject({ ok: false, error: 'quota' });
  });
});

describe('blockAndIsolate ("block, wipe its data, new tab")', () => {
  it('keeps it blocked, puts it in Fortress, wipes data for every origin, and asks for a new tab', async () => {
    const { deps, state, log } = mkDeps();
    state.blocked = [];
    state.trusted = ['evil.test'];
    const r = await CorsairBlockActions.blockAndIsolate('evil.test', deps);
    expect(r.ok).toBe(true);
    expect(r.newTab).toBe(true);
    expect(state.blocked).toContain('evil.test');
    expect(state.trusted).not.toContain('evil.test');
    expect(state.profile).toMatchObject({ protected: true, mode: 'fortress' });
    const wipe = log.find(l => l[0] === 'wipe')[1];
    expect(wipe).toContain('https://evil.test');
    expect(wipe).toContain('http://www.evil.test');
    expect(state.cache['evil.test']).toBeUndefined();
  });

  it('if wiping fails the site stays blocked and the failure is reported', async () => {
    const { deps, state } = mkDeps({ clearSiteData: async () => ({ ok: false, error: 'browsingData unavailable' }) });
    const r = await CorsairBlockActions.blockAndIsolate('evil.test', deps);
    expect(r.ok).toBe(true);
    expect(state.blocked).toContain('evil.test');
    expect(r.steps.find(s => s.name === 'wipe-site-data')).toMatchObject({ ok: false });
  });

  it('refuses when the block itself fails', async () => {
    const { deps } = mkDeps({ blockDomain: async () => ({ ok: false, error: 'invalid-host' }) });
    expect((await CorsairBlockActions.blockAndIsolate('evil.test', deps)).ok).toBe(false);
  });
});

describe('verdict banner gate (once per visit, not per in-page route change)', () => {
  it('shows once per tab+host; SPA navigations and reloads do not show it again', () => {
    const gate = CorsairAutoArm.createBannerGate();
    expect(gate.shouldShow(7, 'instagram.com')).toBe(true);
    for (let i = 0; i < 20; i++) expect(gate.shouldShow(7, 'instagram.com')).toBe(false);   // "next post" x20
    expect(gate.shouldShow(8, 'instagram.com')).toBe(true);                                  // another tab
    expect(gate.shouldShow(7, 'example.org')).toBe(true);                                    // new site in the tab
    expect(gate.shouldShow(7, 'instagram.com')).toBe(true);                                  // coming back = a new visit
  });

  it('reset() forgets a tab; junk input never shows', () => {
    const gate = CorsairAutoArm.createBannerGate();
    gate.shouldShow(1, 'a.test');
    gate.reset(1);
    expect(gate.shouldShow(1, 'a.test')).toBe(true);
    expect(gate.shouldShow(undefined, 'a.test')).toBe(false);
    expect(gate.shouldShow(2, '')).toBe(false);
  });
});

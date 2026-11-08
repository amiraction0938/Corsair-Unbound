import { describe, it, expect, beforeEach } from 'vitest';
import { loadCore } from './helpers/load-core.js';

beforeEach(() => loadCore('core/autoarm.js'));

const S = (o = {}) => ({ autoArmFortress: true, autoArmFortressThreshold: 10, autoBlockThreshold: 75, ...o });
const R = (risk, o = {}) => ({ status: 'analyzed', verdict: 'clean', riskPercentage: risk, ...o });

describe('CorsairAutoArm.decide', () => {
  const d = (over) => CorsairAutoArm.decide({ settings: S(), report: R(50), profile: null, isAllowlisted: false, isBlocked: false, ...over });

  it('THE REPORTED CASE: risk 4% with threshold 3% arms Fortress', () => {
    const r = d({ settings: S({ autoArmFortressThreshold: 3 }), report: R(4) });
    expect(r.action).toBe('arm');
    expect(r.reason).toBe('arm');
    expect(r.armProfile).toBe(true);
  });

  it('arms exactly at the threshold, not below it', () => {
    expect(d({ settings: S({ autoArmFortressThreshold: 4 }), report: R(4) }).action).toBe('arm');
    expect(d({ settings: S({ autoArmFortressThreshold: 5 }), report: R(4) })).toMatchObject({ action: 'none', reason: 'below-threshold' });
  });

  it('does nothing when the feature is switched off', () => {
    expect(d({ settings: S({ autoArmFortress: false }) })).toMatchObject({ action: 'none', reason: 'disabled' });
  });

  it('ignores error reports, missing reports and allowlisted sites', () => {
    expect(d({ report: null }).reason).toBe('no-report');
    expect(d({ report: R(90, { status: 'error' }) }).reason).toBe('report-error');
    expect(d({ report: R(90, { status: 'allowlisted' }) }).reason).toBe('allowlisted');
    expect(d({ isAllowlisted: true }).reason).toBe('allowlisted');
  });

  it('blocks and arms at or above the block threshold', () => {
    const r = d({ report: R(80) });
    expect(r).toMatchObject({ action: 'block', addToBlocklist: true, armProfile: true });
    expect(d({ report: R(75) }).action).toBe('block');
  });

  it('does not re-add an already blocked host', () => {
    expect(d({ report: R(90), isBlocked: true }).addToBlocklist).toBe(false);
  });

  it('respects an explicit user opt-out for Fortress, but still blocks a dangerous site', () => {
    const optOut = { protected: false, mode: 'standard', autoArmed: false };
    expect(d({ report: R(30), profile: optOut })).toMatchObject({ action: 'none', reason: 'user-opt-out' });
    const hi = d({ report: R(90), profile: optOut });
    expect(hi).toMatchObject({ action: 'block', addToBlocklist: true, armProfile: false });
  });

  it('does not touch a profile that is already protected (manual or automatic)', () => {
    expect(d({ profile: { protected: true, mode: 'fortress' }, report: R(30) }).reason).toBe('already-protected');
    expect(d({ profile: { protected: true, mode: 'fortress', autoArmed: true }, report: R(30) }).reason).toBe('already-protected');
  });

  it('REGRESSION: an old profile without an opt-out flag no longer blocks auto-arm', () => {
    expect(d({ profile: { protected: false, mode: 'standard' } }).action).toBe('arm');
    expect(d({ profile: { protected: false, mode: 'standard', autoArmed: true } }).action).toBe('arm');
  });

  it('tolerates junk settings and reports', () => {
    expect(CorsairAutoArm.resolveThresholds({ autoArmFortressThreshold: 'abc', autoBlockThreshold: null })).toEqual({ armMin: 10, blockMin: 75 });
    expect(CorsairAutoArm.resolveThresholds({ autoArmFortressThreshold: -5, autoBlockThreshold: 9999 })).toEqual({ armMin: 1, blockMin: 100 });
    // SAFETY: empty / null / boolean values must fall back to the defaults, never to 1%
    for (const bad of [null, '', '   ', false, true, undefined, [], {}]) {
      expect(CorsairAutoArm.resolveThresholds({ autoArmFortressThreshold: bad, autoBlockThreshold: bad }), String(bad)).toEqual({ armMin: 10, blockMin: 75 });
    }
    expect(CorsairAutoArm.resolveThresholds({ autoArmFortressThreshold: '3', autoBlockThreshold: '60' })).toEqual({ armMin: 3, blockMin: 60 });
    expect(d({ report: { status: 'analyzed', riskPercentage: 'NaN' } }).reason).toBe('below-threshold');
  });
});

describe('CorsairAutoArm.evaluate (applies the decision)', () => {
  let calls, store;
  const mkDeps = (over = {}) => {
    calls = { events: [], evidence: [], patched: [], blocked: [], remembered: [] };
    store = { settings: S({ autoArmFortressThreshold: 3 }), profile: null, blocked: [], allow: false };
    return {
      getSettings: async () => store.settings,
      isAllowlisted: async () => store.allow,
      getProfile: async () => store.profile,
      getUserBlocked: async () => store.blocked,
      addBlocked: async (h) => { calls.blocked.push(h); },
      patchProfile: async (h, fn) => { const p = fn(store.profile); calls.patched.push([h, p]); return { ok: true, profile: p }; },
      logEvent: async (e) => { calls.events.push(e); },
      addEvidence: async (e) => { calls.evidence.push(e); },
      remember: async (h, dg) => { calls.remembered.push([h, dg]); },
      now: () => 1000,
      sleep: async () => {},
      ...over
    };
  };

  it('arms a 4% site at a 3% threshold and records why', async () => {
    const deps = mkDeps();
    const res = await CorsairAutoArm.evaluate('site.test', R(4), deps);
    expect(res).toMatchObject({ action: 'arm', applied: true, error: '' });
    expect(calls.patched).toHaveLength(1);
    expect(calls.patched[0][1]).toMatchObject({ protected: true, mode: 'fortress', autoArmed: true, autoContainRedirects: true, clickbaitGuard: true, autoArmedAt: 1000 });
    expect(calls.events[0]).toMatchObject({ type: 'auto_fortress_armed', domain: 'site.test' });
    expect(calls.remembered[0][1].reason).toBe('arm');
  });

  it('works with the verdict banner turned off (display setting must not matter)', async () => {
    const deps = mkDeps();
    store.settings = S({ autoArmFortressThreshold: 3, siteVerdictBanner: false });
    expect((await CorsairAutoArm.evaluate('site.test', R(4), deps)).applied).toBe(true);
  });

  it('re-evaluates every time (a later lower threshold takes effect)', async () => {
    const deps = mkDeps();
    store.settings = S({ autoArmFortressThreshold: 10 });
    expect((await CorsairAutoArm.evaluate('site.test', R(4), deps)).reason).toBe('below-threshold');
    store.settings = S({ autoArmFortressThreshold: 3 });
    expect((await CorsairAutoArm.evaluate('site.test', R(4), deps)).reason).toBe('arm');
  });

  it('explains itself when it does not arm', async () => {
    const deps = mkDeps();
    store.settings = S({ autoArmFortressThreshold: 10 });
    await CorsairAutoArm.evaluate('site.test', R(4), deps);
    expect(calls.patched).toHaveLength(0);
    expect(calls.remembered[0][1]).toMatchObject({ action: 'none', reason: 'below-threshold', risk: 4, armMin: 10 });
  });

  it('retries once when applying fails, then succeeds', async () => {
    let n = 0;
    const deps = mkDeps({ patchProfile: async (h, fn) => (++n === 1 ? { ok: false, error: 'dnr-reconcile-failed' } : { ok: true, profile: fn(null) }) });
    const res = await CorsairAutoArm.evaluate('site.test', R(4), deps);
    expect(n).toBe(2);
    expect(res.applied).toBe(true);
  });

  it('NEVER fails silently: a persistent failure is logged as auto_arm_failed', async () => {
    const deps = mkDeps({ patchProfile: async () => { throw new Error('QuotaExceededError'); } });
    const res = await CorsairAutoArm.evaluate('site.test', R(4), deps);
    expect(res.applied).toBe(false);
    expect(res.error).toContain('QuotaExceededError');
    expect(calls.events.map(e => e.type)).toContain('auto_arm_failed');
  });

  it('block path: blocks, logs, evidences and arms', async () => {
    const deps = mkDeps();
    await CorsairAutoArm.evaluate('bad.test', R(90), deps);
    expect(calls.blocked).toEqual(['bad.test']);
    expect(calls.events.map(e => e.type)).toEqual(expect.arrayContaining(['auto_block']));
    expect(calls.patched[0][1]).toMatchObject({ protected: true, mode: 'fortress', autoArmed: true });
  });

  it('block path respects opt-out for Fortress but still blocks', async () => {
    const deps = mkDeps();
    store.profile = { protected: false, mode: 'standard', autoArmed: false };
    await CorsairAutoArm.evaluate('bad.test', R(90), deps);
    expect(calls.blocked).toEqual(['bad.test']);
    expect(calls.patched).toHaveLength(0);
  });

  it('a failing diagnostics store never breaks protection', async () => {
    const deps = mkDeps({ remember: async () => { throw new Error('session storage down'); } });
    expect((await CorsairAutoArm.evaluate('site.test', R(4), deps)).applied).toBe(true);
  });
});

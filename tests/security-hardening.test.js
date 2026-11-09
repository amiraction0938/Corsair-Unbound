// @vitest-environment jsdom
import { describe, it, expect, beforeEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { installChromeMock } from './helpers/chrome-mock.js';
import { loadCore } from './helpers/load-core.js';

const root = path.resolve(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');

describe('sender-bound host checks (core/security.js)', () => {
  beforeEach(() => { installChromeMock(); loadCore('core/security.js'); });

  it("accepts only the sender's own host", () => {
    const sender = { url: 'https://evil.example/page', tab: { url: 'https://evil.example/page', id: 3 } };
    expect(CorsairSecurity.hostMatchesSender('evil.example', sender)).toBe(true);
    expect(CorsairSecurity.hostMatchesSender('www.evil.example', sender)).toBe(true);
    expect(CorsairSecurity.hostMatchesSender('bank.example', sender)).toBe(false);
    expect(CorsairSecurity.hostMatchesSender('example', sender)).toBe(false);
    expect(CorsairSecurity.hostMatchesSender('', sender)).toBe(false);
  });

  it('a parent or child domain is NOT the same host', () => {
    const sender = { url: 'https://login.bank.example/' };
    expect(CorsairSecurity.hostMatchesSender('bank.example', sender)).toBe(false);
    expect(CorsairSecurity.hostMatchesSender('x.login.bank.example', sender)).toBe(false);
  });

  it('missing / unparsable senders never match', () => {
    expect(CorsairSecurity.hostMatchesSender('a.example', null)).toBe(false);
    expect(CorsairSecurity.hostMatchesSender('a.example', {})).toBe(false);
    expect(CorsairSecurity.hostMatchesSender('a.example', { url: 'about:blank' })).toBe(false);
  });
});

describe('settings validation (core/storage.js)', () => {
  beforeEach(() => { installChromeMock(); loadCore('core/security.js'); loadCore('core/storage.js'); });

  it('rejects wrong types for known keys and clamps numbers', () => {
    const { patch, rejected } = CorsairStorage.validateSettingsPatch({
      autoArmFortress: 'yes', autoArmFortressThreshold: 0, autoBlockThreshold: 9999, maxRedirectHops: 'abc', notifications: false, customUnknown: { a: 1 }
    });
    expect(rejected.sort()).toEqual(['autoArmFortress', 'maxRedirectHops']);
    expect(patch.autoArmFortressThreshold).toBe(1);
    expect(patch.autoBlockThreshold).toBe(100);
    expect(patch.notifications).toBe(false);
    expect(patch.customUnknown).toEqual({ a: 1 });
  });

  it('null / empty / boolean values can no longer turn a threshold into 1%', async () => {
    for (const bad of [null, '', false, true, undefined, [], {}]) {
      const { patch } = CorsairStorage.validateSettingsPatch({ autoBlockThreshold: bad, autoArmFortressThreshold: bad });
      expect(patch.autoBlockThreshold, String(bad)).toBeUndefined();
      expect(patch.autoArmFortressThreshold, String(bad)).toBeUndefined();
    }
    const s = await CorsairStorage.patchSettings({ autoBlockThreshold: null });
    expect(s.autoBlockThreshold).toBe(75);
  });

  it('string numbers are accepted and converted', async () => {
    const s = await CorsairStorage.patchSettings({ autoArmFortressThreshold: '3' });
    expect(s.autoArmFortressThreshold).toBe(3);
  });

  it('changing a profile drops the content-script fortress-state cache', async () => {
    await chrome.storage.session.set({ corsairFortressStateCache: { 'a.test::/': { armed: false } } });
    await CorsairStorage.upsertProfile('a.test', { protected: true, mode: 'fortress' });
    const r = await chrome.storage.session.get('corsairFortressStateCache');
    expect(r.corsairFortressStateCache).toBeUndefined();
  });
});

describe('page-triggered privileged actions require a REAL click', () => {
  it('the banner buttons ignore synthetic clicks and the frame guard sends no allow rule for them', () => {
    const banner = read('content.js');
    expect(banner).toMatch(/trustBtn\.addEventListener\('click', async \(ev\) => \{[\s\S]{0,700}ev\.isTrusted !== true\) return;/);
    expect(banner).toMatch(/blockBtn\.addEventListener\('click', async \(ev\) => \{\s*if \(!ev \|\| ev\.isTrusted !== true\) return;/);
    expect(banner).not.toMatch(/attachShadow\(\{ mode: 'open' \}\)/);                 // closed shadow roots
    expect(banner).toMatch(/window\.confirm\(\s*t\('banner\.confirmTrustTitle'/);     // clickjacking guard

    const guard = read('content-frame-guard.js');
    expect(guard).toMatch(/destHost && !isSameHost\(destHost\) && e\.isTrusted === true/);
  });

  it('background verifies the sender host for trust / block / link-allow coming from pages', () => {
    const bg = read('background.js');
    for (const type of ['trust-domain', 'block-domain-global']) {
      const block = bg.slice(bg.indexOf(`case '${type}'`), bg.indexOf(`case '${type}'`) + 500);
      expect(block, type).toMatch(/capability === 'PAGE_OBSERVATION' && !hostMatchesSender\(m\.host, s\)/);
    }
    const allow = bg.slice(bg.indexOf("case 'content-link-allow'"), bg.indexOf("case 'content-link-allow'") + 2400);
    expect(allow).toMatch(/hostMatchesSender\(src, s\)/);
    expect(allow).toMatch(/prof\.protected !== true/);
    expect(allow).toMatch(/linkAllowBudgetOk/);
  });

  it('content scripts can only send the six page-observation messages; privileged ones stay extension-only', () => {
    const bg = read('background.js');
    const i = bg.indexOf("if (capability === 'PAGE_OBSERVATION') {\n        if (m.type !== 'page-observation'");
    expect(i, 'page-observation allowlist not found').toBeGreaterThan(0);
    const chain = bg.slice(i, bg.indexOf("send({ ok: false, error: 'unauthorized-sender' })", i));
    const allowed = [...chain.matchAll(/m\.type !== '([\w-]+)'/g)].map(x => x[1]).sort();
    expect(allowed).toEqual(['block-domain-global', 'content-link-allow', 'content-popup-blocked', 'content-security-event', 'page-observation', 'trust-domain']);
    for (const type of ['us-save', 'us-import-url', 'patch-settings', 'get-autoarm-status', 'export-config', 'import-config', 'patch-profile']) expect(allowed).not.toContain(type);
  });
});

describe('manifest hardening', () => {
  it('extension pages have an explicit strict CSP', () => {
    const m = JSON.parse(read('manifest.json'));
    const csp = m.content_security_policy.extension_pages;
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("object-src 'self'");
    expect(csp).toContain("base-uri 'none'");
    expect(csp).not.toMatch(/unsafe-eval|unsafe-inline|\*/);
  });
});

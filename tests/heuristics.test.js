import { describe, it, expect, beforeAll } from 'vitest';
import { loadCore } from './helpers/load-core.js';

beforeAll(() => {
  loadCore('core/heuristics.js');
});
describe('CorsairHeuristics.analyze — clean inputs', () => {
  it('returns risk 0 for a neutral domain', () => {
    const r = CorsairHeuristics.analyze('example.com');
    expect(r.risk).toBe(0);
    expect(r.signals).toEqual([]);
    expect(r.label).toBe('example');
    expect(r.tld).toBe('com');
  });

  it('returns risk 0 for exact brand matches (no false positive)', () => {
    for (const host of ['google.com', 'github.com', 'wikipedia.org', 'paypal.com', 'amazon.com']) {
      const r = CorsairHeuristics.analyze(host);
      expect(r.risk, `expected ${host} to score 0`).toBe(0);
    }
  });

  it('returns risk 0 for well-known subdomains of a brand', () => {
    const r = CorsairHeuristics.analyze('analytics.google.com');
    expect(r.risk).toBe(0);
  });
});

describe('CorsairHeuristics.analyze — typosquatting', () => {
  it('flags digit substitution as typosquatting-digits (paypa1 vs paypal)', () => {
    const r = CorsairHeuristics.analyze('paypa1.com');
    const sig = r.signals.find(s => s.kind === 'typosquatting-digits');
    expect(sig, 'digit substitution should be detected').toBeTruthy();
    expect(sig.brand).toBe('paypal');
    expect(sig.points).toBe(40);
    expect(r.risk).toBe(40);
  });

  it('flags hyphen insertion as typosquatting-hyphens (pay-pal vs paypal)', () => {
    const r = CorsairHeuristics.analyze('pay-pal.com');
    const sig = r.signals.find(s => s.kind === 'typosquatting-hyphens');
    expect(sig).toBeTruthy();
    expect(sig.brand).toBe('paypal');
    expect(sig.points).toBe(35);
  });

  it('flags single-character typos as typosquatting-levenshtein (gooogle vs google)', () => {
    const r = CorsairHeuristics.analyze('gooogle.com');
    const sig = r.signals.find(s => s.kind === 'typosquatting-levenshtein');
    expect(sig).toBeTruthy();
    expect(sig.brand).toBe('google');
    expect(sig.distance).toBe(1);
  });

  it('identifies the correct brand for each single-brand typosquat', () => {
    // NOTE: compound typosquats (e.g. "amaz0n-paypal") are a known
    // limitation of the current single-brand matcher — documented for
    // a future phase. What we DO verify here is that when exactly one
    // brand is the source, the signal names THAT brand, not some
    // other brand earlier in the iteration order.
    const cases = [
      ['paypa1.com',   'paypal'],
      ['g00gle.com',   'google'],
      ['amaz0n.com',   'amazon'],
      ['faceb00k.com', 'facebook']
    ];
    for (const [host, expectedBrand] of cases) {
      const r = CorsairHeuristics.analyze(host);
      const squat = r.signals.find(s => s.kind.startsWith('typosquatting'));
      expect(squat, `no typosquat signal for ${host}`).toBeTruthy();
      expect(squat.brand, `wrong brand for ${host}`).toBe(expectedBrand);
    }
  });
});

describe('CorsairHeuristics.analyze — homograph / mixed script', () => {
  it('detects Cyrillic-in-Latin homograph (Cyrillic "а" in "аpple")', () => {
    const r = CorsairHeuristics.analyze('\u0430pple.com'); // Cyrillic а
    const sig = r.signals.find(s => s.kind === 'homograph');
    expect(sig).toBeTruthy();
    expect(sig.points).toBe(45);
  });

  it('detects Greek-in-Latin homograph', () => {
    const r = CorsairHeuristics.analyze('\u03B1mazon.com'); // Greek α
    const sig = r.signals.find(s => s.kind === 'homograph');
    expect(sig).toBeTruthy();
  });

  it('does not flag pure-ASCII punycode as homograph (only punycode signal)', () => {
    const r = CorsairHeuristics.analyze('xn--80ak6aa92e.com');
    expect(r.signals.find(s => s.kind === 'punycode')).toBeTruthy();
    expect(r.signals.find(s => s.kind === 'homograph')).toBeFalsy();
  });
});

describe('CorsairHeuristics.analyze — TLDs', () => {
  it('assigns 30 pts for high-risk TLD (.tk)', () => {
    const r = CorsairHeuristics.analyze('something.tk');
    const sig = r.signals.find(s => s.kind === 'suspicious-tld');
    expect(sig).toBeTruthy();
    expect(sig.tld).toBe('tk');
    expect(sig.points).toBe(30);
  });

  it('assigns 15 pts for medium-risk TLD (.click)', () => {
    // .click is in SUSPICIOUS_TLDS but NOT in HIGH_RISK_TLDS,
    // so it exercises the 15-point branch. (.top and .tk are in
    // HIGH_RISK_TLDS and correctly score 30.)
    const r = CorsairHeuristics.analyze('something.click');
    const sig = r.signals.find(s => s.kind === 'suspicious-tld');
    expect(sig).toBeTruthy();
    expect(sig.tld).toBe('click');
    expect(sig.points).toBe(15);
  });

  it('does not flag common TLDs (.com, .org, .io, .dev)', () => {
    for (const tld of ['com', 'org', 'net', 'io', 'dev']) {
      const r = CorsairHeuristics.analyze(`neutral-${tld}.${tld}`);
      expect(r.signals.find(s => s.kind === 'suspicious-tld'), `${tld} should be clean`).toBeFalsy();
    }
  });
});

describe('CorsairHeuristics.analyze — registration age', () => {
  const daysAgo = (n) => Math.floor((Date.now() - n * 86400000) / 1000);

  it('flags recently-registered (<30 days) with 30 pts', () => {
    const r = CorsairHeuristics.analyze('newthing.com', { creationDate: daysAgo(5) });
    const sig = r.signals.find(s => s.kind === 'recently-registered');
    expect(sig).toBeTruthy();
    expect(sig.points).toBe(30);
  });

  it('flags new-domain (30–90 days) with 15 pts', () => {
    const r = CorsairHeuristics.analyze('newthing.com', { creationDate: daysAgo(60) });
    const sig = r.signals.find(s => s.kind === 'new-domain');
    expect(sig).toBeTruthy();
    expect(sig.points).toBe(15);
  });

  it('does not flag domains older than 90 days', () => {
    const r = CorsairHeuristics.analyze('oldthing.com', { creationDate: daysAgo(400) });
    expect(r.signals.find(s => s.kind === 'recently-registered')).toBeFalsy();
    expect(r.signals.find(s => s.kind === 'new-domain')).toBeFalsy();
  });

  it('does not flag domains with no creation date (falls back to nothing)', () => {
    const r = CorsairHeuristics.analyze('unknown.com', {});
    expect(r.signals.find(s => s.kind === 'recently-registered')).toBeFalsy();
  });
});

describe('CorsairHeuristics.analyze — structure', () => {
  it('flags excessive hyphens (>=3)', () => {
    const r = CorsairHeuristics.analyze('a-b-c-d.com');
    expect(r.signals.find(s => s.kind === 'excessive-hyphens')).toBeTruthy();
  });

  it('flags very long labels (>25 chars)', () => {
    const r = CorsairHeuristics.analyze('thisisaverylongdomainlabel.com');
    expect(r.signals.find(s => s.kind === 'very-long-label')).toBeTruthy();
  });

  it('flags deeply nested subdomains (>=4 dots)', () => {
    const r = CorsairHeuristics.analyze('a.b.c.d.example.com');
    expect(r.signals.find(s => s.kind === 'deep-subdomains')).toBeTruthy();
  });

  it('flags brand in subdomain when absent from main label', () => {
    const r = CorsairHeuristics.analyze('paypal.evil-site.com');
    const sig = r.signals.find(s => s.kind === 'brand-in-subdomain');
    expect(sig).toBeTruthy();
    expect(sig.brand).toBe('paypal');
  });
});

describe('CorsairHeuristics.analyze — total risk capping', () => {
  it('caps total risk at 100 even with many signals', () => {
    // Combine every signal we can: mixed script + high-risk TLD +
    // brand in subdomain + deep subdomain + digits.
    const r = CorsairHeuristics.analyze('\u0430maz0n.paypal.evil.deep.co.tk', {
      creationDate: Math.floor((Date.now() - 2 * 86400000) / 1000)
    });
    expect(r.risk).toBeLessThanOrEqual(100);
    expect(r.risk).toBeGreaterThan(50);
  });
});

describe('CorsairHeuristics.levenshtein', () => {
  it('returns 0 for identical strings', () => {
    expect(CorsairHeuristics.levenshtein('abc', 'abc')).toBe(0);
  });

  it('returns 1 for single substitution', () => {
    expect(CorsairHeuristics.levenshtein('abc', 'abd')).toBe(1);
  });

  it('returns 1 for single insertion / deletion', () => {
    expect(CorsairHeuristics.levenshtein('abc', 'abcd')).toBe(1);
    expect(CorsairHeuristics.levenshtein('abcd', 'abc')).toBe(1);
  });

  it('returns the shorter length when one side is empty', () => {
    expect(CorsairHeuristics.levenshtein('', 'abc')).toBe(3);
    expect(CorsairHeuristics.levenshtein('abc', '')).toBe(3);
  });

  it('returns 999 when either string exceeds the 60-char safety cap', () => {
    expect(CorsairHeuristics.levenshtein('a'.repeat(80), 'b'.repeat(3))).toBe(999);
  });
});

describe('CorsairHeuristics.analyze — empty / malformed input', () => {
  it('returns zero risk for empty host', () => {
    const r = CorsairHeuristics.analyze('');
    expect(r.risk).toBe(0);
    expect(r.signals).toEqual([]);
  });

  it('returns zero risk for non-string input', () => {
    const r = CorsairHeuristics.analyze(null);
    expect(r.risk).toBe(0);
  });
});
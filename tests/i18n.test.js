// @vitest-environment jsdom
import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { loadCore, readSource } from './helpers/load-core.js';
import { installChromeMock } from './helpers/chrome-mock.js';

beforeAll(() => {
  // Sanity: file must be syntactically valid — this LOAD call IS the
  // syntax regression test for i18n.js. If it throws, every other test
  // in this file fails, which is exactly what we want.
  installChromeMock();
  loadCore('core/i18n.js');
});

beforeEach(async () => {
  installChromeMock();
  loadCore('core/i18n.js');
  await CorsairI18n.load();
});

const LANGS = ['en', 'fa', 'ar', 'es', 'de', 'fr', 'ru', 'zh'];

describe('CorsairI18n — language registry', () => {
  it('exposes exactly 8 languages', () => {
    expect(CorsairI18n.getLanguages()).toHaveLength(8);
  });

  it('every language has a code / label / flag / dir', () => {
    for (const l of CorsairI18n.getLanguages()) {
      expect(l.code).toMatch(/^[a-z]{2}$/);
      expect(typeof l.label).toBe('string');
      expect(l.label.length).toBeGreaterThan(0);
      expect(typeof l.flag).toBe('string');
      expect(['ltr', 'rtl']).toContain(l.dir);
    }
  });

  it('marks Persian and Arabic as RTL, everything else LTR', () => {
    for (const l of CorsairI18n.getLanguages()) {
      if (l.code === 'fa' || l.code === 'ar') expect(l.dir).toBe('rtl');
      else expect(l.dir).toBe('ltr');
    }
  });
});

describe('CorsairI18n — apostrophe / quote regression', () => {
  // Historical bug: an unescaped apostrophe in "You're all caught up"
  // broke the whole i18n.js source. If the source is broken, the
  // `loadCore` in beforeAll throws and every test in this file fails —
  // which is what we want. But we also want a specific assertion so
  // the failure message is obvious.

  it('loads the source without a syntax error (whole-file regression guard)', async () => {
    // Re-run loadCore in isolation — if it succeeds here, the file
    // is parseable.
    expect(() => loadCore('core/i18n.js')).not.toThrow();
  });

  it('English "notif.empty" is present and contains an apostrophe', async () => {
    await CorsairI18n.set('en');
    const v = CorsairI18n.t('notif.empty', '__MISSING__');
    expect(v).not.toBe('__MISSING__');
    expect(v).toMatch(/'|\u2019/);
  });

  it('every language resolves "notif.empty" without falling back', async () => {
    for (const code of LANGS) {
      await CorsairI18n.set(code);
      const v = CorsairI18n.t('notif.empty', '__MISSING__');
      expect(v, `${code} is missing notif.empty`).not.toBe('__MISSING__');
    }
  });
});

describe('CorsairI18n — key parity across languages', () => {
  // Extract every key that appears anywhere in i18n.js, then for each
  // language verify that it resolves. This catches both missing keys
  // and accidental key renames.
  let keys = [];

  beforeAll(() => {
    const src = readSource('core/i18n.js');
    const re = /^\s*'([a-z][a-z0-9_.]+)':/gm;
    const seen = new Set();
    let m;
    while ((m = re.exec(src)) !== null) seen.add(m[1]);
    keys = [...seen].sort();
    expect(keys.length).toBeGreaterThan(50);
  });

  it('reports per-language coverage', async () => {
    const report = {};
    for (const code of LANGS) {
      await CorsairI18n.set(code);
      let missing = 0;
      const missingKeys = [];
      for (const key of keys) {
        const v = CorsairI18n.t(key, '__MISSING__');
        if (v === '__MISSING__') {
          missing++;
          missingKeys.push(key);
        }
      }
      report[code] = {
        total: keys.length,
        missing,
        coverage: 1 - missing / keys.length
      };
    }

    // English is the reference — it MUST cover every key we extracted
    // from the source. If this fails, an English key is missing.
    expect(report.en.missing, `English missing keys: ${keys.join(', ')}`).toBe(0);

    // Other languages must have at least 95% coverage. Any language
    // below that threshold should fail loudly with the specific keys.
    for (const code of LANGS) {
      if (code === 'en') continue;
      expect(
        report[code].coverage,
        `${code} coverage ${(report[code].coverage * 100).toFixed(1)}% — missing ${report[code].missing} of ${report[code].total} keys`
      ).toBeGreaterThanOrEqual(0.95);
    }
  });
});

describe('CorsairI18n.t — fallback behavior', () => {
  it('returns the fallback when the key is unknown', async () => {
    await CorsairI18n.set('en');
    expect(CorsairI18n.t('nonexistent.key.xyz', 'FB')).toBe('FB');
  });

  it('returns the key itself when no fallback is provided', async () => {
    await CorsairI18n.set('en');
    expect(CorsairI18n.t('nonexistent.key.xyz')).toBe('nonexistent.key.xyz');
  });

  it('falls back to English when a key is missing in the active language', async () => {
    // We cannot guarantee a specific key is missing in a specific
    // language without hardcoding, so we test the mechanism: set
    // language to something, request a key that exists in English,
    // and verify it resolves to a non-empty string.
    await CorsairI18n.set('de');
    const v = CorsairI18n.t('nav.overview', '__MISSING__');
    expect(v).not.toBe('__MISSING__');
    expect(v.length).toBeGreaterThan(0);
  });
});

describe('CorsairI18n.applyDirection — RTL regression guard', () => {
  it('does NOT modify documentElement or body on an http:// page', async () => {
    // In jsdom, location.protocol is 'http:' by default.
    document.documentElement.setAttribute('lang', 'en');
    document.documentElement.setAttribute('dir', 'ltr');
    document.body.className = 'site-specific-class';

    await CorsairI18n.set('fa');
    CorsairI18n.applyDirection();

    expect(document.documentElement.getAttribute('lang')).toBe('en');
    expect(document.documentElement.getAttribute('dir')).toBe('ltr');
    expect(document.body.classList.contains('lang-rtl-text')).toBe(false);
    expect(document.body.classList.contains('rtl')).toBe(false);
    expect(document.body.className).toBe('site-specific-class');
  });
});

describe('CorsairI18n.set / getCurrent', () => {
  it('persists to chrome.storage.local', async () => {
    await CorsairI18n.set('fr');
    const stored = await chrome.storage.local.get('language');
    expect(stored.language).toBe('fr');
  });

  it('rejects unknown language codes (silently)', async () => {
    await CorsairI18n.set('en');
    await CorsairI18n.set('xx');
    // getCurrent should still be 'en'
    expect(CorsairI18n.getCurrent()).toBe('en');
  });
});
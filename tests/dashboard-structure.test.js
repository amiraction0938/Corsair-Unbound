// @vitest-environment jsdom
import { describe, it, expect, beforeEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { installChromeMock } from './helpers/chrome-mock.js';

const root = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'dashboard.html'), 'utf8');
const js = fs.readFileSync(path.join(root, 'dashboard.js'), 'utf8');

function slice(startMarker, endMarker) {
  const a = js.indexOf(startMarker);
  const b = js.indexOf(endMarker, a);
  if (a < 0 || b < 0) throw new Error(`markers not found: ${startMarker}`);
  return js.slice(a, b);
}
function extractFn(name) {
  const start = js.indexOf(`function ${name}(`);
  if (start < 0) throw new Error(`${name} not found`);
  let depth = 0;
  // body starts after the closing paren of the parameter list (params may contain braces)
  for (let j = js.indexOf(') {', start) + 2; j < js.length; j++) {
    if (js[j] === '{') depth++;
    else if (js[j] === '}') { depth--; if (depth === 0) return js.slice(start, j + 1); }
  }
  throw new Error('unbalanced');
}

describe('dashboard layout', () => {
  beforeEach(() => { document.documentElement.innerHTML = html.replace(/<script[\s\S]*?<\/script>/g, ''); });

  const navViews = () => [...document.querySelectorAll('.sidebar-nav .nav-item')].map(b => b.dataset.view);

  it('every nav item has a matching view section and a registered view key', () => {
    const keys = [...js.match(/const VIEW_KEYS = \{([\s\S]*?)\};/)[1].matchAll(/(\w+):/g)].map(m => m[1]);
    for (const v of navViews()) {
      expect(document.getElementById(`view-${v}`), `view-${v}`).not.toBeNull();
      expect(keys, `VIEW_KEYS has ${v}`).toContain(v);
    }
  });

  it('the sidebar is split into four labelled groups in a sensible order', () => {
    const order = [...document.querySelectorAll('.sidebar-nav > *')].map(el =>
      el.classList.contains('nav-group-title') ? 'G:' + el.dataset.en : el.dataset.view);
    expect(order).toEqual([
      'G:Monitor', 'overview', 'analytics', 'activity',
      'G:Protection', 'domains', 'security', 'privacy',
      'G:Tools', 'scripts', 'api',
      'G:System', 'settings', 'about'
    ]);
  });

  it('userscripts live on their own page, no longer inside Security', () => {
    expect(document.querySelector('#view-scripts .custom-scripts-panel')).not.toBeNull();
    expect(document.querySelector('#view-scripts #usGuide')).not.toBeNull();
    expect(document.querySelector('#view-security .custom-scripts-panel')).toBeNull();
  });

  it('the notification bell is gone', () => {
    expect(document.getElementById('notifBell')).toBeNull();
  });

  it('the backup panel offers the API-key option (checked by default)', () => {
    const cb = document.getElementById('exportIncludeSecrets');
    expect(cb).not.toBeNull();
    expect(cb.checked).toBe(true);
  });

  it('the search field has its own styled class', () => {
    expect(document.getElementById('scriptSearch').classList.contains('script-search')).toBe(true);
    const css = fs.readFileSync(path.join(root, 'dashboard.css'), 'utf8');
    expect(css).toMatch(/\.script-search\s*\{/);
  });
});

describe('userscript guide (EN / FA) and AI prompt', () => {
  let ui, state;

  beforeEach(() => {
    document.documentElement.innerHTML = html.replace(/<script[\s\S]*?<\/script>/g, '');
    state = { guideLang: 'en', guideTab: 'how' };
    const src = slice('const US_GUIDE = {', 'const USERSCRIPT_TEMPLATE') + '\n' + '';
    const fn = new Function('state', 'document', '$', 'isFaUi', 'navigator',
      `${src}; return { US_GUIDE, renderUserscriptGuide };`);
    ui = fn(state, document, (id) => document.getElementById(id), () => false, { clipboard: { writeText: async () => {} } });
  });

  it('renders the English guide with the key concepts', () => {
    ui.renderUserscriptGuide();
    const box = document.getElementById('usGuide');
    expect(box.dir).toBe('ltr');
    const text = box.textContent;
    for (const w of ['@match', '@grant', '@run-at', '@require', 'GM_xmlhttpRequest', 'GM_setValue', 'MutationObserver', 'Allow User Scripts']) {
      expect(text, w).toContain(w);
    }
  });

  it('renders the Persian guide right-to-left', () => {
    state.guideLang = 'fa';
    ui.renderUserscriptGuide();
    const box = document.getElementById('usGuide');
    expect(box.dir).toBe('rtl');
    expect(box.textContent).toContain('اسکریپت کاربر');
    expect(box.textContent).toContain('@grant');
    expect(document.getElementById('usTabPrompt').textContent).toContain('پرامپت');
  });

  it('the AI prompt tab shows the checklist and a copy-ready prompt (both languages)', () => {
    for (const lang of ['en', 'fa']) {
      state.guideLang = lang; state.guideTab = 'prompt';
      ui.renderUserscriptGuide();
      const pre = document.querySelector('#usGuide .us-prompt');
      expect(pre, lang).not.toBeNull();
      expect(pre.textContent).toContain('==UserScript==');
      expect(pre.textContent).toContain('@grant none');
      expect(pre.textContent).toContain('GM_xmlhttpRequest');
      expect(pre.textContent).toContain('MutationObserver');
      expect(pre.textContent).toMatch(/<[^>]+>/);   // fill-in placeholders
      expect(document.querySelectorAll('#usGuide .us-list li').length).toBeGreaterThanOrEqual(6);
      expect(document.querySelector('#usGuide .btn-primary')).not.toBeNull();
    }
  });

  it('every GM function the guide documents really exists in the engine', async () => {
    const engine = fs.readFileSync(path.join(root, 'core/userscripts.js'), 'utf8');
    const documented = [...new Set(
      [...JSON.stringify(ui.US_GUIDE.en.cards).matchAll(/GM_(\w+)/g)].map(m => m[1].toLowerCase())
    )];
    for (const name of documented) {
      if (['getvalues', 'setvalues', 'deletevalues'].includes(name)) { expect(engine.toLowerCase()).toContain(name); continue; }
      expect(engine.toLowerCase(), `GM_${name}`).toContain(name);
    }
  });
});

describe('settings are grouped but nothing was lost', () => {
  it('renders every previous setting key exactly once, inside four groups', () => {
    document.body.innerHTML = '<div id="settingsForm" class="settings-grid"></div>';
    const state = { settings: {} };
    const src = ['renderSettings', 'makeSliderRow', 'readSettingsForm'].map(extractFn).join('\n');
    const fn = new Function('state', 'document', '$', 't', 'tx', `${src}; return { renderSettings, readSettingsForm };`);
    const api = fn(state, document, (id) => document.getElementById(id), (k, d) => d, (en) => en);
    api.renderSettings();

    expect(document.querySelectorAll('.settings-group')).toHaveLength(4);
    const keys = [...document.querySelectorAll('#settingsForm [data-key]')].map(e => e.dataset.key).sort();
    expect(keys).toEqual([
      'autoArmFortress', 'downloadGuard', 'enforceSuspiciousRedirects', 'logEvents', 'maxRedirectHops',
      'notifications', 'notifyOnSafeSites', 'observationEnabled', 'resolverEnabled', 'siteVerdictBanner',
      'threatIntelAutoScan', 'threatIntelEnabled', 'verificationEnabled'
    ]);
    const patch = api.readSettingsForm();
    expect(Object.keys(patch)).toEqual(expect.arrayContaining(['autoArmFortressThreshold', 'autoBlockThreshold', 'maxRedirectHops']));
  });
});

describe('product tour', () => {
  const stops = [...js.slice(js.indexOf('const TOUR_STOP_DEFS = ['), js.indexOf('\n];', js.indexOf('const TOUR_STOP_DEFS = [')))
    .matchAll(/view: (null|'(\w+)'),\s*target: '([^']+)',\s*titleKey: '([^']+)',[\s\S]*?descKey: '([^']+)'/g)]
    .map(m => ({ view: m[2] || null, target: m[3], titleKey: m[4], descKey: m[5] }));

  it('has the new stops (userscripts, guide, settings, backup) in a sensible order', () => {
    expect(stops.length).toBe(11);
    const keys = stops.map(s => s.titleKey);
    expect(keys.indexOf('tour.stepScripts.title')).toBeGreaterThan(keys.indexOf('tour.step6.title'));
    expect(keys.indexOf('tour.stepGuide.title')).toBe(keys.indexOf('tour.stepScripts.title') + 1);
    expect(keys.indexOf('tour.stepBackup.title')).toBe(keys.length - 1);
  });

  it('every stop targets an element that exists on the right page', () => {
    document.documentElement.innerHTML = html.replace(/<script[\s\S]*?<\/script>/g, '');
    for (const s of stops) {
      const el = document.querySelector(s.target);
      expect(el, s.target).not.toBeNull();
      if (s.view) expect(el.closest(`#view-${s.view}`), `${s.target} inside view-${s.view}`).not.toBeNull();
    }
  });

  it('every stop has a translation in all 8 languages', async () => {
    installChromeMock();
    (0, eval)(fs.readFileSync(path.join(root, 'core/i18n.js'), 'utf8'));
    for (const lang of ['en', 'fa', 'ar', 'es', 'de', 'fr', 'ru', 'zh']) {
      await CorsairI18n.set(lang);
      for (const s of stops) {
        for (const k of [s.titleKey, s.descKey]) {
          expect(CorsairI18n.t(k, '__MISSING__'), `${lang} ${k}`).not.toBe('__MISSING__');
        }
      }
    }
  });
});

describe('Persian coverage', () => {
  it('the previously missing API / URLhaus keys now exist in Persian', async () => {
    installChromeMock();
    (0, eval)(fs.readFileSync(path.join(root, 'core/i18n.js'), 'utf8'));
    await CorsairI18n.set('fa');
    const keys = ['api.verifying', 'api.savedVerified', 'api.savedRateLimited', 'api.verifyFailed', 'api.invalidKey',
      'api.invalidLength', 'api.networkError', 'api.emptyKey', 'api.alreadySaved', 'urlhaus.disabled', 'urlhaus.verifying',
      'urlhaus.savedVerified', 'urlhaus.savedRateLimited', 'urlhaus.verifyFailed', 'urlhaus.invalidKey', 'urlhaus.invalidLength',
      'urlhaus.networkError', 'urlhaus.emptyKey', 'urlhaus.alreadySaved', 'update.modal.step3.button'];
    for (const k of keys) {
      const v = CorsairI18n.t(k, '__MISSING__');
      expect(v, k).not.toBe('__MISSING__');
      expect(v, k).toMatch(/[\u0600-\u06FF]/);
    }
  });

  it('no language still claims the API key is "memory only / never in backups"', async () => {
    installChromeMock();
    (0, eval)(fs.readFileSync(path.join(root, 'core/i18n.js'), 'utf8'));
    for (const lang of ['en', 'fa', 'ar', 'es', 'de', 'fr', 'ru', 'zh']) {
      await CorsairI18n.set(lang);
      for (const k of ['vt.subtitle', 'vt.keyStorageNote', 'onboarding.step4.subtitle']) {
        const v = CorsairI18n.t(k, '');
        expect(v, `${lang} ${k}`).not.toMatch(/never written to disk|never included in backups|Nur im Speicher\.$|Solo en memoria\.$|En mémoire uniquement\.$/);
      }
    }
  });

  it('static English UI pieces carry a Persian counterpart (data-fa attributes)', () => {
    document.documentElement.innerHTML = html.replace(/<script[\s\S]*?<\/script>/g, '');
    for (const id of ['scriptNewBtn', 'scriptImportBtn', 'scriptImportFileBtn', 'urlhausKeySave', 'apiKeyMissingWarning']) {
      const el = document.getElementById(id);
      expect(el, id).not.toBeNull();
      expect(el.dataset.fa, id).toMatch(/[\u0600-\u06FF]/);
    }
    expect(document.getElementById('scriptSearch').dataset.faPh).toMatch(/[\u0600-\u06FF]/);
  });
});

describe('applyBilingual', () => {
  it('switches text, html, placeholder, title and aria-label to Persian', () => {
    document.body.innerHTML = `
      <span id="a" data-en="Hello" data-fa="سلام">Hello</span>
      <div id="b" data-en-html="<b>One</b>" data-fa-html="<b>یک</b>"><b>One</b></div>
      <input id="c" placeholder="Search" data-en-ph="Search" data-fa-ph="جستجو">
      <button id="d" title="Close" aria-label="Close" data-en-title="Close" data-fa-title="بستن" data-en-aria="Close" data-fa-aria="بستن"></button>`;
    for (const fa of [true, false]) {
      const fn = new Function('document', 'isFaUi', `${extractFn('applyBilingual')}; applyBilingual();`);
      fn(document, () => fa);
      expect(document.getElementById('a').textContent).toBe(fa ? 'سلام' : 'Hello');
      expect(document.getElementById('b').innerHTML).toBe(fa ? '<b>یک</b>' : '<b>One</b>');
      expect(document.getElementById('c').getAttribute('placeholder')).toBe(fa ? 'جستجو' : 'Search');
      expect(document.getElementById('d').getAttribute('title')).toBe(fa ? 'بستن' : 'Close');
      expect(document.getElementById('d').getAttribute('aria-label')).toBe(fa ? 'بستن' : 'Close');
    }
  });
});

describe('translation tables', () => {
  const i18n = fs.readFileSync(path.join(root, 'core/i18n.js'), 'utf8').replace(/\r\n/g, '\n').split('\n');
  const starts = i18n.map((l, i) => [l, i]).filter(([l]) => /^\s{2,6}(en|fa|ar|es|de|fr|ru|zh)\s*:\s*\{/.test(l)).map(([, i]) => i);

  it('no language block defines the same key twice (the last one silently wins)', () => {
    const dupes = [];
    starts.forEach((a, n) => {
      const b = starts[n + 1] ?? i18n.length;
      const seen = new Set();
      for (let i = a; i < b; i++) {
        const m = /^\s*'([^']+)'\s*:/.exec(i18n[i]) || /\{\s+'([^']+)'\s*:/.exec(i18n[i]);
        if (!m) continue;
        if (seen.has(m[1])) dupes.push(`${m[1]} @ line ${i + 1}`);
        seen.add(m[1]);
      }
    });
    expect(dupes).toEqual([]);
  });

  it('the block page title and the dashboard panel title no longer share one key', async () => {
    installChromeMock();
    (0, eval)(fs.readFileSync(path.join(root, 'core/i18n.js'), 'utf8'));
    await CorsairI18n.set('en');
    expect(CorsairI18n.t('blocked.title', '')).toBe('Navigation Blocked');
    expect(CorsairI18n.t('blocked.panelTitle', '')).toContain('Blocked Domains');
    await CorsairI18n.set('fa');
    expect(CorsairI18n.t('blocked.title', '')).toBe('ناوبری مسدود شد');
    expect(html).toContain('data-i18n="blocked.panelTitle"');
  });
});

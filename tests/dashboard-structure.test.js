// @vitest-environment jsdom
import { describe, it, expect, beforeEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

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

// @vitest-environment jsdom
import { describe, it, expect, beforeEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(__dirname, '..');
const js = fs.readFileSync(path.join(root, 'dashboard.js'), 'utf8');
const css = fs.readFileSync(path.join(root, 'dashboard.css'), 'utf8');

function extract(name) {
  const start = js.indexOf(`function ${name}(`);
  if (start < 0) throw new Error(`${name} not found`);
  let depth = 0, i = js.indexOf('{', start);
  for (let j = i; j < js.length; j++) {
    if (js[j] === '{') depth++;
    else if (js[j] === '}') { depth--; if (depth === 0) return js.slice(start, j + 1); }
  }
  throw new Error('unbalanced');
}

function loadUi(scripts, query = '') {
  document.body.innerHTML = '<div id="usStatus"></div><input id="scriptSearch"><span id="scriptCount"></span><div id="scriptList"></div>';
  const state = { customScripts: scripts, scriptQuery: query, highlightScriptId: '', userscriptAvailability: { ok: true } };
  const src = [
    'usTargetDomains', 'usDomainHue', 'usBuildDomainChips', 'renderUserscriptStatus', 'renderCustomScripts'
  ].map(extract).join('\n');
  const factory = new Function('state', 'document', '$', 't', 'send', 'showToast', 'openEditor', 'refresh', 'confirm', `${src}; return { usTargetDomains, renderCustomScripts };`);
  return factory(
    state, document, (id) => document.getElementById(id), (k, d) => d,
    async () => ({ ok: true }), () => {}, () => {}, async () => {}, () => true
  );
}

const mk = (name, matches, extra = {}) => ({
  id: 'cu-' + name, name, version: '1.0', description: '', matches, enabled: true,
  lines: 10, runAt: 'document-idle', world: 'MAIN', sourceUrl: '', migratedFrom: '', noMatch: false, lastError: '', ...extra
});

describe('userscript list — domain badges', () => {
  it('extracts tidy, de-duplicated domain labels', () => {
    const { usTargetDomains } = loadUi([]);
    expect(usTargetDomains(['*://foo.com/*', '*://*.foo.com/*']).map(d => d.label)).toEqual(['foo.com']);
    expect(usTargetDomains(['https://*.example.com/a*', 'http://localhost:3000/*']).map(d => d.label))
      .toEqual(['example.com', 'localhost:3000']);
    expect(usTargetDomains(['<all_urls>'])[0]).toEqual({ label: 'All sites', kind: 'all' });
    expect(usTargetDomains(['*://*/*'])[0].kind).toBe('all');
    expect(usTargetDomains(['/^https:\\/\\/a\\.com/'])[0].kind).toBe('regex');
    expect(usTargetDomains(['file:///*'])[0].label).toBe('Local files');
  });

  it('renders one card per script with domain chips in the corner column', () => {
    const { renderCustomScripts } = loadUi([
      mk('A', ['*://foo.com/*', '*://*.foo.com/*']),
      mk('B', ['https://a.com/*', 'https://b.com/*', 'https://c.com/*', 'https://d.com/*', 'https://e.com/*'])
    ]);
    renderCustomScripts();
    const cards = document.querySelectorAll('.script-item');
    expect(cards).toHaveLength(2);
    expect(cards[0].querySelector('.script-side .domain-chip .label').textContent).toBe('foo.com');
    const b = cards[1].querySelectorAll('.domain-chip');
    expect(b).toHaveLength(4);                      // 3 chips + "+2"
    expect(b[3].textContent).toBe('+2');
    expect(b[3].title).toContain('d.com');
  });

  it('sorts alphabetically and filters by name or domain', () => {
    const list = [mk('Zeta', ['https://zed.org/*']), mk('alpha', ['https://example.com/*'])];
    let ui = loadUi(list);
    ui.renderCustomScripts();
    expect([...document.querySelectorAll('.script-host')].map(e => e.textContent.trim().split(' ')[0])).toEqual(['alpha', 'Zeta']);

    ui = loadUi(list, 'zed.org');
    ui.renderCustomScripts();
    expect(document.querySelectorAll('.script-item')).toHaveLength(1);
    expect(document.getElementById('scriptCount').textContent).toBe('1 / 2');

    ui = loadUi(list, 'nothing-here');
    ui.renderCustomScripts();
    expect(document.querySelector('.empty').textContent).toContain('No scripts match');
  });

  it('renders 60 scripts without dropping any (list stays complete)', () => {
    const many = Array.from({ length: 60 }, (_, i) => mk('S' + String(i).padStart(2, '0'), [`https://site${i}.com/*`]));
    loadUi(many).renderCustomScripts();
    expect(document.querySelectorAll('.script-item')).toHaveLength(60);
  });
});

describe('userscript list — scrolling CSS', () => {
  const block = (sel) => {
    const m = new RegExp(sel.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*\\{([^}]*)\\}').exec(css);
    return m ? m[1] : '';
  };

  it('the list scrolls vertically inside a bounded height', () => {
    const b = block('.script-list');
    expect(b).toMatch(/overflow-y:\s*auto/);
    expect(b).toMatch(/max-height:/);
    expect(b).toMatch(/min-height:\s*0/);
  });

  it('cards never shrink inside the flex column (root cause of the old bug)', () => {
    expect(block('.script-item')).toMatch(/flex:\s*0 0 auto/);
  });
});

import { describe, it, expect, beforeAll } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { loadCore } from './helpers/load-core.js';

const root = path.resolve(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');

beforeAll(() => {
  globalThis.chrome = globalThis.chrome || { runtime: { getManifest: () => ({ version: '1.10.0' }), id: 'x', getURL: (p) => 'chrome-extension://x/' + p }, storage: { local: { get: async () => ({}), set: async () => {} } } };
  loadCore('core/userscripts.js');
});

const meta = (over) => ({ name: 'S', namespace: '', version: '1', description: '', author: '', homepage: '', icon: '', updateURL: '', downloadURL: '', supportURL: '', license: '', runAt: 'document-idle', injectInto: 'auto', noframes: false, topLevelAwait: false, match: ['https://*.redgifs.com/*'], include: [], exclude: [], excludeMatch: [], grant: [], require: [], resource: [], connect: [], tags: [], localized: {}, ...over });

describe('userscript menu lives in the toolbar popup, not in the page', () => {
  it('the floating in-page button is gone', () => {
    expect(read('core/userscripts.js')).not.toContain('data-corsair-gm-menu');
  });

  it('urlMatchesMeta decides which scripts the popup lists', () => {
    const M = CorsairUserScripts.urlMatchesMeta;
    expect(M(meta(), 'https://www.redgifs.com/watch/abc')).toBe(true);
    expect(M(meta(), 'https://example.org/')).toBe(false);
    expect(M(meta(), 'chrome://extensions')).toBe(false);
    expect(M(meta({ exclude: ['*/watch/*'] }), 'https://www.redgifs.com/watch/abc')).toBe(false);
    expect(M(meta({ match: [] }), 'https://www.redgifs.com/')).toBe(false);
  });

  it('content scripts still have exactly the six pinned messages (no new page-reachable message)', () => {
    const bg = read('background.js');
    const i = bg.indexOf("if (capability === 'PAGE_OBSERVATION') {\n        if (m.type !== 'page-observation'");
    expect(i).toBeGreaterThan(0);
    const chain = bg.slice(i, bg.indexOf("send({ ok: false, error: 'unauthorized-sender' })", i));
    const allowed = [...chain.matchAll(/m\.type !== '([\w-]+)'/g)].map(x => x[1]).sort();
    expect(allowed).toEqual(['block-domain-global', 'content-link-allow', 'content-popup-blocked', 'content-security-event', 'page-observation', 'trust-domain']);
    expect(allowed).not.toContain('gm-menu-get');
    expect(allowed).not.toContain('gm-menu-run');
  });

  it('listing and running commands is restricted to extension pages', () => {
    const bg = read('background.js');
    for (const type of ['gm-menu-get', 'gm-menu-run']) {
      const block = bg.slice(bg.indexOf(`case '${type}'`), bg.indexOf(`case '${type}'`) + 300);
      expect(block, type).toMatch(/capability !== 'PRIVILEGED_INTERNAL'/);
    }
  });
});

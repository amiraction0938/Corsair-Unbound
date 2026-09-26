/* ============================================================
   RTL REGRESSION GUARD (STATIC)
   ------------------------------------------------------------
   Root cause of the original RTL bug: `core/i18n.js` was loaded
   into every http(s) page as a content script and its
   `applyDirection()` mutated `document.documentElement` and
   `document.body` unconditionally — corrupting the host page's
   own `dir` / `lang` / `class` state.

   The fix has two parts that we now verify as static invariants:

     (1) `applyDirection()` and `apply()` MUST short-circuit on
         non-extension contexts. This file verifies the
         `isExtensionContext()` guard is present and gates both.

     (2) Content scripts (content.js and friends) MUST NOT
         directly manipulate documentElement.dir / body.class
         in a way that would leak onto the host page.

     (3) dashboard.css MUST NOT contain an unscoped
         `html { direction: rtl }` or `body { direction: rtl }`
         rule that would fire without a `.lang-rtl-text` gate.
   ============================================================ */
import { describe, it, expect } from 'vitest';
import { readSource } from './helpers/load-core.js';

describe('RTL regression — core/i18n.js context guard', () => {
  const src = readSource('core/i18n.js');

  it('defines an isExtensionContext() helper', () => {
    expect(src).toMatch(/function\s+isExtensionContext\s*\(/);
    expect(src).toMatch(/chrome-extension:/);
  });

  it('applyDirection() short-circuits when not in extension context', () => {
    const start = src.indexOf('function applyDirection');
    expect(start, 'applyDirection() must be present').toBeGreaterThan(-1);
    // 1500 chars covers the whole function body comfortably.
    const body = src.slice(start, start + 1500);

    // The guard must be called…
    const guardIndex = body.indexOf('isExtensionContext');
    expect(guardIndex, 'applyDirection must call isExtensionContext()').toBeGreaterThan(-1);

    // …and it must appear BEFORE the first mutation. In i18n.js the
    // mutation uses `html.setAttribute(...)` where `html` is
    // document.documentElement — so we look for `setAttribute`, not
    // `documentElement.setAttribute`.
    const mutationIndex = body.indexOf('setAttribute');
    expect(mutationIndex, 'applyDirection must mutate via setAttribute').toBeGreaterThan(-1);
    expect(mutationIndex, 'guard must precede mutation').toBeGreaterThan(guardIndex);
  });

  it('apply() short-circuits when not in extension context', () => {
    const fn = src.match(/function\s+apply\s*\(\s*root\s*=\s*document\s*\)\s*\{[\s\S]*?\n\s{2}\}/);
    expect(fn, 'apply(root) must be present').toBeTruthy();
    const body = fn[0];
    expect(body).toMatch(/isExtensionContext\s*\(/);
  });
});

describe('RTL regression — content scripts must not touch host layout', () => {
  const scripts = [
    'content.js',
    'content-frame-guard.js',
    'content-main-world.js',
    'content-security-guard.js'
  ];

  for (const path of scripts) {
    it(`${path} does not set documentElement.dir`, () => {
      const src = readSource(path);
      expect(src).not.toMatch(/documentElement\.dir\s*=/);
      expect(src).not.toMatch(/documentElement\.setAttribute\s*\(\s*['"]dir['"]/);
    });

    it(`${path} does not set documentElement.lang`, () => {
      const src = readSource(path);
      expect(src).not.toMatch(/documentElement\.lang\s*=/);
      expect(src).not.toMatch(/documentElement\.setAttribute\s*\(\s*['"]lang['"]/);
    });

    it(`${path} does not add class="rtl" to body`, () => {
      const src = readSource(path);
      // Match patterns like: document.body.classList.add('rtl')
      //                      body.classList.toggle('rtl', ...)
      expect(src).not.toMatch(/body\.classList\.add\s*\(\s*['"]rtl['"]/);
      expect(src).not.toMatch(/body\.className\s*=\s*[^;]*['"]rtl['"]/);
    });
  }
});

describe('RTL regression — dashboard.css must scope direction rules', () => {
  const css = readSource('dashboard.css');

  it('has no unscoped html { direction: rtl }', () => {
    // Match `html {` followed by any content and a `direction: rtl`
    // BEFORE the closing brace. Do not match `.lang-rtl-text html`.
    expect(css).not.toMatch(/^\s*html\s*\{[^}]*direction\s*:\s*rtl/im);
  });

  it('has no unscoped body { direction: rtl }', () => {
    expect(css).not.toMatch(/^\s*body\s*\{[^}]*direction\s*:\s*rtl/im);
  });

  it('any direction: rtl rule is scoped to .lang-rtl-text or an RTL child', () => {
    // Every occurrence of `direction: rtl` must be inside a selector
    // that contains `.lang-rtl-text` (or is a child of it). We check
    // this by inspecting each rule block.
    const ruleRe = /([^{}]+)\{([^}]*)\}/g;
    let m;
    let violations = [];
    while ((m = ruleRe.exec(css)) !== null) {
      const selector = m[1];
      const body = m[2];
      if (!/direction\s*:\s*rtl/.test(body)) continue;
      // Selector must mention .lang-rtl-text (or be a descendant of it).
      if (!/\.lang-rtl-text/.test(selector)) {
        violations.push(selector.trim().slice(0, 120));
      }
    }
    expect(violations, `Unscoped direction:rtl in: ${violations.join(' | ')}`).toEqual([]);
  });
});
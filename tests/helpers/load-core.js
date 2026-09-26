/* ============================================================
   LOAD CORE MODULE
   ------------------------------------------------------------
   The Corsair core modules are classic scripts (IIFE that
   assigns `globalThis.CorsairX = ...`). This helper evaluates
   a file into the current Node global, exactly as
   `background.js` does at runtime via `import './core/x.js'`.

   Each call re-evaluates the file. The wrapper function ensures
   that the internal `const CorsairX = ...` binding is scoped to
   the invocation, so re-loading a module never throws a
   re-declaration error — the outer `globalThis.X = X` line is
   what actually matters and always runs last.
   ============================================================ */
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..', '..');

export function loadCore(relativePath) {
  const abs = resolve(ROOT, relativePath);
  const code = readFileSync(abs, 'utf8');
  // Indirect eval → global scope. The wrapper isolates top-level
  // `const` bindings so re-loads are safe.
  (0, eval)(`(function () {\n${code}\n})();`);
}

export function loadCores(paths) {
  for (const p of paths) loadCore(p);
}

export function readSource(relativePath) {
  return readFileSync(resolve(ROOT, relativePath), 'utf8');
}

export function repoRoot() {
  return ROOT;
}
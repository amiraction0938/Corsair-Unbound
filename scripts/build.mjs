/* ============================================================
   CORSAIR UNBOUND — BUILD
   ------------------------------------------------------------
   Stages the runtime files into `dist/` so CI can upload them
   as a ZIP artifact. Deliberately does NOT copy:
     • tests/, scripts/, .github/, node_modules/
     • package.json, package-lock.json, vitest.config.js
     • any dotfile (except the ones explicitly listed)
   This keeps the ZIP reproducible and free of development
   artifacts.
   ============================================================ */
import { existsSync, mkdirSync, rmSync, cpSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');
const DIST = resolve(ROOT, 'dist');

// Files and directories that ship in the extension ZIP.
// Order does not matter; missing optional files are skipped.
const RUNTIME_FILES = [
  'manifest.json',
  'background.js',
  'content.js',
  'content-frame-guard.js',
  'content-main-world.js',
  'content-security-guard.js',
  'blocked.html',
  'blocked.js',
  'dashboard.html',
  'dashboard.css',
  'dashboard.js',
  'popup.html',
  'popup.css',
  'popup.js',
  'core',
  'icons'
];

// Documentation is included when present but is not required.
const OPTIONAL_FILES = [
  'README.md',
  'CHANGELOG.md',
  'LICENSE'
];

rmSync(DIST, { recursive: true, force: true });
mkdirSync(DIST, { recursive: true });

let staged = 0;
let skipped = 0;

for (const item of RUNTIME_FILES) {
  const src = resolve(ROOT, item);
  if (!existsSync(src)) {
    console.error(`[build] MISSING REQUIRED FILE: ${item}`);
    process.exitCode = 1;
    skipped++;
    continue;
  }
  cpSync(src, resolve(DIST, item), { recursive: true });
  staged++;
}

for (const item of OPTIONAL_FILES) {
  const src = resolve(ROOT, item);
  if (!existsSync(src)) continue;
  cpSync(src, resolve(DIST, item), { recursive: true });
  staged++;
}

console.log(`[build] staged ${staged} entr${staged === 1 ? 'y' : 'ies'} → ${DIST}`);
if (skipped > 0) {
  console.error(`[build] ${skipped} required entr${skipped === 1 ? 'y' : 'ies'} missing — build FAILED`);
}
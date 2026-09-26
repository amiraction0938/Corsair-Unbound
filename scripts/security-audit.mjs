#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const ROOT = process.cwd();
const HISTORY = process.argv.includes('--history');

const TEXT_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.json', '.md', '.txt', '.html', '.css',
  '.yml', '.yaml', '.xml', '.svg', '.sh', '.bat', '.ps1', '.b64'
]);

const IGNORED_DIRS = new Set([
  '.git', 'node_modules', 'dist', 'coverage'
]);

const SENSITIVE_NAME = /(^|[\\/])(?:\.env(?:\.[^.]+)?|id_rsa|credentials?|secrets?|.*\.(?:pem|key|p12|pfx|cer|crt))$/i;

const PATTERNS = [
  { name: 'private-key', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |)?PRIVATE KEY-----/i },
  { name: 'aws-access-key', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { name: 'google-api-key', re: /\bAIza[0-9A-Za-z_-]{30,}\b/ },
  { name: 'github-token', re: /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/ },
  { name: 'jwt', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
  { name: 'bearer-token', re: /\bBearer\s+[A-Za-z0-9._~+/=-]{24,}\b/i },
  {
    name: 'credential-assignment',
    re: /['"](?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|password)['"]\s*:\s*['"][A-Za-z0-9._~+/=-]{24,}['"]/i
  },
  {
    name: 'x-apikey-literal',
    re: /['"]x-apikey['"]\s*:\s*['"][A-Za-z0-9._~+/=-]{24,}['"]/i
  }
];

function isTextFile(filePath) {
  return TEXT_EXTENSIONS.has(path.extname(filePath).toLowerCase());
}

function isIgnored(filePath) {
  const rel = path.relative(ROOT, filePath);
  return rel.split(path.sep).some((part) => IGNORED_DIRS.has(part));
}

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!IGNORED_DIRS.has(entry.name)) walk(full, out);
      continue;
    }
    if (entry.isFile() && isTextFile(full) && !isIgnored(full)) out.push(full);
  }
  return out;
}

function scanText(fileName, content, findings) {
  for (const pattern of PATTERNS) {
    if (pattern.re.test(content)) {
      findings.push({ file: fileName, type: pattern.name });
    }
  }
}

function scanWorkingTree() {
  const findings = [];

  for (const filePath of walk(ROOT)) {
    const rel = path.relative(ROOT, filePath);
    if (SENSITIVE_NAME.test(rel)) {
      findings.push({ file: rel, type: 'sensitive-filename' });
    }
    scanText(rel, fs.readFileSync(filePath, 'utf8'), findings);
  }

  return findings;
}

function scanManifest() {
  const findings = [];
  const manifestPath = path.join(ROOT, 'manifest.json');

  if (!fs.existsSync(manifestPath)) {
    findings.push({ file: 'manifest.json', type: 'missing-manifest' });
    return findings;
  }

  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  } catch {
    findings.push({ file: 'manifest.json', type: 'invalid-json' });
    return findings;
  }

  if (manifest.update_url) {
    findings.push({ file: 'manifest.json', type: 'unexpected-update-url' });
  }

  if (manifest.externally_connectable) {
    findings.push({ file: 'manifest.json', type: 'externally-connectable-present' });
  }

  const csp = manifest.content_security_policy?.extension_pages;
  if (typeof csp === 'string' && /https?:\/\//i.test(csp)) {
    findings.push({ file: 'manifest.json', type: 'remote-extension-csp-source' });
  }

  return findings;
}

function scanHistory() {
  const findings = [];
  let objectsText = '';

  try {
    objectsText = execFileSync('git', ['rev-list', '--objects', '--all'], {
      cwd: ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe']
    });
  } catch {
    return [{ file: '<git>', type: 'history-scan-unavailable' }];
  }

  const objects = [];
  for (const line of objectsText.split(/\r?\n/)) {
    const match = line.match(/^([0-9a-f]{40})\s+(.+)$/i);
    if (!match) continue;

    const rel = match[2];
    if (!isTextFile(rel)) continue;
    if (isIgnored(path.join(ROOT, rel))) continue;

    objects.push({ sha: match[1], rel });
  }

  if (objects.length === 0) return findings;

  let input = '';
  for (const obj of objects) input += obj.sha + '\n';

  let raw;
  try {
    raw = execFileSync('git', ['cat-file', '--batch'], {
      cwd: ROOT,
      input,
      encoding: 'utf8',
      maxBuffer: 128 * 1024 * 1024
    });
  } catch {
    return [{ file: '<git>', type: 'history-scan-failed' }];
  }

  let offset = 0;
  for (const obj of objects) {
    const headerEnd = raw.indexOf('\n', offset);
    if (headerEnd === -1) break;

    const header = raw.slice(offset, headerEnd).split(' ');
    const size = Number(header[2]);
    if (!Number.isFinite(size) || size < 0) break;

    const start = headerEnd + 1;
    const content = raw.slice(start, start + size);
    scanText(obj.rel, content, findings);
    offset = start + size + 1;
  }

  return findings;
}

const findings = [
  ...scanWorkingTree(),
  ...scanManifest(),
  ...(HISTORY ? scanHistory() : [])
];

const unique = [...new Map(
  findings.map((finding) => [
    finding.file + '|' + finding.type,
    finding
  ])
).values()];

console.log('Corsair Unbound security audit');
console.log('Mode: ' + (HISTORY ? 'working tree + reachable Git history' : 'working tree'));
console.log('Findings: ' + unique.length);

for (const finding of unique) {
  console.log('- ' + finding.file + ' :: ' + finding.type);
}

if (unique.length > 0) {
  console.error('Security audit failed: review the findings before release.');
  process.exit(1);
}

console.log('Security audit passed.');

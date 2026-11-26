/* ============================================================
   CORSAIR UNBOUND — AI SCRIPT VALIDATOR & SECURITY ANALYZER (v1.13.0)
   ------------------------------------------------------------
   Treats all AI-generated userscripts as untrusted code.
   - 100% CSP-safe pure-JS syntax & delimiter validation
     (ZERO eval / ZERO new Function)
   - Metadata, @match, @grant, @connect, @require checks
   - Static security findings (remote code, obfuscation, eval,
     data exfiltration, DOM injection, @connect *, infinite loops,
     aggressive polling, suspicious clipboard/credential access)
   - Least-privilege permission & side-effect extraction
   - Explicitly separates syntax, static security, API compat,
     live execution, and behavioral verification
   ============================================================ */

const CorsairAIScriptValidator = (() => {
  'use strict';

  function parseHeaderQuick(code) {
    const src = String(code || '');
    const m = src.match(/\/\/\s*==UserScript==([\s\S]*?)\/\/\s*==\/UserScript==/);
    if (!m) return { hasHeader: false, meta: null };
    if (typeof CorsairUserScripts !== 'undefined' && CorsairUserScripts.parseMetadata) {
      const parsed = CorsairUserScripts.parseMetadata(src);
      return { hasHeader: true, meta: parsed.meta, warnings: parsed.warnings || [] };
    }
    const meta = {
      name: '', description: '', version: '', runAt: 'document-idle',
      match: [], include: [], exclude: [], grant: [], connect: [], require: [], resource: []
    };
    for (const line of m[1].split(/\r?\n/)) {
      const dm = line.match(/^\s*\/\/\s*@([\w-]+)(?:\s+(.*))?$/);
      if (!dm) continue;
      const k = dm[1].toLowerCase();
      const v = (dm[2] || '').trim();
      if (k === 'name') meta.name = v;
      else if (k === 'description') meta.description = v;
      else if (k === 'version') meta.version = v;
      else if (k === 'run-at') meta.runAt = v;
      else if (k === 'match') meta.match.push(v);
      else if (k === 'include') meta.include.push(v);
      else if (k === 'exclude') meta.exclude.push(v);
      else if (k === 'grant') meta.grant.push(v);
      else if (k === 'connect') meta.connect.push(v);
      else if (k === 'require') meta.require.push(v);
      else if (k === 'resource') meta.resource.push(v);
    }
    return { hasHeader: true, meta, warnings: [] };
  }

  /**
   * Pure-JS lexical & delimiter balance validator (CSP-safe, no eval/Function).
   */
  function checkSyntaxLexical(code) {
    const errors = [];
    const src = String(code || '');
    const stack = [];
    const pairs = { '(': ')', '[': ']', '{': '}' };
    let line = 1;
    let inSingle = false, inDouble = false, inTemplate = false, inLineComment = false, inBlockComment = false;

    for (let i = 0; i < src.length; i++) {
      const ch = src[i];
      const next = src[i + 1];

      if (ch === '\n') {
        line++;
        inLineComment = false;
        if (inSingle) { errors.push({ line, message: 'Unterminated single-quoted string literal.' }); inSingle = false; }
        if (inDouble) { errors.push({ line, message: 'Unterminated double-quoted string literal.' }); inDouble = false; }
        continue;
      }

      if (inLineComment) continue;
      if (inBlockComment) {
        if (ch === '*' && next === '/') { inBlockComment = false; i++; }
        continue;
      }
      if (inSingle) {
        if (ch === '\\') { i++; continue; }
        if (ch === "'") inSingle = false;
        continue;
      }
      if (inDouble) {
        if (ch === '\\') { i++; continue; }
        if (ch === '"') inDouble = false;
        continue;
      }
      if (inTemplate) {
        if (ch === '\\') { i++; continue; }
        if (ch === '`') inTemplate = false;
        continue;
      }

      if (ch === '/' && next === '/') { inLineComment = true; i++; continue; }
      if (ch === '/' && next === '*') { inBlockComment = true; i++; continue; }
      if (ch === "'") { inSingle = true; continue; }
      if (ch === '"') { inDouble = true; continue; }
      if (ch === '`') { inTemplate = true; continue; }

      if (pairs[ch]) {
        stack.push({ open: ch, expect: pairs[ch], line });
      } else if (ch === ')' || ch === ']' || ch === '}') {
        const top = stack.pop();
        if (!top || top.expect !== ch) {
          errors.push({ line, message: `Unexpected closing "${ch}"${top ? ` (expected "${top.expect}" opened on line ${top.line})` : ''}.` });
        }
      }
    }

    if (inBlockComment) errors.push({ line, message: 'Unterminated block comment (/* ... */).' });
    if (inTemplate) errors.push({ line, message: 'Unterminated template literal (`...`).' });
    if (inSingle || inDouble) errors.push({ line, message: 'Unterminated string literal at end of file.' });
    for (const rem of stack) {
      errors.push({ line: rem.line, message: `Unclosed "${rem.open}" opened on line ${rem.line}.` });
    }

    // Check for obvious uncompiled TypeScript syntax leftovers
    if (/^\s*(?:export\s+)?interface\s+\w+\s*\{/m.test(src) || /^\s*(?:export\s+)?type\s+\w+\s*=/m.test(src)) {
      errors.push({ line: 1, message: 'Uncompiled TypeScript syntax detected (interface/type declaration). Convert to JavaScript before running.' });
    }

    return { ok: errors.length === 0, errors };
  }

  const SECURITY_RULES = [
    {
      id: 'eval-usage',
      severity: 'high',
      pattern: /\b(?:eval\s*\(|new\s+Function\s*\()/,
      title: 'Dynamic code execution (eval / new Function)',
      detail: 'Dynamic code execution increases XSS and code-injection risk and often violates site CSP.'
    },
    {
      id: 'remote-script-injection',
      severity: 'high',
      pattern: /createElement\s*\(\s*['"]script['"]\s*\)[\s\S]{0,200}\.src\s*=/i,
      title: 'Remote executable script injection',
      detail: 'Injecting external <script src> loads unverified remote code at runtime.'
    },
    {
      id: 'obfuscated-payload',
      severity: 'high',
      pattern: /(?:atob\s*\([^)]{20,}\)|(?:\\x[0-9a-fA-F]{2}){8,}|(?:\\u[0-9a-fA-F]{4}){8,})/,
      title: 'Obfuscated or encoded payload detected',
      detail: 'Encoded blobs may conceal malicious behavior and should be replaced with readable code.'
    },
    {
      id: 'credential-exfiltration',
      severity: 'high',
      pattern: /(?:(?:document\.cookie|input\[type=['"]?password|localStorage)[\s\S]{0,260}(?:fetch\s*\(|XMLHttpRequest|sendBeacon|GM_xmlhttpRequest)|(?:fetch\s*\(|XMLHttpRequest|sendBeacon|GM_xmlhttpRequest)[\s\S]{0,260}(?:document\.cookie|input\[type=['"]?password|localStorage))/i,
      title: 'Potential credential or session data exfiltration',
      detail: 'Script reads sensitive session/credential data near an outbound network call.'
    },
    {
      id: 'suspicious-clipboard-shell',
      severity: 'high',
      pattern: /clipboard\.writeText\s*\([\s\S]{0,160}(?:powershell|pwsh|mshta|cmd\.exe|curl\s+[^)]*\|\s*sh)/i,
      title: 'Suspicious clipboard shell command injection',
      detail: 'Writing shell commands to the clipboard matches ClickFix social-engineering patterns.'
    },
    {
      id: 'dangerous-dom-sink',
      severity: 'medium',
      pattern: /\.(?:innerHTML|outerHTML)\s*=|document\.write\s*\(/,
      title: 'Unsafe HTML injection sink (innerHTML / document.write)',
      detail: 'Prefer textContent or DOM creation APIs (createElement) to avoid DOM XSS.'
    },
    {
      id: 'unbounded-loop',
      severity: 'medium',
      pattern: /while\s*\(\s*true\s*\)\s*\{(?![\s\S]{0,400}\b(?:break|return|await)\b)/,
      title: 'Potential infinite loop (while (true) without break/return/await)',
      detail: 'Unbounded synchronous loops freeze browser tabs.'
    },
    {
      id: 'aggressive-polling',
      severity: 'medium',
      pattern: /setInterval\s*\([\s\S]{1,400},\s*(?:[0-9]|[1-9][0-9])\s*\)/,
      title: 'Aggressive polling interval (< 100ms)',
      detail: 'Prefer MutationObserver or a longer interval to protect page performance and battery.'
    },
    {
      id: 'external-network',
      severity: 'low',
      pattern: /\b(?:fetch\s*\(|new\s+XMLHttpRequest|navigator\.sendBeacon|new\s+WebSocket)\b/,
      title: 'External network access in script body',
      detail: 'Verify that all outbound endpoints are expected and necessary for the requested feature.'
    }
  ];

  function analyze(code, opts = {}) {
    const src = String(code || '');
    const header = parseHeaderQuick(src);
    const syntax = checkSyntaxLexical(src);

    // Strip header comments before running body security rules
    const body = src.replace(/\/\/\s*==UserScript==[\s\S]*?\/\/\s*==\/UserScript==/, '');

    const findings = [];
    for (const rule of SECURITY_RULES) {
      if (rule.pattern.test(body)) {
        findings.push({ id: rule.id, severity: rule.severity, title: rule.title, detail: rule.detail });
      }
    }

    const meta = header.meta || {
      name: '', description: '', version: '', runAt: 'document-idle',
      match: [], include: [], exclude: [], grant: [], connect: [], require: [], resource: []
    };

    const metaErrors = [];
    if (!header.hasHeader) {
      metaErrors.push('Missing ==UserScript== metadata header block.');
    } else {
      if (!meta.name) metaErrors.push('Missing @name metadata directive.');
      const scopes = [...(meta.match || []), ...(meta.include || [])];
      if (scopes.length === 0) metaErrors.push('Missing @match or @include scope.');
      for (const m of scopes) {
        if (m === '*://*/*' || m === '<all_urls>' || m === 'http://*/*' || m === 'https://*/*') {
          findings.push({
            id: 'overbroad-match',
            severity: 'high',
            title: `Overbroad website scope (${m})`,
            detail: 'Generated scripts should be scoped to the specific target website unless explicitly widened.'
          });
        }
      }
      for (const c of (meta.connect || [])) {
        if (c === '*') {
          findings.push({
            id: 'wildcard-connect',
            severity: 'high',
            title: 'Unrestricted @connect * permission',
            detail: '@connect * allows cross-origin requests to any public host. Restrict to exact domains.'
          });
        }
      }
      for (const r of (meta.require || [])) {
        if (/^http:\/\//i.test(r) && !/^http:\/\/localhost\b/i.test(r)) {
          findings.push({
            id: 'insecure-require',
            severity: 'high',
            title: `Insecure HTTP @require (${r})`,
            detail: 'External @require libraries must use HTTPS.'
          });
        }
      }
    }

    const grants = (meta.grant || []).filter(g => g && g !== 'none');
    const privilegedGrants = grants.filter(g => /xmlhttpRequest|cookie|download|openInTab/i.test(g));
    if (privilegedGrants.length > 0) {
      findings.push({
        id: 'privileged-grants',
        severity: 'medium',
        title: `Privileged GM APIs requested: ${privilegedGrants.join(', ')}`,
        detail: 'Review carefully before approving execution.'
      });
    }

    // Check API compatibility
    const unsupportedApis = [];
    for (const g of grants) {
      if (/^GM[._]?(webRequest|cookie)$/i.test(g)) unsupportedApis.push(g);
    }

    const recommendedWorld = (grants.includes('unsafeWindow') || /unsafeWindow\b/.test(body))
      ? 'MAIN'
      : 'USER_SCRIPT';

    const highCount = findings.filter(f => f.severity === 'high').length;
    const medCount = findings.filter(f => f.severity === 'medium').length;

    return {
      ok: syntax.ok && metaErrors.length === 0 && unsupportedApis.length === 0,
      hasHighRisk: highCount > 0,
      riskLevel: highCount > 0 ? 'high' : (medCount > 0 ? 'medium' : 'low'),
      meta,
      permissions: {
        matches: meta.match || [],
        includes: meta.include || [],
        excludes: meta.exclude || [],
        grants,
        connects: meta.connect || [],
        requires: meta.require || [],
        runAt: meta.runAt || 'document-idle',
        recommendedWorld
      },
      stages: {
        syntax: { ok: syntax.ok, errors: syntax.errors },
        metadata: { ok: metaErrors.length === 0, errors: metaErrors },
        staticSecurity: { ok: highCount === 0, highCount, mediumCount: medCount, findings },
        apiCompatibility: { ok: unsupportedApis.length === 0, unsupportedApis },
        liveExecution: opts.liveExecution || { status: 'not-run', message: 'Not yet tested on tab.' },
        behavioralVerification: {
          status: 'user-confirmation-required',
          message: 'Injection success does not prove functional correctness; verify behavior on the target website before approving.'
        }
      }
    };
  }

  return {
    parseHeaderQuick,
    checkSyntaxLexical,
    analyze
  };
})();

globalThis.CorsairAIScriptValidator = CorsairAIScriptValidator;

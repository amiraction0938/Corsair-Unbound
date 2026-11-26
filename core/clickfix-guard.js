/* ============================================================
   CORSAIR UNBOUND — CLICKFIX & FAKE-CAPTCHA GUARD
   ------------------------------------------------------------
   Contextual detector for clipboard social-engineering attacks
   ("ClickFix" / Fake CAPTCHA) that trick users into pasting
   malicious OS commands (PowerShell, mshta, cmd, certutil, etc.)
   into Windows Run (Win+R) or a terminal.

   Uses multi-signal confidence scoring + developer-documentation
   dampening to minimize false positives on GitHub, MDN,
   StackOverflow, Microsoft Learn, etc.
   ============================================================ */
const CorsairClickFixGuard = (() => {
  'use strict';

  const DEV_DOCS_HOSTS = new Set([
    'github.com', 'gist.github.com', 'gitlab.com', 'bitbucket.org',
    'stackoverflow.com', 'superuser.com', 'serverfault.com', 'stackexchange.com',
    'learn.microsoft.com', 'docs.microsoft.com', 'developer.mozilla.org',
    'npmjs.com', 'pypi.org', 'docs.python.org', 'nodejs.org', 'rust-lang.org',
    'wikipedia.org', 'reddit.com'
  ]);

  const COMMAND_SIGNALS = [
    { id: 'powershell-exec', weight: 35, re: /\b(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\b/i },
    { id: 'encoded-command', weight: 40, re: /(?:^|\s)-(?:e|en|enc|enco|encodedcommand)\s+[A-Za-z0-9+/=]{20,}/i },
    { id: 'hidden-window', weight: 30, re: /(?:^|\s)-(?:w|win|windowstyle)\s+(?:hidden|1)\b/i },
    { id: 'bypass-exec-policy', weight: 25, re: /(?:^|\s)-(?:ep|exec|executionpolicy)\s+(?:bypass|unrestricted)\b/i },
    { id: 'download-and-exec', weight: 45, re: /(?:iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|curl|wget)\b[\s\S]{0,200}(?:\|\s*(?:iex|invoke-expression|sh|bash|zsh|powershell)|;\s*(?:iex|invoke-expression))/i },
    { id: 'mshta-remote', weight: 50, re: /\bmshta(?:\.exe)?\s+(?:https?:\/\/|javascript:|vbscript:)/i },
    { id: 'lolbin-exec', weight: 40, re: /\b(?:cmd(?:\.exe)?\s+\/c|wscript(?:\.exe)?|cscript(?:\.exe)?|rundll32(?:\.exe)?|regsvr32(?:\.exe)?|certutil(?:\.exe)?\s+-urlcache|bitsadmin(?:\.exe)?\s+\/transfer)\b/i },
    { id: 'base64-decode-exec', weight: 35, re: /(?:FromBase64String|base64\s+-d[\s\S]{0,60}\|\s*(?:sh|bash))/i },
    { id: 'obfuscated-comment-lure', weight: 20, re: /#\s*(?:human|verify|verification|captcha|cloudflare|robot|security\s+check|تایید)/i }
  ];

  const PAGE_LURE_SIGNALS = [
    { id: 'win-r-instruction', weight: 35, re: /(?:press|hold|hit)\s+(?:windows|win)\s*(?:\+|key\s*\+)?\s*r\b|⊞\s*\+\s*r|کلید\s*ویندوز\s*\+\s*r/i },
    { id: 'paste-enter-instruction', weight: 25, re: /(?:ctrl\s*\+\s*v|paste)[\s\S]{0,60}(?:press\s+enter|hit\s+enter|run\s+dialog|اینتر)/i },
    { id: 'fake-captcha-language', weight: 25, re: /(?:verify\s+you\s+are\s+human|i\s+am\s+not\s+a\s+robot|verification\s+steps|prove\s+you\s+are\s+human|human\s+verification|تایید\s*کنید\s*ربات\s*نیستید)/i }
  ];

  function hostInDevDocs(host) {
    const h = String(host || '').toLowerCase().replace(/\.$/, '');
    if (!h) return false;
    for (const d of DEV_DOCS_HOSTS) {
      if (h === d || h.endsWith('.' + d)) return true;
    }
    return false;
  }

  /**
   * Analyze a clipboard payload together with optional page text context & hostname.
   * Returns { suspicious, confidence, score, severity, signals, isDevDocs, shouldSuppress, preview }.
   */
  function analyze({ text, pageText = '', host = '', source = 'copy', trustedHosts = [] }) {
    const payload = String(text || '').trim();
    if (!payload || payload.length < 8 || payload.length > 8000) {
      return { suspicious: false, confidence: 0, score: 0, severity: 'none', signals: [], shouldSuppress: false, preview: '' };
    }

    const h = String(host || '').toLowerCase().replace(/\.$/, '');
    if (Array.isArray(trustedHosts) && trustedHosts.some((t) => h === t || h.endsWith('.' + t))) {
      return { suspicious: false, confidence: 0, score: 0, severity: 'none', signals: ['trusted-host'], shouldSuppress: false, preview: '' };
    }

    const signals = [];
    let cmdScore = 0;
    for (const sig of COMMAND_SIGNALS) {
      if (sig.re.test(payload)) {
        cmdScore += sig.weight;
        signals.push(sig.id);
      }
    }

    // Must have at least one dangerous command execution signal
    if (cmdScore === 0) {
      return { suspicious: false, confidence: 0, score: 0, severity: 'none', signals: [], shouldSuppress: false, preview: '' };
    }

    let lureScore = 0;
    const contextBlob = String(pageText || '').slice(0, 6000);
    for (const lure of PAGE_LURE_SIGNALS) {
      if (lure.re.test(contextBlob)) {
        lureScore += lure.weight;
        signals.push(lure.id);
      }
    }

    // Programmatic clipboard.writeText on a non-dev site is a stronger ClickFix signal than manual user copy
    const programmaticBonus = source === 'clipboard-api' ? 15 : 0;
    const isDevDocs = hostInDevDocs(h);

    let total = cmdScore + lureScore + programmaticBonus;
    if (isDevDocs && lureScore === 0) {
      // Strongly dampen benign command snippets copied from developer documentation
      total = Math.round(total * 0.35);
      signals.push('dev-docs-dampened');
    }

    const score = Math.min(100, total);
    const suspicious = score >= 60;
    const severity = score >= 85 ? 'critical' : score >= 60 ? 'high' : 'none';
    const shouldSuppress = score >= 75 && source === 'clipboard-api';

    return {
      suspicious,
      confidence: Math.round((score / 100) * 100) / 100,
      score,
      severity,
      signals,
      isDevDocs,
      shouldSuppress,
      // Safe redacted preview (never expose full potentially sensitive clipboard data)
      preview: payload.replace(/[\r\n\t]+/g, ' ').slice(0, 96)
    };
  }

  return {
    analyze,
    hostInDevDocs,
    DEV_DOCS_HOSTS
  };
})();

globalThis.CorsairClickFixGuard = CorsairClickFixGuard;

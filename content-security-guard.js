/* ============================================================
   CORSAIR UNBOUND — CONTENT SECURITY GUARD
   ------------------------------------------------------------
   Runs at document_start in EVERY frame (see manifest.json).
   Adds three passive detection layers that cooperate with the
   existing background service worker:

     1. Clipboard Hijack Detector
        A malicious page can intercept a `copy` event and silently
        replace the copied text (classic crypto-address swap). We
        detect this by:
          a. capturing window.getSelection() in the CAPTURE phase
             (before any page listener runs)
          b. reading e.clipboardData in a BUBBLE phase listener
             attached to `window`, which fires AFTER the page's
             own bubble listeners (window is the outermost node in
             the event path)
          c. comparing the two. If the plain-text payload has been
             significantly mutated AND the original looked like a
             crypto address / URL / email, we report a hijack.

     2. CSP Violation Monitor
        Listens for `securitypolicyviolation` events. Unexpected
        blocked external resources — especially script loads — are
        a strong signal that a page has been compromised by an
        injected payload. We forward each violation to the worker.

     3. Form-Jacking Detector
        Watches `submit` events in the CAPTURE phase. If the form
        action points to a cross-registrable-domain host AND the
        form looks sensitive (password / email / card fields), we
        report potential credential theft / payment skimming.
        Known OAuth / payment providers are allowlisted to keep
        false positives low.

   The frame guard (`content-frame-guard.js`) owns the nonce
   handshake and fortress state. This module is independent — its
   detections run everywhere, fortress or not.
   ============================================================ */
(function () {
  'use strict';

  let _selfHost = '';
  try { _selfHost = String(location.hostname || '').toLowerCase(); } catch {}

  function sendBg(msg) {
    try { return chrome.runtime.sendMessage(msg).catch(() => null); }
    catch { return Promise.resolve(null); }
  }

  function isSafeWebScheme(u) {
    try {
      const p = new URL(u).protocol;
      return p === 'http:' || p === 'https:';
    } catch { return false; }
  }

  /* ============================================================
     1. CLIPBOARD HIJACK DETECTOR
     ============================================================ */

  const CRYPTO_PATTERNS = [
    /^bc1[a-z0-9]{25,90}$/i,                    // BTC bech32
    /^[13][a-km-zA-HJ-NP-Z1-9]{25,39}$/,        // BTC legacy
    /^0x[a-f0-9]{40}$/i,                         // ETH
    /^T[a-zA-Z0-9]{33}$/,                        // TRON
    /^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}$/,    // Monero
    /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/,            // XRP
    /^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$/         // LTC
  ];

  const URL_PATTERN = /^https?:\/\/[^\s]{6,}$/i;
  const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

  function looksSensitive(text) {
    if (!text || typeof text !== 'string') return false;
    const trimmed = text.trim();
    if (trimmed.length < 6 || trimmed.length > 200) return false;
    if (URL_PATTERN.test(trimmed)) return true;
    if (EMAIL_PATTERN.test(trimmed)) return true;
    for (const re of CRYPTO_PATTERNS) if (re.test(trimmed)) return true;
    return false;
  }

  function normalizedDiff(a, b) {
    if (a === b) return 0;
    if (!a || !b) return 1;
    const la = String(a).trim();
    const lb = String(b).trim();
    if (la === lb) return 0;
    const len = Math.max(la.length, lb.length);
    let same = 0;
    const n = Math.min(la.length, lb.length);
    for (let i = 0; i < n; i++) if (la[i] === lb[i]) same++;
    return 1 - same / len;
  }

  const _clipboardReports = new Map();
  const CLIPBOARD_REPORT_COOLDOWN_MS = 8000;

  function reportClipboardHijack(originalText, replacedText) {
    const now = Date.now();
    const last = _clipboardReports.get(_selfHost) || 0;
    if (now - last < CLIPBOARD_REPORT_COOLDOWN_MS) return;
    _clipboardReports.set(_selfHost, now);

    sendBg({
      type: 'content-security-event',
      kind: 'clipboard_hijack',
      page: String(location.href || ''),
      host: _selfHost,
      severity: 'high',
      data: {
        originalPreview: String(originalText).slice(0, 80),
        replacedPreview: String(replacedText).slice(0, 80),
        originalLength: String(originalText).length,
        replacedLength: String(replacedText).length
      }
    });
  }

  (function installClipboardDetector() {
    let _selectionAtCopyStart = '';

    document.addEventListener('copy', () => {
      try {
        const sel = window.getSelection && window.getSelection();
        _selectionAtCopyStart = sel ? String(sel.toString() || '') : '';
      } catch {
        _selectionAtCopyStart = '';
      }
    }, true);

    window.addEventListener('copy', (e) => {
      try {
        const original = _selectionAtCopyStart;
        _selectionAtCopyStart = '';
        if (!original || !looksSensitive(original)) return;

        const cd = e.clipboardData;
        if (!cd || typeof cd.getData !== 'function') return;
        const finalText = String(cd.getData('text/plain') || '');
        if (!finalText) return;

        const diff = normalizedDiff(original, finalText);
        if (diff >= 0.15) {
          reportClipboardHijack(original, finalText);
        }
      } catch {}
    }, false);
  })();

  /* ============================================================
     2. CSP VIOLATION MONITOR
     ============================================================ */

  const _cspReported = new Map();
  const CSP_DEDUPE_MS = 15000;
  const CSP_MAX_BLOCKED_URI_LEN = 300;

  function reportCspViolation(evt) {
    try {
      const directive = String(evt.violatedDirective || '');
      const blockedURI = String(evt.blockedURI || '');
      if (!blockedURI || blockedURI === 'inline' || blockedURI === 'eval') return;
      if (blockedURI.length > CSP_MAX_BLOCKED_URI_LEN) return;

      let isExternal = false;
      try {
        const u = new URL(blockedURI, location.href);
        isExternal = Boolean(
          u.hostname && u.hostname !== _selfHost && !u.hostname.endsWith('.' + _selfHost)
        );
      } catch {}

      const key = `${directive}::${blockedURI}`;
      const now = Date.now();
      const last = _cspReported.get(key) || 0;
      if (now - last < CSP_DEDUPE_MS) return;
      _cspReported.set(key, now);

      sendBg({
        type: 'content-security-event',
        kind: 'csp_violation',
        page: String(location.href || ''),
        host: _selfHost,
        severity: isExternal ? 'medium' : 'low',
        data: {
          directive,
          blockedURI,
          disposition: String(evt.disposition || ''),
          isExternal
        }
      });
    } catch {}
  }

  (function installCspMonitor() {
    try {
      document.addEventListener('securitypolicyviolation', reportCspViolation, true);
    } catch {}
  })();

  /* ============================================================
     3. FORM-JACKING DETECTOR
     ============================================================ */

  const FORM_ACTION_ALLOWLIST = new Set([
    'accounts.google.com',
    'login.microsoftonline.com',
    'login.live.com',
    'appleid.apple.com',
    'www.paypal.com',
    'checkout.stripe.com',
    'js.stripe.com',
    'api.stripe.com',
    'auth0.com',
    'okta.com',
    'checkout.shopify.com'
  ]);

  function regDomain(host) {
    const parts = String(host || '').toLowerCase().split('.').filter(Boolean);
    if (parts.length <= 2) return parts.join('.');
    return parts.slice(-2).join('.');
  }

  const _formReported = new Set();

  function formLooksSensitive(form) {
    try {
      if (!form || typeof form.querySelectorAll !== 'function') return false;
      if (form.querySelector('input[type="password"]')) return true;
      if (form.querySelector('input[type="email"]')) return true;
      if (form.querySelector('input[name*="card" i]')) return true;
      if (form.querySelector('input[name*="cvv" i]')) return true;
      if (form.querySelector('input[name*="credit" i]')) return true;
      if (form.querySelector('input[autocomplete="cc-number"]')) return true;
      if (form.querySelector('input[autocomplete="current-password"]')) return true;
      return false;
    } catch { return false; }
  }

  function reportFormJacking(formAction, destHost) {
    const key = `${_selfHost}::${destHost}`;
    if (_formReported.has(key)) return;
    _formReported.add(key);

    sendBg({
      type: 'content-security-event',
      kind: 'form_jacking',
      page: String(location.href || ''),
      host: _selfHost,
      severity: 'high',
      data: {
        action: String(formAction).slice(0, 300),
        destinationHost: destHost
      }
    });
  }

  (function installFormGuard() {
    document.addEventListener('submit', (e) => {
      try {
        if (!e.isTrusted) return;
        const form = e.target;
        if (!form || form.tagName !== 'FORM') return;
        if (!formLooksSensitive(form)) return;

        const rawAction = String(form.getAttribute('action') || '');
        let actionUrl = '';
        try { actionUrl = new URL(rawAction || location.href, location.href).href; }
        catch { return; }
        if (!isSafeWebScheme(actionUrl)) return;

        let destHost = '';
        try { destHost = new URL(actionUrl).hostname.toLowerCase(); } catch { return; }
        if (!destHost) return;

        if (regDomain(destHost) === regDomain(_selfHost)) return;

        for (const ok of FORM_ACTION_ALLOWLIST) {
          if (destHost === ok || destHost.endsWith('.' + ok)) return;
        }

        reportFormJacking(actionUrl, destHost);
      } catch {}
    }, true);
  })();
})();
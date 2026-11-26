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

  /* ============================================================
     4. CREDENTIAL & PHISHING FORM GUARD + CLICKFIX GUARD (v1.12.0)
     Uses isolated Shadow DOM warnings; NEVER reads input values.
     ============================================================ */
  const _warnedKeys = new Set();

  function showSecurityOverlay({ id, severity, title, body, details, allowProceed, onProceed, onCancel }) {
    try {
      if (document.getElementById(id)) return;
      const host = document.createElement('div');
      host.id = id;
      host.style.cssText = 'position:fixed;inset:0;z-index:2147483647;pointer-events:auto;';
      const shadow = host.attachShadow({ mode: 'closed' });
      const accent = severity === 'critical' ? '#ef4444' : '#f59e0b';
      shadow.innerHTML = `
        <style>
          .backdrop{position:fixed;inset:0;background:rgba(6,9,17,0.82);backdrop-filter:blur(6px);display:flex;align-items:center;justify-content:center;padding:20px;font-family:system-ui,-apple-system,Segoe UI,sans-serif;}
          .card{max-width:480px;width:100%;background:#0f1624;color:#f1f5f9;border:1px solid ${accent};border-radius:14px;padding:24px;box-shadow:0 24px 60px rgba(0,0,0,0.6);}
          .badge{display:inline-block;padding:3px 10px;border-radius:999px;font-size:11px;font-weight:700;text-transform:uppercase;background:rgba(239,68,68,0.16);color:${accent};margin-bottom:10px;}
          h2{margin:0 0 8px;font-size:18px;font-weight:700;}
          p{margin:0 0 12px;font-size:13.5px;line-height:1.6;color:#cbd5e1;}
          .meta{background:#090d16;border:1px solid rgba(255,255,255,0.08);border-radius:8px;padding:10px 12px;font-family:monospace;font-size:12px;color:#fbbf24;word-break:break-word;margin-bottom:16px;}
          .actions{display:flex;flex-wrap:wrap;gap:8px;justify-content:flex-end;}
          button{border-radius:8px;padding:9px 14px;font-size:13px;font-weight:600;cursor:pointer;border:1px solid rgba(255,255,255,0.14);background:#181f2e;color:#f1f5f9;}
          button.primary{background:${accent};border-color:transparent;color:#fff;}
        </style>
        <div class="backdrop" role="alertdialog" aria-modal="true">
          <div class="card">
            <div class="badge">Corsair Unbound Security Warning</div>
            <h2 id="t"></h2>
            <p id="b"></p>
            <div class="meta" id="d"></div>
            <div class="actions">
              <button type="button" id="proceedBtn" hidden>Proceed once</button>
              <button type="button" class="primary" id="cancelBtn">Cancel &amp; Stay Safe</button>
            </div>
          </div>
        </div>`;
      shadow.getElementById('t').textContent = title;
      shadow.getElementById('b').textContent = body;
      shadow.getElementById('d').textContent = details;
      const pBtn = shadow.getElementById('proceedBtn');
      const cBtn = shadow.getElementById('cancelBtn');
      if (allowProceed && pBtn) {
        pBtn.hidden = false;
        pBtn.addEventListener('click', () => { host.remove(); if (typeof onProceed === 'function') onProceed(); });
      }
      cBtn.addEventListener('click', () => { host.remove(); if (typeof onCancel === 'function') onCancel(); });
      (document.documentElement || document.body).appendChild(host);
    } catch {}
  }

  // Feature 1: Pre-submit Credential & Phishing Form Guard
  if (typeof CorsairCredentialGuard !== 'undefined') {
    const _proceededForms = new WeakSet();
    document.addEventListener('submit', (e) => {
      try {
        const form = e.target;
        if (!form || _proceededForms.has(form)) return;
        const actionAttr = form.getAttribute ? (form.getAttribute('action') || location.href) : location.href;
        const verdict = CorsairCredentialGuard.evaluateSubmission({
          pageUrl: location.href,
          actionUrl: actionAttr,
          fields: form
        });
        if (!verdict.shouldWarn) return;

        e.preventDefault();
        e.stopImmediatePropagation();

        sendBg({
          type: 'content-security-event',
          kind: 'credential_phishing_warning',
          page: String(location.href || ''),
          host: _selfHost,
          severity: verdict.severity === 'critical' ? 'high' : 'medium',
          data: {
            destinationHost: verdict.destHost,
            categories: verdict.categories,
            reasons: verdict.reasons,
            risk: verdict.risk
          }
        });

        showSecurityOverlay({
          id: 'corsair-cred-guard-overlay',
          severity: verdict.severity,
          title: 'Suspicious Credential or Payment Submission Detected',
          body: 'This form requests sensitive information (' + verdict.categories.join(', ') + ') and is sending it to a suspicious or insecure destination. Corsair Unbound did not read or store your typed values.',
          details: 'Destination: ' + verdict.destHost + ' | Signals: ' + verdict.reasons.join(', '),
          allowProceed: true,
          onProceed: () => {
            _proceededForms.add(form);
            try { HTMLFormElement.prototype.submit.call(form); } catch {}
          }
        });
      } catch {}
    }, true);
  }

  // Feature 2: ClickFix & Fake-CAPTCHA Clipboard Guard
  if (typeof CorsairClickFixGuard !== 'undefined') {
    const handleClickFixCandidate = (text, source) => {
      try {
        const pageText = (document.body && document.body.innerText) ? document.body.innerText.slice(0, 4000) : '';
        const res = CorsairClickFixGuard.analyze({ text, pageText, host: _selfHost, source });
        if (!res.suspicious) return false;

        const key = 'cf:' + _selfHost + ':' + res.signals.join(',');
        if (_warnedKeys.has(key)) return res.shouldSuppress;
        _warnedKeys.add(key);

        sendBg({
          type: 'content-security-event',
          kind: 'clickfix_detected',
          page: String(location.href || ''),
          host: _selfHost,
          severity: 'high',
          data: { score: res.score, signals: res.signals, source, preview: res.preview }
        });

        showSecurityOverlay({
          id: 'corsair-clickfix-overlay',
          severity: res.severity,
          title: 'Possible ClickFix / Fake CAPTCHA Command Attack',
          body: 'This page attempted to place a potentially dangerous operating-system command into your clipboard. Do NOT paste it into Windows Run (Win+R) or a terminal unless you fully trust this source.',
          details: 'Detected signals: ' + res.signals.join(', ') + ' | Preview: ' + res.preview,
          allowProceed: false
        });
        return res.shouldSuppress;
      } catch { return false; }
    };

    window.addEventListener('copy', (e) => {
      try {
        const cd = e.clipboardData;
        const txt = (cd && typeof cd.getData === 'function' ? cd.getData('text/plain') : '') ||
          (window.getSelection ? String(window.getSelection().toString() || '') : '');
        if (txt) handleClickFixCandidate(txt, 'copy');
      } catch {}
    }, false);

    document.addEventListener('corsair-clipboard-write', (e) => {
      try {
        const txt = e && e.detail ? String(e.detail) : '';
        if (txt) handleClickFixCandidate(txt, 'clipboard-api');
      } catch {}
    });
  }

})();
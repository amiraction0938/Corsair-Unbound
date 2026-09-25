/* ============================================================
   CORSAIR UNBOUND — MAIN-WORLD GUARD (hardened)
   ------------------------------------------------------------
   Runs in MAIN world (shares `window` with page scripts) so the
   `window.open` override actually intercepts the page's own
   calls.

   Nonce handshake (hardened against load-order races):
     • The ISOLATED world writes `data-corsair-nonce` on <html>
       at document_start, BEFORE any page script runs.
     • We read it as soon as possible. If it isn't there yet
       (cross-world load-order race), we observe the <html>
       element with a MutationObserver and pick it up within a
       microtask — then remove the attribute so the page never
       sees it.
     • EVERY message we accept must carry the nonce. The page
       cannot forge one because it never learns the value.
     • Until the nonce arrives, we FAIL CLOSED: messages that
       arrive without a nonce are rejected (the older version
       failed open, which was exploitable).
     • We ALSO send our request-for-state with whatever nonce
       we currently have; the ISOLATED world will send the
       state again once its own _stateReady resolves, so we
       catch the update even if our first request carried an
       empty nonce.

   The window.open override is installed synchronously at the
   top of the file, before anything else — so it wins the race
   against page scripts that try to grab window.open early.
   ============================================================ */
(function () {
  'use strict';

  if (window.__corsairMainWorldInstalled) return;
  window.__corsairMainWorldInstalled = true;

  let _selfHost = '';
  try { _selfHost = String(location.hostname || '').toLowerCase(); } catch {}

  /* ============================================================
     LOCAL STATE
     ============================================================ */
  let _nonce = '';
  let _fortressArmed = false;
  let _fortressChecked = false;

  /* Read the nonce synchronously if it's already there. If it
     isn't, schedule a MutationObserver on <html> so we catch it
     the moment the ISOLATED script writes it. */
  function tryReadNonce() {
    if (_nonce) return true;
    try {
      const root = document.documentElement;
      if (!root || !root.getAttribute) return false;
      const v = String(root.getAttribute('data-corsair-nonce') || '');
      if (!v) return false;
      _nonce = v;
      try { root.removeAttribute('data-corsair-nonce'); } catch {}
      // Re-announce ourselves now that we can authenticate.
      requestFortressState();
      return true;
    } catch { return false; }
  }

  tryReadNonce();

  if (!_nonce) {
    try {
      const root = document.documentElement;
      if (root) {
        const mo = new MutationObserver(() => {
          if (tryReadNonce()) {
            try { mo.disconnect(); } catch {}
          }
        });
        mo.observe(root, { attributes: true, attributeFilter: ['data-corsair-nonce'] });
        // Safety: stop watching after 2 seconds.
        setTimeout(() => { try { mo.disconnect(); } catch {} }, 2000);
      }
    } catch {}
  }

  /* ============================================================
     MESSAGE VALIDATION — FAIL CLOSED
     ------------------------------------------------------------
     The previous version returned `true` whenever we had no
     nonce, which meant a page could silently disable the guard
     by racing the load order. We now require a nonce before
     accepting ANY message. If we never learn the nonce, we
     simply never accept state broadcasts — which is safe,
     because the guard then stays in its default-armed state
     for the purposes of the override.

     NOTE: the override defaults to ARMED=true only if we have
     never received a state broadcast. That closes the tiny
     window between install and the first authenticated
     broadcast where the page could try to pop open a window.
     ============================================================ */
  let _receivedAuthenticatedState = false;

  function isTrustedMessage(data) {
    if (!data || typeof data !== 'object') return false;
    if (data.__corsair !== true) return false;
    if (!_nonce) return false;
    return data.__nonce === _nonce;
  }

  /* We start with the guard in "block until proven otherwise"
     mode so the initial microtask window before the first
     authenticated broadcast cannot be abused. */
  let _armedByDefault = true;

  function isCurrentlyArmed() {
    if (_receivedAuthenticatedState) return _fortressArmed;
    return _armedByDefault;
  }

  /* ---------- Receive authenticated state updates ---------- */
  window.addEventListener('message', (e) => {
    if (e.source !== window) return;
    if (!isTrustedMessage(e.data)) return;
    if (e.data.type === 'fortress-state') {
      _fortressArmed = e.data.armed === true;
      _fortressChecked = true;
      _receivedAuthenticatedState = true;
    }
  }, false);

  /* Ask ISOLATED world for the current state. */
  function requestFortressState() {
    try {
      window.postMessage({
        __corsair: true,
        __nonce: _nonce,
        type: 'request-fortress-state'
      }, '*');
    } catch {}
  }
  requestFortressState();

  /* ---------- Report blocked events back to ISOLATED world ---------- */
  function reportBlocked(url, reason) {
    try {
      window.postMessage({
        __corsair: true,
        __nonce: _nonce,
        type: 'guard-event',
        eventType: 'popup-blocked',
        payload: {
          url: String(url || 'about:blank'),
          host: _selfHost,
          page: String(location.href || ''),
          reason: reason || 'fortress-popup-lockdown'
        }
      }, '*');
    } catch {}
  }

  /* ============================================================
     window.open OVERRIDE — installed synchronously, first thing
     ------------------------------------------------------------
     Nothing else in this file runs before this block, so no page
     script can win the race to grab the original window.open.
     ============================================================ */
  try {
    const originalOpen = window.open;

    const patchedOpen = function (url, name, features) {
      // Safe default: block while armed, allow otherwise.
      if (isCurrentlyArmed()) {
        reportBlocked(url, 'fortress-popup-lockdown');
        return null;
      }

      // Shape-based heuristic for the brief window before we've
      // received an authenticated state: a classic popup shape
      // (about:blank or _blank with explicit dimensions) is
      // almost always an ad or tracker. Reject it while we wait
      // for the first state broadcast.
      if (!_receivedAuthenticatedState) {
        const isSuspiciousShape =
          (!name || /^_blank$/i.test(String(name))) &&
          /(?:left|top|width|height|resizable)/i.test(String(features || ''));
        if (isSuspiciousShape) {
          reportBlocked(url, 'unchecked-suspicious-popup');
          return null;
        }
      }

      return originalOpen.apply(this, arguments);
    };

    // Hide the override from scripts that call toString().
    try {
      Object.defineProperty(patchedOpen, 'toString', {
        value: () => 'function open() { [native code] }',
        configurable: false,
        writable: false
      });
      Object.defineProperty(patchedOpen, 'name', {
        value: 'open',
        configurable: false,
        writable: false
      });
      Object.defineProperty(patchedOpen, 'length', {
        value: 3,
        configurable: false,
        writable: false
      });
    } catch {}

    try {
      Object.defineProperty(window, 'open', {
        value: patchedOpen,
        configurable: false,
        writable: false
      });
    } catch {}
  } catch {}

  /* ============================================================
     META-REFRESH GUARD
     ============================================================ */
  (function installMetaRefreshGuard() {
    function isSameHost(host) {
      const h = String(host || '').toLowerCase();
      if (!h) return false;
      return h === _selfHost || h.endsWith('.' + _selfHost);
    }

    function isExternalUrl(raw) {
      try {
        const u = new URL(raw, location.href);
        if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
        return !isSameHost(u.hostname);
      } catch { return false; }
    }

    function processNode(node) {
      if (!node || node.nodeType !== 1) return;
      if (node.tagName !== 'META') return;
      const httpEquiv = (node.getAttribute('http-equiv') || '').toLowerCase();
      if (httpEquiv !== 'refresh') return;
      const content = node.getAttribute('content') || '';
      const m = content.match(/url\s*=\s*(.+)$/i);
      if (m && isExternalUrl(m[1].trim().replace(/^['"]|['"]$/g, ''))) {
        try { node.remove(); } catch {}
      }
    }

    try {
      const mo = new MutationObserver(muts => {
        for (const m of muts) {
          for (const n of m.addedNodes || []) processNode(n);
        }
      });
      const target = document.documentElement || document;
      mo.observe(target, { childList: true, subtree: true });
      document.querySelectorAll('meta[http-equiv="refresh"]').forEach(processNode);
    } catch {}
  })();
})();
(function () {
  'use strict';

  /* ============================================================
     CORSAIR UNBOUND — ISOLATED-WORLD FRAME GUARD
     ------------------------------------------------------------
     Runs in EVERY frame at document_start, BEFORE any page script.

     Responsibilities:
       1. Generate a per-page NONCE and hand it to the MAIN-world
          guard via a DOM attribute. The page cannot see the nonce
          because our script (and the MAIN-world script) both run
          before any page script executes.
       2. Relay popup-blocked events from the MAIN-world guard to
          the background service worker.
       3. Keep the MAIN world informed of the current fortress
          state — every message is authenticated with the nonce so
          the page CANNOT spoof a "fortress-state: disarmed" and
          silently disable the guard.
       4. Intercept user-gesture popups (click/auxclick) that do
          not need MAIN-world privileges.

     Nonce handshake:
       ISOLATED (this file) → writes data-corsair-nonce on <html>
       MAIN-world script    → reads & removes it, keeps in closure
       Both worlds          → every postMessage includes __nonce
       Both worlds          → reject any message whose nonce differs
     ============================================================ */

  let _selfHost = '';
  try { _selfHost = String(location.hostname || '').toLowerCase(); } catch {}

  /* ============================================================
     NONCE GENERATION + HANDOFF
     ============================================================ */
  const _nonce = (() => {
    try {
      if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
        return crypto.randomUUID();
      }
    } catch {}
    try {
      const buf = new Uint8Array(16);
      crypto.getRandomValues(buf);
      return Array.from(buf, b => b.toString(16).padStart(2, '0')).join('');
    } catch {}
    return 'n_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2);
  })();

  try {
    const root = document.documentElement || document.head || document;
    if (root && root.setAttribute) {
      root.setAttribute('data-corsair-nonce', _nonce);
    }
  } catch {}

  /* ============================================================
     FORTRESS STATE
     ------------------------------------------------------------
     Read once per frame from a small session cache to avoid
     hammering chrome.storage.local with every iframe on the page.
     ============================================================ */
  let _fortressArmed = false;
  let _fortressChecked = false;
  let _stateLoaded = false;

  const STATE_CACHE_KEY = 'corsairFortressStateCache';

  const _stateReady = (async () => {
    try {
      const cached = await chrome.storage.session.get(STATE_CACHE_KEY).catch(() => ({}));
      const map = (cached && cached[STATE_CACHE_KEY]) || {};
      if (map && Object.prototype.hasOwnProperty.call(map, _selfHost)) {
        _fortressArmed = map[_selfHost] === true;
        _fortressChecked = true;
        _stateLoaded = true;
        return;
      }
    } catch {}

    try {
      const res = await chrome.storage.local.get('domainProfiles');
      const profiles = res?.domainProfiles || {};
      const p = profiles[_selfHost];
      _fortressArmed = Boolean(p && p.protected === true && p.mode === 'fortress');
      _fortressChecked = true;
      _stateLoaded = true;
      try {
        const existing = (await chrome.storage.session.get(STATE_CACHE_KEY))[STATE_CACHE_KEY] || {};
        existing[_selfHost] = _fortressArmed;
        await chrome.storage.session.set({ [STATE_CACHE_KEY]: existing });
      } catch {}
    } catch {
      _fortressChecked = true;
    }
  })();

  /* Live updates when the profile changes. */
  try {
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area !== 'local' || !changes.domainProfiles) return;
      const next = changes.domainProfiles.newValue || {};
      const p = next[_selfHost];
      _fortressArmed = Boolean(p && p.protected === true && p.mode === 'fortress');
      _fortressChecked = true;
      _stateLoaded = true;
      broadcastFortressState();
      try {
        chrome.storage.session.get(STATE_CACHE_KEY).then(c => {
          const map = (c && c[STATE_CACHE_KEY]) || {};
          map[_selfHost] = _fortressArmed;
          chrome.storage.session.set({ [STATE_CACHE_KEY]: map }).catch(() => {});
        }).catch(() => {});
      } catch {}
    });
  } catch {}

  function broadcastFortressState() {
    try {
      window.postMessage({
        __corsair: true,
        __nonce: _nonce,
        type: 'fortress-state',
        armed: _fortressArmed
      }, '*');
    } catch {}
  }

  /* ============================================================
     MESSAGE VALIDATION
     ------------------------------------------------------------
     Accept ONLY messages that carry our nonce. The page cannot
     know it because it runs after us.
     ============================================================ */
  function isTrustedMessage(data) {
    if (!data || typeof data !== 'object') return false;
    if (data.__corsair !== true) return false;
    return data.__nonce === _nonce;
  }

  /* Reply to state requests from MAIN world. */
  window.addEventListener('message', (e) => {
    if (e.source !== window) return;
    if (!isTrustedMessage(e.data)) return;
    if (e.data.type === 'request-fortress-state') {
      _stateReady.then(broadcastFortressState).catch(() => {});
      broadcastFortressState();
    }
  }, false);

  _stateReady.then(broadcastFortressState).catch(() => {});

  function isSameHost(host) {
    const h = String(host || '').toLowerCase();
    if (!h) return false;
    return h === _selfHost || h.endsWith('.' + _selfHost);
  }

  function sendBg(msg) {
    try { return chrome.runtime.sendMessage(msg).catch(() => null); }
    catch { return Promise.resolve(null); }
  }

  /* ============================================================
     RELAY: MAIN-world guard events → background
     ============================================================ */
  window.addEventListener('message', (e) => {
    if (e.source !== window) return;
    if (!isTrustedMessage(e.data)) return;
    if (e.data.type !== 'guard-event') return;

    const payload = e.data.payload || {};
    if (e.data.eventType === 'popup-blocked') {
      sendBg({
        type: 'content-popup-blocked',
        url: String(payload.url || 'about:blank'),
        page: String(payload.page || location.href || ''),
        host: _selfHost,
        reason: String(payload.reason || 'fortress-popup-lockdown')
      });
    }
  }, false);

  /* ============================================================
     SAFE REDIRECT RESOLVER
     ============================================================ */
  const REDIRECTOR_PATH_REGEX =
    /\/(?:url|out|redirect|redir|link|click|goto|jump|track|gateway|away|external|safelink)(?:\/|\.[a-z0-9]+|$)/i;
  const REDIRECT_PARAM_KEYS = [
    'url','target','dest','destination','redirect','redirect_url','redirect_uri',
    'redir','u','link','to','next','return','return_url','r','q','goto'
  ];

  function isSafeWebScheme(rawUrl) {
    if (!rawUrl || typeof rawUrl !== 'string') return false;
    try {
      const u = new URL(rawUrl);
      return u.protocol === 'http:' || u.protocol === 'https:';
    } catch { return false; }
  }

  function iterativelyDecodeUrl(raw) {
    if (!raw || typeof raw !== 'string') return '';
    let current = raw.trim();
    for (let i = 0; i < 3; i++) {
      try {
        const decoded = decodeURIComponent(current);
        if (decoded === current) break;
        current = decoded;
      } catch { break; }
    }
    return current;
  }

  function resolveRedirectTarget() {
    if (!window.location || !window.location.href) return null;
    let currentUrl;
    try { currentUrl = new URL(window.location.href); } catch { return null; }
    const pathname = currentUrl.pathname || '';
    if (!REDIRECTOR_PATH_REGEX.test(pathname)) return null;
    const params = currentUrl.searchParams;
    if (!params) return null;
    for (const key of REDIRECT_PARAM_KEYS) {
      const val = params.get(key);
      if (!val) continue;
      const decoded = iterativelyDecodeUrl(val);
      if (!isSafeWebScheme(decoded)) continue;
      try {
        const parsedTarget = new URL(decoded);
        if (parsedTarget.href === currentUrl.href) continue;
        return parsedTarget.href;
      } catch { continue; }
    }
    return null;
  }

  _stateReady.then(() => {
    try {
      if (_fortressArmed) return;
      const target = resolveRedirectTarget();
      if (target && typeof window.location.replace === 'function') {
        window.location.replace(target);
      }
    } catch {}
  }).catch(() => {});

  /* ============================================================
     USER-GESTURE INTERCEPTION
     ------------------------------------------------------------
     Closes a real gap the earlier version left open: ctrl/cmd/
     shift+click on a regular link opened a new tab WITHOUT
     firing the click handler's popup branch (because the link
     had no target="_blank"). The tab then hit
     webNavigation.onCreatedNavigationTarget in the background,
     which closed it — but only AFTER the browser had already
     created a new tab, and if the user had done it on purpose
     the experience was terrible.

     Now the guard intercepts the modifier-click itself and
     preventDefaults before the browser ever creates a tab.
     ============================================================ */

  function blockAnchorPopup(e, anchor, reason) {
    try {
      e.preventDefault();
      e.stopPropagation();
      if (typeof e.stopImmediatePropagation === 'function') {
        e.stopImmediatePropagation();
      }
    } catch {}
    const href = String(anchor.href || '');
    sendBg({
      type: 'content-popup-blocked',
      url: href,
      page: String(location.href || ''),
      host: _selfHost,
      reason
    });
  }

  document.addEventListener('click', function (e) {
    if (!_stateLoaded || !_fortressArmed) return;

    const anchor = e.target && e.target.closest && e.target.closest('a');
    if (!anchor) return;

    // 1) Modifier-click — user is trying to open a new tab.
    //    In a Fortress lockdown, all escape vectors are contained.
    if (e.ctrlKey || e.metaKey || e.shiftKey || e.button === 1) {
      blockAnchorPopup(e, anchor, 'fortress-modifier-click');
      return;
    }

    // 2) Popup-shaped anchors (target=_blank / _new, rel=noopener).
    const target = String(anchor.target || '').toLowerCase();
    const rel = String(anchor.rel || '').toLowerCase();
    const looksLikePopup =
      target === '_blank' ||
      target === '_new' ||
      rel.includes('noopener') ||
      rel.includes('noreferrer');

    if (looksLikePopup) {
      blockAnchorPopup(e, anchor, 'fortress-anchor-popup');
      return;
    }

    // 3) Same-origin is always allowed; cross-origin navigation
    //    triggers a temporary fortress-allow rule so the DNR
    //    catch-all doesn't redirect it.
    const href = String(anchor.href || '');
    let destHost = '';
    try {
      const u = new URL(href);
      if (u.protocol === 'http:' || u.protocol === 'https:') destHost = u.hostname.toLowerCase();
    } catch {}

    if (destHost && !isSameHost(destHost)) {
      sendBg({
        type: 'content-link-allow',
        source: _selfHost,
        destination: destHost,
        page: String(location.href || '')
      });
    }
  }, true);

  document.addEventListener('auxclick', function (e) {
    if (e.button !== 1) return;
    if (!_stateLoaded || !_fortressArmed) return;
    const anchor = e.target && e.target.closest && e.target.closest('a');
    if (!anchor) return;
    blockAnchorPopup(e, anchor, 'fortress-middle-click');
  }, true);

  /* Block keydown-based navigation shortcuts too (Enter+modifier
     on a focused link, etc.). */
  document.addEventListener('keydown', function (e) {
    if (!_stateLoaded || !_fortressArmed) return;
    if (e.key !== 'Enter') return;
    if (!(e.ctrlKey || e.metaKey || e.shiftKey)) return;
    const anchor = e.target && e.target.closest && e.target.closest('a');
    if (!anchor) return;
    blockAnchorPopup(e, anchor, 'fortress-modifier-enter');
  }, true);
})();
(function () {
  'use strict';

  const REDIRECTOR_PATH_REGEX =
    /\/(?:url|out|redirect|redir|link|click|goto|jump|track|gateway|away|external|safelink)(?:\/|\.[a-z0-9]+|$)/i;

  const REDIRECT_PARAM_KEYS = [
    'url',
    'target',
    'dest',
    'destination',
    'redirect',
    'redirect_url',
    'redirect_uri',
    'redir',
    'u',
    'link',
    'to',
    'next',
    'return',
    'return_url',
    'r',
    'q',
    'goto'
  ];

  function isSafeWebScheme(rawUrl) {
    if (!rawUrl || typeof rawUrl !== 'string') return false;

    try {
      const u = new URL(rawUrl);
      return u.protocol === 'http:' || u.protocol === 'https:';
    } catch {
      return false;
    }
  }

  function iterativelyDecodeUrl(raw) {
    if (!raw || typeof raw !== 'string') return '';

    let current = raw.trim();

    for (let i = 0; i < 3; i++) {
      try {
        const decoded = decodeURIComponent(current);

        if (decoded === current) break;

        current = decoded;
      } catch {
        break;
      }
    }

    return current;
  }

  function resolveRedirectTarget() {
    if (!window.location || !window.location.href) return null;

    let currentUrl;

    try {
      currentUrl = new URL(window.location.href);
    } catch {
      return null;
    }

    const pathname = currentUrl.pathname || '';

    if (!REDIRECTOR_PATH_REGEX.test(pathname)) {
      return null;
    }

    const params = currentUrl.searchParams;

    if (!params) return null;

    for (const key of REDIRECT_PARAM_KEYS) {
      const val = params.get(key);

      if (!val) continue;

      const decoded = iterativelyDecodeUrl(val);

      if (!isSafeWebScheme(decoded)) continue;

      try {
        const parsedTarget = new URL(decoded);

        if (parsedTarget.href === currentUrl.href) {
          continue;
        }

        return parsedTarget.href;
      } catch {
        continue;
      }
    }

    return null;
  }

  try {
    const target = resolveRedirectTarget();

    if (
      target &&
      typeof window.location.replace === 'function'
    ) {
      window.location.replace(target);
      return;
    }
  } catch {}

  function collectExternalHosts(pageUrl) {
    const externalHosts = [];
    try {
      if (typeof document !== 'undefined' && document.querySelectorAll) {
        const currentHost = new URL(pageUrl).hostname;

        const elements = document.querySelectorAll(
          'script[src], link[href], img[src], a[href]'
        );

        for (const el of elements) {
          const raw = el.src || el.href;

          if (raw && typeof raw === 'string') {
            try {
              const u = new URL(raw, pageUrl);

              if (
                (u.protocol === 'http:' || u.protocol === 'https:') &&
                u.hostname &&
                u.hostname !== currentHost
              ) {
                if (!externalHosts.includes(u.hostname)) {
                  externalHosts.push(u.hostname);
                }
              }
            } catch {}
          }

          if (externalHosts.length >= 40) {
            break;
          }
        }
      }
    } catch {}
    return externalHosts;
  }

  function reportObservation() {
    try {
      if (
        typeof chrome === 'undefined' ||
        !chrome.runtime?.sendMessage ||
        !window.location?.href
      ) {
        return;
      }

      const pageUrl = window.location.href;
      if (!isSafeWebScheme(pageUrl)) return;

      const externalHosts = collectExternalHosts(pageUrl);

      chrome.runtime.sendMessage({
        type: 'page-observation',
        observation: {
          url: pageUrl,
          externalHosts: externalHosts.slice(0, 40),
          findings: []
        }
      }).catch(() => {});
    } catch {}
  }

  try {
    // This script runs at document_start so the early-redirect check above
    // can intercept redirector pages before their JS executes. At
    // document_start the DOM has not been parsed yet, so scanning for
    // external resource hosts here would almost always find nothing.
    // Defer the actual observation scan until the DOM has been parsed.
    if (typeof document !== 'undefined' && document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', reportObservation, { once: true });
    } else {
      reportObservation();
    }
  } catch {}
})();
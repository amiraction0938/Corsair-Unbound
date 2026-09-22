(function () {
  'use strict';

  const REDIRECTOR_PATH_REGEX =
    /\/(?:url|out|redirect|redir|link|click|goto|jump|track|gateway|away|external|safelink)(?:\/|\.[a-z0-9]+|$)/i;

  const REDIRECT_PARAM_KEYS = [
    'url','target','dest','destination','redirect','redirect_url','redirect_uri',
    'redir','u','link','to','next','return','return_url','r','q','goto'
  ];

  const AUTO_DISMISS_MS = 3000;

  let _fortressArmed = false;
  let _fortressChecked = false;
  let _selfHost = '';
  try { _selfHost = String(location.hostname || '').toLowerCase(); } catch {}

  async function refreshFortressState() {
    try {
      const res = await chrome.storage.local.get('domainProfiles');
      const profiles = res?.domainProfiles || {};
      const p = profiles[_selfHost];
      _fortressArmed = Boolean(p && p.protected === true && p.mode === 'fortress');
    } catch {}
    _fortressChecked = true;
  }

  try {
    refreshFortressState();
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area === 'local' && changes.domainProfiles) refreshFortressState();
    });
  } catch {}

  function isSafeWebScheme(rawUrl) {
    if (!rawUrl || typeof rawUrl !== 'string') return false;
    try {
      const u = new URL(rawUrl);
      return u.protocol === 'http:' || u.protocol === 'https:';
    } catch { return false; }
  }

  function isSameHost(host) {
    const h = String(host || '').toLowerCase();
    if (!h) return false;
    return h === _selfHost || h.endsWith('.' + _selfHost);
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

  function sendBg(msg) {
    try { return chrome.runtime.sendMessage(msg).catch(() => null); }
    catch { return Promise.resolve(null); }
  }

  /* ============================================================
     SAFE DOM HELPERS
     (Work even under Trusted Types restrictions)
     ============================================================ */
  function el(tag, opts = {}) {
    const node = document.createElement(tag);
    if (opts.className) node.className = opts.className;
    if (opts.text != null) node.textContent = String(opts.text);
    if (opts.style) {
      try { node.setAttribute('style', String(opts.style)); } catch {}
    }
    if (opts.attrs) {
      for (const [k, v] of Object.entries(opts.attrs)) {
        try { node.setAttribute(k, String(v)); } catch {}
      }
    }
    if (opts.children) {
      for (const c of opts.children) {
        if (c) node.appendChild(c);
      }
    }
    return node;
  }

  function setStyleText(styleEl, css) {
    // <style>.textContent is NOT blocked by Trusted Types
    try { styleEl.textContent = css; return true; }
    catch { return false; }
  }

  /* ============================================================
     BANNER HOST (shared)
     ============================================================ */
  const BANNER_HOST_ID = 'corsair-verdict-banner-host';
  let _autoDismissTimer = null;
  let _progressTimer = null;
  let _loadingTimeout = null;

  function hardRemoveBanner() {
    try {
      const existing = document.getElementById(BANNER_HOST_ID);
      if (existing) existing.remove();
    } catch {}
    if (_autoDismissTimer) { clearTimeout(_autoDismissTimer); _autoDismissTimer = null; }
    if (_progressTimer) { clearInterval(_progressTimer); _progressTimer = null; }
    if (_loadingTimeout) { clearTimeout(_loadingTimeout); _loadingTimeout = null; }
  }

  function getVerdictStyle(verdict) {
    switch (String(verdict || '').toLowerCase()) {
      case 'allowlisted': return { color: '#3b82f6', icon: '🛡️', label: 'Trusted Site' };
      case 'clean':       return { color: '#10b981', icon: '✓',  label: 'Safe Site' };
      case 'suspicious':  return { color: '#f59e0b', icon: '⚡', label: 'Suspicious Site' };
      case 'malicious':   return { color: '#f43f5e', icon: '⚠',  label: 'Malicious Site' };
      default:            return { color: '#94a3b8', icon: '?',  label: 'Unknown Site' };
    }
  }

  function buildReasons(report) {
    const reasons = [];
    const stats = report.stats || {};
    if (report.status === 'allowlisted') {
      reasons.push('Domain is on the trusted allowlist');
    } else {
      if (stats.malicious > 0) reasons.push(`${stats.malicious} engine(s) flagged as MALICIOUS`);
      if (stats.suspicious > 0) reasons.push(`${stats.suspicious} engine(s) flagged as suspicious`);
      if (Array.isArray(report.flaggedEngines) && report.flaggedEngines.length) {
        const list = report.flaggedEngines.slice(0, 4).join(', ');
        const more = report.flaggedEngines.length > 4 ? ` +${report.flaggedEngines.length - 4} more` : '';
        reasons.push(`Flagged by: ${list}${more}`);
      }
      if (report.heuristicSignals?.length) {
        for (const sig of report.heuristicSignals.slice(0, 2)) {
          if (sig.message) reasons.push(sig.message);
        }
      }
      if (!reasons.length && report.verdict === 'clean') {
        reasons.push('0 / 70+ engines flagged this domain');
      }
      if (!reasons.length) reasons.push('No threat intelligence signals');
    }
    return reasons.slice(0, 3);
  }

  /* ============================================================
     LOADING BANNER — built with DOM API (Trusted-Types safe)
     ============================================================ */
  function showLoadingBanner(host) {
    hardRemoveBanner();

    const hostEl = el('div', {
      attrs: { id: BANNER_HOST_ID, 'data-state': 'loading' },
      style: 'position:fixed;top:14px;right:14px;z-index:2147483647;pointer-events:auto;'
    });

    const shadow = hostEl.attachShadow({ mode: 'open' });

    const styleEl = document.createElement('style');
    setStyleText(styleEl, `
      :host { all: initial; }
      .card {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        position: relative;
        min-width: 300px; max-width: 360px;
        background: #0f172a;
        border: 1px solid #3b82f6;
        border-left: 5px solid #3b82f6;
        border-radius: 12px;
        padding: 12px 14px 12px 12px;
        color: #f8fafc; font-size: 13px;
        box-shadow: 0 12px 32px rgba(0,0,0,0.55), 0 2px 6px rgba(0,0,0,0.4);
        animation: corsairSlideIn 0.32s cubic-bezier(0.16,1,0.3,1);
        box-sizing: border-box;
      }
      .row { display: flex; align-items: flex-start; gap: 12px; }
      .spinner {
        width: 28px; height: 28px; flex-shrink: 0;
        border-radius: 50%;
        border: 3px solid rgba(59,130,246,0.2);
        border-top-color: #3b82f6;
        animation: corsairSpin 0.85s linear infinite;
        box-sizing: border-box;
      }
      .body { flex: 1; min-width: 0; padding-right: 16px; }
      .title { font-weight: 800; color: #60a5fa; font-size: 13px; }
      .host { font-family: 'SF Mono', Menlo, Consolas, monospace; font-size: 11px; color: #cbd5e1; margin-top: 3px; word-break: break-all; }
      .progress-wrap { margin-top: 10px; height: 6px; background: #1e293b; border-radius: 999px; overflow: hidden; }
      .progress-fill { height: 100%; width: 8%; background: linear-gradient(90deg, #3b82f6, #60a5fa); border-radius: 999px; transition: width 0.4s ease; }
      .status { font-size: 11px; color: #94a3b8; margin-top: 6px; font-family: 'SF Mono', Menlo, Consolas, monospace; }
      .close-loading {
        position: absolute; top: 8px; right: 10px;
        background: transparent; border: none; color: #64748b;
        cursor: pointer; font-size: 15px; line-height: 1;
        padding: 2px 6px; margin: 0;
      }
      .close-loading:hover { color: #fff; }
      @keyframes corsairSpin { to { transform: rotate(360deg); } }
      @keyframes corsairSlideIn {
        from { opacity: 0; transform: translateX(30px) scale(0.96); }
        to   { opacity: 1; transform: translateX(0) scale(1); }
      }
    `);
    shadow.appendChild(styleEl);

    const closeBtn = el('button', {
      className: 'close-loading',
      text: '✕',
      attrs: { 'aria-label': 'Dismiss' }
    });

    const card = el('div', { className: 'card', attrs: { role: 'status' }, children: [closeBtn] });

    const row = el('div', { className: 'row' });
    const spinner = el('div', { className: 'spinner' });
    const body = el('div', { className: 'body' });

    const title = el('div', { className: 'title', text: 'Scanning Site…' });
    const hostLine = el('div', { className: 'host', text: String(host || _selfHost || '') });
    const progressWrap = el('div', { className: 'progress-wrap' });
    const progressFill = el('div', { className: 'progress-fill' });
    progressWrap.appendChild(progressFill);
    const statusLine = el('div', { className: 'status', text: 'Checking local cache…' });

    body.appendChild(title);
    body.appendChild(hostLine);
    body.appendChild(progressWrap);
    body.appendChild(statusLine);

    row.appendChild(spinner);
    row.appendChild(body);
    card.appendChild(row);
    shadow.appendChild(card);

    try {
      const target = document.body || document.documentElement;
      if (target) target.appendChild(hostEl);
    } catch { return; }

    closeBtn.addEventListener('click', () => {
      hardRemoveBanner();
      sendBg({ type: 'corsair-verdict-cancel' });
    });

    const start = Date.now();

    _progressTimer = setInterval(() => {
      if (!document.getElementById(BANNER_HOST_ID)) {
        if (_progressTimer) { clearInterval(_progressTimer); _progressTimer = null; }
        return;
      }
      const elapsed = Date.now() - start;
      const pct = Math.min(90, 8 + (elapsed / 20000) * 82);
      try { progressFill.style.width = pct + '%'; } catch {}
      try {
        if (elapsed < 3000) statusLine.textContent = 'Checking local cache…';
        else if (elapsed < 8000) statusLine.textContent = 'Querying VirusTotal…';
        else if (elapsed < 15000) statusLine.textContent = 'Waiting for rate-limit slot…';
        else if (elapsed < 25000) statusLine.textContent = 'Analyzing 70+ security engines…';
        else statusLine.textContent = 'Still working…';
      } catch {}
    }, 250);

    _loadingTimeout = setTimeout(() => {
      const current = document.getElementById(BANNER_HOST_ID);
      if (current && current.dataset.state === 'loading') {
        try {
          current.style.transition = 'opacity 0.3s ease';
          current.style.opacity = '0';
          setTimeout(() => { try { current.remove(); } catch {} }, 320);
        } catch {}
      }
    }, 45000);
  }

  /* ============================================================
     VERDICT BANNER — built with DOM API (Trusted-Types safe)
     ============================================================ */
  function showVerdictBanner(report) {
    hardRemoveBanner();
    if (!report || typeof report !== 'object') return;
    if (report.status === 'error') return;

    const style = getVerdictStyle(report.verdict || report.status);
    const risk = Number(report.riskPercentage) || 0;
    const hostName = String(report.host || _selfHost || '');
    const reasons = buildReasons(report);
    const isMalicious = String(report.verdict || '').toLowerCase() === 'malicious';
    const showTrustBtn = !isMalicious && report.verdict !== 'suspicious';

    const hostEl = el('div', {
      attrs: { id: BANNER_HOST_ID, 'data-state': 'verdict' },
      style: 'position:fixed;top:14px;right:14px;z-index:2147483647;pointer-events:auto;'
    });

    const shadow = hostEl.attachShadow({ mode: 'open' });

    // Style element (textContent, not innerHTML)
    const styleEl = document.createElement('style');
    setStyleText(styleEl, `
      :host { all: initial; }
      .card {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        min-width: 300px; max-width: 380px;
        background: #0f172a;
        border: 1px solid ${style.color};
        border-left: 5px solid ${style.color};
        border-radius: 12px;
        padding: 12px 14px 12px 12px;
        color: #f8fafc; font-size: 13px;
        box-shadow: 0 12px 32px rgba(0,0,0,0.55), 0 2px 6px rgba(0,0,0,0.4);
        animation: corsairSlideIn 0.32s cubic-bezier(0.16,1,0.3,1);
        box-sizing: border-box;
      }
      .row { display: flex; align-items: flex-start; gap: 10px; }
      .icon {
        width: 30px; height: 30px; flex-shrink: 0;
        border-radius: 50%;
        background: ${style.color};
        color: #0f172a;
        display: flex; align-items: center; justify-content: center;
        font-weight: 900; font-size: 15px;
        box-shadow: 0 0 0 3px ${style.color}33;
      }
      .body { flex: 1; min-width: 0; }
      .title { font-weight: 800; color: ${style.color}; font-size: 13px; }
      .host { font-family: 'SF Mono', Menlo, Consolas, monospace; font-size: 11px; color: #cbd5e1; margin-top: 3px; word-break: break-all; }
      .risk { font-family: 'SF Mono', Menlo, Consolas, monospace; font-size: 11px; color: #94a3b8; margin-top: 3px; }
      .reasons { margin-top: 8px; padding-top: 8px; border-top: 1px solid #1e293b; }
      .reasons > div { font-size: 11px; color: #cbd5e1; line-height: 1.55; margin-top: 3px; padding-left: 10px; position: relative; }
      .reasons > div::before { content: '\\2022'; color: ${style.color}; position: absolute; left: 0; }
      .actions {
        margin-top: 10px; padding-top: 8px; border-top: 1px solid #1e293b;
        display: flex; gap: 6px; align-items: center; justify-content: flex-end;
      }
      .trust-btn {
        background: rgba(16,185,129,0.15);
        border: 1px solid rgba(16,185,129,0.35);
        color: #34d399;
        padding: 5px 10px; border-radius: 6px;
        font-size: 11px; font-weight: 700;
        cursor: pointer;
      }
      .trust-btn:hover { background: rgba(16,185,129,0.3); }
      .close {
        background: transparent; border: none; color: #64748b;
        cursor: pointer; font-size: 15px; line-height: 1;
        padding: 2px 6px; margin: 0;
      }
      .close:hover { color: #fff; }
      @keyframes corsairSlideIn {
        from { opacity: 0; transform: translateX(30px) scale(0.96); }
        to   { opacity: 1; transform: translateX(0) scale(1); }
      }
    `);
    shadow.appendChild(styleEl);

    // Card
    const card = el('div', { className: 'card', attrs: { role: 'alert' } });

    // Row: icon + body
    const row = el('div', { className: 'row' });
    const iconEl = el('div', { className: 'icon', text: style.icon });
    const body = el('div', { className: 'body' });

    body.appendChild(el('div', { className: 'title', text: style.label }));
    body.appendChild(el('div', { className: 'host', text: hostName }));
    body.appendChild(el('div', { className: 'risk', text: `${risk}% risk` }));

    if (reasons.length) {
      const reasonsEl = el('div', { className: 'reasons' });
      for (const r of reasons) {
        reasonsEl.appendChild(el('div', { text: r }));
      }
      body.appendChild(reasonsEl);
    }

    row.appendChild(iconEl);
    row.appendChild(body);
    card.appendChild(row);

    // Actions
    const actions = el('div', { className: 'actions' });

    if (showTrustBtn) {
      const trustBtn = el('button', { className: 'trust-btn', text: '✓ Trust permanently' });
      trustBtn.addEventListener('click', async () => {
        await sendBg({ type: 'trust-domain', host: hostName });
        try {
          trustBtn.textContent = '✓ Trusted';
          trustBtn.disabled = true;
          trustBtn.style.opacity = '0.6';
        } catch {}
      });
      actions.appendChild(trustBtn);
    }

    const closeBtn = el('button', {
      className: 'close',
      text: '✕',
      attrs: { 'aria-label': 'Dismiss' }
    });
    closeBtn.addEventListener('click', () => hostEl.remove());
    actions.appendChild(closeBtn);

    card.appendChild(actions);
    shadow.appendChild(card);

    try {
      const target = document.body || document.documentElement;
      if (target) target.appendChild(hostEl);
    } catch { return; }

    _autoDismissTimer = setTimeout(() => {
      try {
        hostEl.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
        hostEl.style.opacity = '0';
        hostEl.style.transform = 'translateX(30px)';
        setTimeout(() => { try { hostEl.remove(); } catch {} }, 320);
      } catch {}
    }, AUTO_DISMISS_MS);
  }

  function transitionToVerdict(report) {
    const existing = document.getElementById(BANNER_HOST_ID);
    if (existing && existing.dataset.state === 'loading') {
      try {
        if (_progressTimer) { clearInterval(_progressTimer); _progressTimer = null; }
        if (_loadingTimeout) { clearTimeout(_loadingTimeout); _loadingTimeout = null; }
        existing.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
        existing.style.opacity = '0';
        existing.style.transform = 'translateX(30px)';
      } catch {}
      setTimeout(() => {
        try { existing.remove(); } catch {}
        showVerdictBanner(report);
      }, 320);
    } else {
      showVerdictBanner(report);
    }
  }

  /* ============================================================
     MESSAGE LISTENER
     ============================================================ */
  try {
    chrome.runtime.onMessage.addListener((msg, sender, send) => {
      try {
        if (!msg || typeof msg !== 'object') return;
        if (msg.type === 'corsair-verdict-loading') {
          showLoadingBanner(msg.host || _selfHost);
          if (typeof send === 'function') send({ ok: true });
        } else if (msg.type === 'corsair-verdict') {
          transitionToVerdict(msg.report || {});
          if (typeof send === 'function') send({ ok: true });
        } else if (msg.type === 'corsair-verdict-cancel') {
          hardRemoveBanner();
          if (typeof send === 'function') send({ ok: true });
        }
      } catch {}
      return false;
    });
  } catch {}

  /* ============================================================
     SAFE REDIRECT RESOLVER
     ============================================================ */
  try {
    if (!_fortressArmed) {
      const target = resolveRedirectTarget();
      if (target && typeof window.location.replace === 'function') {
        window.location.replace(target);
        return;
      }
    }
  } catch {}

  /* ============================================================
     POPUP GUARD
     ============================================================ */
  (function installPopupGuard() {
    try {
      const originalOpen = window.open;
      window.open = function (url, name, features) {
        const isSuspiciousShape = (!name || /^_blank$/i.test(String(name))) &&
          /(?:left|top|width|height|resizable)/i.test(String(features || ''));

        if (_fortressArmed) {
          sendBg({
            type: 'content-popup-blocked',
            url: String(url || 'about:blank'),
            page: String(location.href || ''),
            host: _selfHost,
            reason: 'fortress-popup-lockdown'
          });
          console.warn('[Corsair Shield] Fortress armed — popup blocked:', url);
          return null;
        }

        if (!_fortressChecked && isSuspiciousShape) {
          sendBg({
            type: 'content-popup-blocked',
            url: String(url || 'about:blank'),
            page: String(location.href || ''),
            host: _selfHost,
            reason: 'unchecked-suspicious-popup'
          });
          return null;
        }

        return originalOpen.apply(this, arguments);
      };
    } catch {}
  })();

  /* ============================================================
     CLICK INTERCEPTION
     ============================================================ */
  document.addEventListener('click', function (e) {
    if (!_fortressArmed) return;
    const anchor = e.target && e.target.closest && e.target.closest('a');
    if (!anchor) return;

    const target = String(anchor.target || '').toLowerCase();
    const rel = String(anchor.rel || '').toLowerCase();
    const looksLikePopup = target === '_blank' || target === '_new' || rel.includes('noopener') || rel.includes('noreferrer');

    const href = String(anchor.href || '');
    let destHost = '';
    try {
      const u = new URL(href);
      if (u.protocol === 'http:' || u.protocol === 'https:') destHost = u.hostname.toLowerCase();
    } catch {}

    if (looksLikePopup) {
      e.preventDefault();
      e.stopPropagation();
      sendBg({
        type: 'content-popup-blocked',
        url: href,
        page: String(location.href || ''),
        host: _selfHost,
        reason: 'fortress-anchor-popup'
      });
      return;
    }

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
    if (!_fortressArmed) return;
    const anchor = e.target && e.target.closest && e.target.closest('a');
    if (!anchor) return;
    e.preventDefault();
    e.stopPropagation();
    sendBg({
      type: 'content-popup-blocked',
      url: String(anchor.href || ''),
      page: String(location.href || ''),
      host: _selfHost,
      reason: 'fortress-middle-click'
    });
  }, true);

  /* ============================================================
     META REFRESH GUARD
     ============================================================ */
  (function installMetaRefreshGuard() {
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
        node.remove();
        console.warn('[Corsair Shield] removed external meta refresh');
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

  /* ============================================================
     OBSERVATION COLLECTION
     ============================================================ */
  function collectExternalHosts(pageUrl) {
    const externalHosts = [];
    try {
      if (typeof document !== 'undefined' && document.querySelectorAll) {
        const currentHost = new URL(pageUrl).hostname;
        const elements = document.querySelectorAll('script[src], link[href], img[src], a[href]');
        for (const element of elements) {
          const raw = element.src || element.href;
          if (raw && typeof raw === 'string') {
            try {
              const u = new URL(raw, pageUrl);
              if ((u.protocol === 'http:' || u.protocol === 'https:') && u.hostname && u.hostname !== currentHost) {
                if (!externalHosts.includes(u.hostname)) externalHosts.push(u.hostname);
              }
            } catch {}
          }
          if (externalHosts.length >= 40) break;
        }
      }
    } catch {}
    return externalHosts;
  }

  function analyzeClickbaitPatterns() {
    let title = document.title || '';
    const ogTitleEl = document.querySelector('meta[property="og:title"]');
    if (ogTitleEl && ogTitleEl.content) title = ogTitleEl.content;
    if (!title || title.length < 8) return { score: 0, triggers: [] };

    let score = 0;
    const triggers = [];

    if (/[!?]{2,}/.test(title) || /[؟!]{2,}/.test(title)) {
      score += 30;
      triggers.push('excessive-punctuation');
    }

    const clickbaitKeywords = [
      /باورنکردنی/i, /راز\s*مخفی/i, /شوکه\s*کننده/i, /فوری\s*فوری/i,
      /هرگز\s*باور\s*نمی‌کنید/i, /لو\s*رفت/i, /دیدن\s*این\s*عکس/i,
      /you won't believe/i, /shocking/i, /mind-blowing/i, /secret trick/i,
      /what happens next/i, /this is why/i, /blow your mind/i
    ];

    for (const pattern of clickbaitKeywords) {
      if (pattern.test(title)) {
        score += 35;
        triggers.push(`pattern:${pattern.source.replace(/\\s\*/g, ' ')}`);
      }
    }
    return { score: Math.min(100, score), triggers: [...new Set(triggers)] };
  }

  function reportObservation() {
    try {
      if (typeof chrome === 'undefined' || !chrome.runtime?.sendMessage || !window.location?.href) return;
      const pageUrl = window.location.href;
      if (!isSafeWebScheme(pageUrl)) return;
      const externalHosts = collectExternalHosts(pageUrl);
      const clickbait = analyzeClickbaitPatterns();
      chrome.runtime.sendMessage({
        type: 'page-observation',
        observation: {
          url: pageUrl,
          externalHosts: externalHosts.slice(0, 40),
          clickbaitScore: clickbait.score,
          clickbaitTriggers: clickbait.triggers,
          findings: clickbait.score >= 50 ? ['suspicious-clickbait-title'] : []
        }
      }).catch(() => {});
    } catch {}
  }

  try {
    if (typeof document !== 'undefined' && document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', reportObservation, { once: true });
    } else {
      reportObservation();
    }
  } catch {}
})();

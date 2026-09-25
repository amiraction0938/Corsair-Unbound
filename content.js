(function () {
  'use strict';

  // This script runs ONLY in the top frame (all_frames: false, see
  // manifest.json) — it owns the verdict banner UI and page-level
  // observation (external-host scan, clickbait heuristics). The
  // behavioral interception that must run in every frame (popup guard,
  // click hijacking, meta-refresh, redirector resolution) lives in
  // content-frame-guard.js instead, so an ad iframe doesn't also try
  // to render its own copy of the verdict banner.

  let _selfHost = '';
  try { _selfHost = String(location.hostname || '').toLowerCase(); } catch {}

  function isSafeWebScheme(rawUrl) {
    if (!rawUrl || typeof rawUrl !== 'string') return false;
    try {
      const u = new URL(rawUrl);
      return u.protocol === 'http:' || u.protocol === 'https:';
    } catch { return false; }
  }

  function sendBg(msg) {
    try { return chrome.runtime.sendMessage(msg).catch(() => null); }
    catch { return Promise.resolve(null); }
  }

  /* ============================================================
     I18N BOOTSTRAP
     ------------------------------------------------------------
     core/i18n.js is loaded right before this file (see manifest),
     so window.CorsairI18n is available in the isolated world. We
     kick off load() immediately and every banner string is read
     via t() which is safe to call even before load() resolves
     (falls back to English defaults).
     ============================================================ */
  const t = (k, fb) => {
    try {
      if (window.CorsairI18n && typeof CorsairI18n.t === 'function') {
        const v = CorsairI18n.t(k, fb);
        if (v) return v;
      }
    } catch {}
    return fb || k;
  };

  let _i18nReadyPromise = null;
  function ensureI18n() {
    if (_i18nReadyPromise) return _i18nReadyPromise;
    _i18nReadyPromise = (async () => {
      try {
        if (window.CorsairI18n && typeof CorsairI18n.load === 'function') {
          await CorsairI18n.load();
        }
      } catch {}
    })();
    return _i18nReadyPromise;
  }
  ensureI18n();

  const AUTO_DISMISS_MS = 3000;

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
      case 'allowlisted': return { color: '#3b82f6', icon: '🛡️', label: t('banner.verdictAllowlisted', 'Trusted Site') };
      case 'clean':       return { color: '#10b981', icon: '✓',  label: t('banner.verdictClean', 'Safe Site') };
      case 'suspicious':  return { color: '#f59e0b', icon: '⚡', label: t('banner.verdictSuspicious', 'Suspicious Site') };
      case 'malicious':   return { color: '#f43f5e', icon: '⚠',  label: t('banner.verdictMalicious', 'Malicious Site') };
      default:            return { color: '#94a3b8', icon: '?',  label: t('banner.verdictUnknown', 'Unknown Site') };
    }
  }

  function buildReasons(report) {
    const reasons = [];
    const stats = report.stats || {};
    if (report.status === 'allowlisted') {
      reasons.push(t('banner.reasonAllowlisted', 'Domain is on the trusted allowlist'));
    } else {
      if (stats.malicious > 0) {
        reasons.push(t('banner.reasonMalicious', '{count} engine(s) flagged as MALICIOUS')
          .replace('{count}', String(stats.malicious)));
      }
      if (stats.suspicious > 0) {
        reasons.push(t('banner.reasonSuspicious', '{count} engine(s) flagged as suspicious')
          .replace('{count}', String(stats.suspicious)));
      }
      if (Array.isArray(report.flaggedEngines) && report.flaggedEngines.length) {
        const list = report.flaggedEngines.slice(0, 4).join(', ');
        const more = report.flaggedEngines.length > 4
          ? t('banner.reasonMore', ' +{count} more').replace('{count}', String(report.flaggedEngines.length - 4))
          : '';
        reasons.push(t('banner.reasonFlaggedBy', 'Flagged by: {list}').replace('{list}', list + more));
      }
      if (report.heuristicSignals?.length) {
        for (const sig of report.heuristicSignals.slice(0, 2)) {
          if (sig.message) reasons.push(sig.message);
        }
      }
      if (!reasons.length && report.verdict === 'clean') {
        reasons.push(t('banner.reasonClean', '0 / 70+ engines flagged this domain'));
      }
      if (!reasons.length) reasons.push(t('banner.reasonNoSignals', 'No threat intelligence signals'));
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
      attrs: { 'aria-label': t('banner.dismiss', 'Dismiss') }
    });

    const card = el('div', { className: 'card', attrs: { role: 'status' }, children: [closeBtn] });

    const row = el('div', { className: 'row' });
    const spinner = el('div', { className: 'spinner' });
    const body = el('div', { className: 'body' });

    const title = el('div', { className: 'title', text: t('banner.scanningTitle', 'Scanning Site…') });
    const hostLine = el('div', { className: 'host', text: String(host || _selfHost || '') });
    const progressWrap = el('div', { className: 'progress-wrap' });
    const progressFill = el('div', { className: 'progress-fill' });
    progressWrap.appendChild(progressFill);
    const statusLine = el('div', { className: 'status', text: t('banner.statusCache', 'Checking local cache…') });

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
        if (elapsed < 3000) statusLine.textContent = t('banner.statusCache', 'Checking local cache…');
        else if (elapsed < 8000) statusLine.textContent = t('banner.statusVT', 'Querying VirusTotal…');
        else if (elapsed < 15000) statusLine.textContent = t('banner.statusRate', 'Waiting for rate-limit slot…');
        else if (elapsed < 25000) statusLine.textContent = t('banner.statusEngines', 'Analyzing 70+ security engines…');
        else statusLine.textContent = t('banner.statusWorking', 'Still working…');
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
    const isAllowlisted = report.status === 'allowlisted';

    // Trust is offered on clean/unknown sites. Block is offered on
    // everything except sites already on the allowlist — because a site
    // only gets onto the allowlist through a prior explicit user action,
    // so re-offering "block" there would be redundant noise.
    const showTrustBtn = !isAllowlisted && !isMalicious;
    const showBlockBtn = !isAllowlisted;

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
        flex-wrap: wrap;
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
      .block-btn {
        background: rgba(244,63,94,0.15);
        border: 1px solid rgba(244,63,94,0.35);
        color: #f87171;
        padding: 5px 10px; border-radius: 6px;
        font-size: 11px; font-weight: 700;
        cursor: pointer;
      }
      .block-btn:hover { background: rgba(244,63,94,0.3); }
      .block-btn:disabled,
      .trust-btn:disabled { cursor: default; }
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
    body.appendChild(el('div', {
      className: 'risk',
      text: t('banner.riskLabel', '{risk}% risk').replace('{risk}', String(risk))
    }));

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
      const trustBtn = el('button', { className: 'trust-btn', text: t('banner.trustBtn', '✓ Trust') });
      trustBtn.addEventListener('click', async () => {
        await sendBg({ type: 'trust-domain', host: hostName });
        try {
          trustBtn.textContent = t('banner.trustedBtn', '✓ Trusted');
          trustBtn.disabled = true;
          trustBtn.style.opacity = '0.6';
        } catch {}
      });
      actions.appendChild(trustBtn);
    }

    if (showBlockBtn) {
      const blockBtn = el('button', { className: 'block-btn', text: t('banner.blockBtn', '🚫 Block') });
      blockBtn.addEventListener('click', async () => {
        const confirmTitle = t('banner.confirmBlockTitle', 'Block {host} everywhere?')
          .replace('{host}', hostName);
        const confirmBody = t('banner.confirmBlockBody',
          'All navigation to this domain will be stopped — from any page, any link, any redirect.\n\nYou can undo this from the Corsair dashboard → Blocked Domains.');
        const confirmed = window.confirm(confirmTitle + '\n\n' + confirmBody);
        if (!confirmed) return;

        blockBtn.disabled = true;
        blockBtn.textContent = '…';

        const res = await sendBg({ type: 'block-domain-global', host: hostName });
        if (res && res.ok) {
          blockBtn.textContent = t('banner.blockedBtn', '🚫 Blocked');
          blockBtn.style.opacity = '0.6';
        } else {
          blockBtn.textContent = t('banner.blockFailed', '⚠ Failed');
          setTimeout(() => {
            blockBtn.textContent = t('banner.blockBtn', '🚫 Block');
            blockBtn.disabled = false;
          }, 2000);
        }
      });
      actions.appendChild(blockBtn);
    }

    const closeBtn = el('button', {
      className: 'close',
      text: '✕',
      attrs: { 'aria-label': t('banner.dismiss', 'Dismiss') }
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
     ------------------------------------------------------------
     Verdict rendering is deferred until i18n is ready so the very
     first banner of a session is already in the user's language.
     ============================================================ */
  try {
    chrome.runtime.onMessage.addListener((msg, sender, send) => {
      try {
        if (!msg || typeof msg !== 'object') return false;

        if (msg.type === 'corsair-verdict-loading') {
          ensureI18n().then(() => {
            showLoadingBanner(msg.host || _selfHost);
            if (typeof send === 'function') send({ ok: true });
          }).catch(() => {
            if (typeof send === 'function') send({ ok: false });
          });
          return true;
        }

        if (msg.type === 'corsair-verdict') {
          ensureI18n().then(() => {
            transitionToVerdict(msg.report || {});
            if (typeof send === 'function') send({ ok: true });
          }).catch(() => {
            if (typeof send === 'function') send({ ok: false });
          });
          return true;
        }

        if (msg.type === 'corsair-verdict-cancel') {
          hardRemoveBanner();
          if (typeof send === 'function') send({ ok: true });
          return false;
        }
      } catch {}
      return false;
    });
  } catch {}

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
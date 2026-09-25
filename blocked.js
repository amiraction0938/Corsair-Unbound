(function () {
  'use strict';

  const t = (k, fb) => {
    try {
      if (window.CorsairI18n && typeof CorsairI18n.t === 'function') {
        const v = CorsairI18n.t(k, fb);
        if (v) return v;
      }
    } catch {}
    return fb || k;
  };

  function esc(s) {
    return String(s == null ? '' : s).replace(/[<>&"]/g, c => ({
      '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;'
    })[c]);
  }

  function sendBg(msg) {
    try { return chrome.runtime.sendMessage(msg).catch(() => null); }
    catch { return Promise.resolve(null); }
  }

  function setText(id, txt) {
    const el = document.getElementById(id);
    if (el) el.textContent = txt;
  }

  function setHtml(id, html) {
    const el = document.getElementById(id);
    if (el) el.innerHTML = html;
  }

  async function applyI18n() {
    try {
      if (window.CorsairI18n && typeof CorsairI18n.load === 'function') {
        await CorsairI18n.load();
      }
    } catch {}

    const params = new URLSearchParams(location.search);
    const isUserBlock = params.get('reason') === 'user-blocklist';
    const host = params.get('host') || '';

    if (isUserBlock) {
      setText('titleText', t('blocked.userBlockTitle', 'Domain Blocked'));
      setHtml('introText',
        t('blocked.userBlockIntro', 'You manually added {host} to your blocklist in Corsair Unbound.')
          .replace('{host}', '<strong>' + esc(host || 'this domain') + '</strong>')
      );
      setText('reasonText', t('blocked.userBlockReason',
        'This domain is on your personal blocklist. All navigation to it is stopped, from any page or link.'));
      setText('hintText', t('blocked.userBlockHint',
        'Changed your mind? Open the Corsair dashboard → Blocked Domains, and click Unblock.'));
    } else {
      setText('titleText', t('blocked.title', 'Navigation Blocked'));
      setHtml('introText', t('blocked.intro',
        'Corsair Unbound intercepted a third-party navigation from a Fortress-protected page.'));
      setText('reasonText', t('blocked.reasonDefault',
        'Source page is under lockdown. Script-driven redirects to external domains are contained before they leave the browser.'));
      setText('hintText', t('blocked.hint',
        'If you trust the destination, open the extension popup on the source site and add the domain to your allowlist.'));
    }

    setText('escapeBtn', t('blocked.escapeBtn', '← Leave this page'));
    setText('dashboardBtn', t('blocked.dashboardBtn', 'Open Corsair Dashboard'));
    setText('footerText', t('blocked.footer', 'Protected by Corsair Unbound — local-first browser shield'));
  }

  // Kick off translation immediately (async, but page is empty for a tick)
  applyI18n();

  document.getElementById('escapeBtn').addEventListener('click', async () => {
    const btn = document.getElementById('escapeBtn');
    btn.disabled = true;
    btn.textContent = '…';
    await sendBg({ type: 'blocked-page-escape' });
    // Failsafe: if the background never responds or the tab wasn't
    // updated, fall back to a plain history walk.
    setTimeout(() => {
      try {
        if (history.length > 1) history.back();
        else location.replace('about:blank');
      } catch {}
    }, 400);
  });

  document.getElementById('dashboardBtn').addEventListener('click', () => {
    try {
      chrome.runtime.sendMessage({ type: 'open-dashboard' }).catch(() => {});
    } catch {}
    // Belt-and-braces — the background may not have a handler, so navigate
    // the tab directly.
    setTimeout(() => {
      try {
        location.href = chrome.runtime.getURL('dashboard.html');
      } catch {}
    }, 200);
  });
})();
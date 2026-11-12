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

  const fmt = (s, vars) => String(s).replace(/\{(\w+)\}/g, (m, k) => (vars && Object.prototype.hasOwnProperty.call(vars, k)) ? String(vars[k]) : m);

  function sendBg(msg) {
    try { return chrome.runtime.sendMessage(msg).catch(() => null); }
    catch { return Promise.resolve(null); }
  }

  const $ = (id) => document.getElementById(id);
  function setText(id, txt) { const el = $(id); if (el) el.textContent = txt; }

  /** "...{host}..." with the host in <strong>, built from DOM nodes (no HTML injection). */
  function setIntro(id, template, host) {
    const el = $(id);
    if (!el) return;
    el.textContent = '';
    const parts = String(template).split('{host}');
    parts.forEach((part, i) => {
      if (part) el.appendChild(document.createTextNode(part));
      if (i < parts.length - 1) {
        const s = document.createElement('strong');
        s.textContent = host || t('blocked.thisDomain', 'this domain');
        el.appendChild(s);
      }
    });
  }

  const params = new URLSearchParams(location.search);
  const reason = params.get('reason') || '';
  const host = (params.get('host') || '').toLowerCase();
  const isUserBlock = reason === 'user-blocklist';

  // This page is web-accessible, so another site could put it in an iframe and try to trick the
  // user into clicking a button (clickjacking). The actions only work when the page is on its own.
  const framed = (() => { try { return window.top !== window.self; } catch { return true; } })();

  function showStatus(text, kind) {
    const box = $('statusBox');
    if (!box) return;
    box.hidden = false;
    box.className = 'status' + (kind ? ' ' + kind : '');
    box.textContent = text;
  }

  function setBusy(busy) {
    ['proceedBtn', 'fpBtn', 'wipeBtn'].forEach(id => { const b = $(id); if (b) b.disabled = busy; });
  }

  function addWhy(text) {
    const li = document.createElement('li');
    li.textContent = text;
    $('whyList').appendChild(li);
  }

  function renderWhy(info) {
    const list = $('whyList');
    if (list) list.textContent = '';

    if (!isUserBlock) {
      addWhy(fmt(t('blocked.why.fortress', '{host} is under Fortress lockdown. A script on that page tried to send you to another website, so Corsair stopped it.'), { host }));
      return;
    }

    const r = info && info.report;
    const autoRisk = (() => {
      if (r && Number.isFinite(r.risk)) return r.risk;
      const m = info && info.auto && /risk\s+(\d+(?:\.\d+)?)%/i.exec(info.auto.reason || '');
      return m ? Number(m[1]) : null;
    })();

    if (info && info.auto) {
      addWhy(fmt(t('blocked.why.auto', 'Corsair blocked it automatically: its risk score ({risk}%) reached your auto-block threshold ({threshold}%).'),
        { risk: autoRisk === null ? '?' : autoRisk, threshold: info.thresholds ? info.thresholds.autoBlock : '?' }));
    } else {
      addWhy(t('blocked.why.userList', 'The domain is on your blocklist.'));
    }

    if (r) {
      addWhy(fmt(t('blocked.why.scan', 'Last scan: risk {risk}%, {flagged} engine(s) flagged it ({malicious} malicious, {suspicious} suspicious). Verdict: {verdict}.'),
        { risk: r.risk === null ? '?' : r.risk, flagged: r.flagged, malicious: r.malicious, suspicious: r.suspicious, verdict: r.verdict }));
    } else {
      addWhy(t('blocked.why.noScan', 'No scan details are stored for this domain.'));
    }
  }

  async function applyI18n() {
    try {
      if (window.CorsairI18n && typeof CorsairI18n.load === 'function') {
        await CorsairI18n.load();
        if (typeof CorsairI18n.getDir === 'function') document.documentElement.dir = CorsairI18n.getDir() || 'ltr';
      }
    } catch {}

    if (isUserBlock) {
      setText('titleText', t('blocked.userBlockTitle', 'Domain Blocked'));
      setIntro('introText', t('blocked.userBlockIntro', 'Corsair Unbound blocked {host}.'), host);
      setText('reasonText', t('blocked.userBlockReason',
        'This domain is on your personal blocklist. All navigation to it is stopped, from any page or link.'));
      setText('hintText', t('blocked.userBlockHint',
        'Changed your mind? Open the Corsair dashboard \u2192 Blocked Domains, and click Unblock.'));
    } else {
      setText('titleText', t('blocked.title', 'Navigation Blocked'));
      setText('introText', t('blocked.intro',
        'Corsair Unbound intercepted a third-party navigation from a Fortress-protected page.'));
      setText('reasonText', t('blocked.reasonDefault',
        'Source page is under lockdown. Script-driven redirects to external domains are contained before they leave the browser.'));
      setText('hintText', t('blocked.hint',
        'If you trust the destination, open the extension popup on the source site and add the domain to your allowlist.'));
    }

    setText('whyTitle', t('blocked.whyTitle', 'Why was this blocked?'));
    setText('fpNote', t('blocked.fpNote', 'Risk scores are estimates and can be wrong. If you know this site is safe, choose "False positive".'));
    setText('proceedLabel', t('blocked.btn.proceed', 'Back to the site, with Fortress ON'));
    setText('proceedHint', t('blocked.btn.proceedHint', 'Unblocks it but keeps strict protection: redirects and popups stay contained. Automatic blocking pauses for 24 hours.'));
    setText('fpLabel', t('blocked.btn.fp', 'False positive: it is safe, trust it'));
    setText('fpHint', t('blocked.btn.fpHint', 'Adds it to your trusted list, removes the block and the automatic protection, and forgets the bad verdict.'));
    setText('wipeLabel', t('blocked.btn.wipe', 'Block it, wipe its data, open a new tab'));
    setText('wipeHint2', t('blocked.btn.wipeHint', 'Keeps it blocked, turns on Fortress, deletes its cookies and stored site data, then moves you to a new tab.'));
    setText('escapeBtn', t('blocked.escapeBtn', '\u2190 Leave this page'));
    setText('dashboardBtn', t('blocked.dashboardBtn', 'Open Corsair Dashboard'));
    setText('footerText', t('blocked.footer', 'Protected by Corsair Unbound \u2014 local-first browser shield'));

    renderWhy(null);
  }

  async function loadInfo() {
    if (framed || !host) return;
    const res = await sendBg({ type: 'get-block-info', host });
    if (res && res.ok) renderWhy(res.info);
  }

  async function runAction(ev, action, confirmKey, confirmFallback) {
    // only a real user click counts (the page itself could script a fake one)
    if (!ev || ev.isTrusted !== true) return;
    if (framed) return;
    if (confirmKey && !window.confirm(fmt(t(confirmKey, confirmFallback), { host }))) return;

    setBusy(true);
    showStatus(t('blocked.working', 'Working\u2026'));
    const res = await sendBg({ type: 'block-page-action', action, host });

    if (!res || !res.ok) {
      showStatus(fmt(t('blocked.failed', 'It did not work: {error}'), { error: (res && res.error) || 'no response' }), 'bad');
      setBusy(false);
      return;
    }
    const failed = (res.steps || []).filter(s => !s.ok);
    if (res.newTab && !res.navigated && failed.length) {
      showStatus(fmt(t('blocked.partial', 'Blocked, but some cleanup steps failed: {steps}. This page stays open so you can see it.'),
        { steps: failed.map(s => `${s.name} (${s.error})`).join(', ') }), 'warn');
      setBusy(false);
      return;
    }
    showStatus(t('blocked.done', 'Done. Opening\u2026'), 'ok');
  }

  applyI18n().then(loadInfo);

  if (framed) {
    ['choices'].forEach(id => { const el = $(id); if (el) el.hidden = true; });
    showStatus(t('blocked.framed', 'For your safety these actions only work when this page is opened by itself, not inside another page.'), 'warn');
  } else {
    $('proceedBtn').addEventListener('click', (ev) => runAction(ev, 'proceed-fortress'));
    $('fpBtn').addEventListener('click', (ev) => runAction(ev, 'false-positive', 'blocked.confirm.fp', 'Trust {host}? Corsair will stop scanning and protecting this domain.'));
    $('wipeBtn').addEventListener('click', (ev) => runAction(ev, 'block-wipe', 'blocked.confirm.wipe', 'Keep {host} blocked and delete its cookies and stored site data?'));
  }

  $('escapeBtn').addEventListener('click', async (ev) => {
    if (!ev || ev.isTrusted !== true) return;
    const btn = $('escapeBtn');
    btn.disabled = true;
    await sendBg({ type: 'blocked-page-escape' });
    // Failsafe: if the background never responds or the tab wasn't updated, fall back to history.
    setTimeout(() => {
      try {
        if (history.length > 1) history.back();
        else location.replace('about:blank');
      } catch {}
    }, 400);
  });

  $('dashboardBtn').addEventListener('click', (ev) => {
    if (!ev || ev.isTrusted !== true) return;
    try { chrome.runtime.sendMessage({ type: 'open-dashboard' }).catch(() => {}); } catch {}
    setTimeout(() => { try { location.href = chrome.runtime.getURL('dashboard.html'); } catch {} }, 200);
  });
})();

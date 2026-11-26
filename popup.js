(() => {
  'use strict';

  const $ = id => document.getElementById(id);
  const t = (k, fb) => (window.CorsairI18n ? CorsairI18n.t(k, fb) : (fb || k));
  const isFaUi = () => String((window.CorsairI18n && CorsairI18n.getCurrent && CorsairI18n.getCurrent()) || '').toLowerCase().startsWith('fa');
  const tx = (en, fa) => (isFaUi() ? fa : en);

  const state = {
  domain: '',
  profile: null,
  diagnostics: null,
  settings: {},
  threatReport: null,
  hasApiKey: false
};

  /* ============================================================
     DOM HELPERS — Trusted-Types / XSS safe (all createElement)
     ============================================================ */
  function el(tag, opts = {}) {
    const node = document.createElement(tag);
    if (opts.className) node.className = opts.className;
    if (opts.text != null) node.textContent = String(opts.text);
    if (opts.style) {
      if (typeof opts.style === 'string') {
        try { node.setAttribute('style', opts.style); } catch {}
      } else {
        for (const [k, v] of Object.entries(opts.style)) {
          try { node.style[k] = v; } catch {}
        }
      }
    }
    if (opts.attrs) {
      for (const [k, v] of Object.entries(opts.attrs)) {
        try { node.setAttribute(k, String(v)); } catch {}
      }
    }
    if (opts.children) {
      for (const c of opts.children) if (c) node.appendChild(c);
    }
    if (opts.on) {
      for (const [evt, handler] of Object.entries(opts.on)) {
        node.addEventListener(evt, handler);
      }
    }
    return node;
  }

  function clearNode(node) {
    if (!node) return;
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  /* ============================================================
     i18n APPLY
     ============================================================ */
  function applyI18n(root = document) {
    if (!window.CorsairI18n) return;
    root.querySelectorAll('[data-i18n]').forEach(node => {
      const key = node.getAttribute('data-i18n');
      node.textContent = t(key, node.textContent);
    });
    root.querySelectorAll('[data-i18n-title]').forEach(node => {
      const key = node.getAttribute('data-i18n-title');
      node.setAttribute('title', t(key, node.getAttribute('title') || ''));
    });
    root.querySelectorAll('[data-i18n-placeholder]').forEach(node => {
      const key = node.getAttribute('data-i18n-placeholder');
      node.setAttribute('placeholder', t(key, node.getAttribute('placeholder') || ''));
    });
    if (window.CorsairI18n.applyDirection) CorsairI18n.applyDirection();
    // Sync the DOM's lang attribute
    try { document.documentElement.setAttribute('lang', CorsairI18n.getCurrent()); } catch {}
  }

  /* ============================================================
     TOAST
     ============================================================ */
  function showToast(message, type = 'success') {
    const container = $('toastContainer');
    if (!container) return;
    const toast = el('div', { className: `toast ${type}` });
    toast.appendChild(el('span', { text: type === 'success' ? '✓' : '⚠' }));
    toast.appendChild(el('span', { text: String(message || '') }));
    container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transition = 'opacity 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 3000);
  }

  /* ============================================================
     HELPERS
     ============================================================ */
  function normalizeHost(raw) {
    try {
      const u = new URL(raw);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return '';
      return u.hostname.toLowerCase().replace(/\.$/, '');
    } catch { return ''; }
  }

  function send(message) {
    return chrome.runtime.sendMessage(message).then(res => {
      if (!res || !res.ok) throw new Error(res?.error || 'Request failed');
      return res;
    });
  }

  /* ============================================================
     USERSCRIPTS ON THIS SITE
     (the commands used to be a floating button inside the page; they live here now)
     ============================================================ */
  async function renderUserscripts() {
    const sec = $('gmSection');
    const list = $('gmList');
    if (!sec || !list) return;
    const hide = () => { sec.hidden = true; list.textContent = ''; };

    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const tab = tabs[0];
    const host = normalizeHost((tab && tab.url) || '');
    if (!tab || !Number.isInteger(tab.id) || !host) { hide(); return; }

    let res;
    try { res = await send({ type: 'gm-menu-get', tabId: tab.id }); } catch { hide(); return; }
    const scripts = Array.isArray(res.scripts) ? res.scripts : [];
    const otherScripts = Array.isArray(res.otherScripts) ? res.otherScripts : [];
    if (!scripts.length && !otherScripts.length) { hide(); return; }

    const title = $('gmTitle');
    if (title) title.textContent = '\u{1F9E9} ' + tx('Userscripts on this site', 'اسکریپت‌های کاربر روی این سایت');
    list.textContent = '';

    for (const s of scripts) {
      const enabled = s.enabled !== false;
      const box = el('div', { className: 'gm-script' + (enabled ? '' : ' disabled') });

      const head = el('div', { className: 'gm-script-head' });
      const nameEl = el('div', {
        className: 'gm-script-name',
        text: String(s.name || 'Script') + (s.version ? ' v' + s.version : '')
      });
      nameEl.title = nameEl.textContent;

      const rightControls = el('div', { className: 'gm-script-controls' });
      const runNowBtn = el('button', { className: 'gm-mini-btn', text: '▶' });
      runNowBtn.type = 'button';
      runNowBtn.title = tx('Inject & run now on this tab', 'تزریق و اجرای فوری روی این تب');
      runNowBtn.addEventListener('click', async () => {
        runNowBtn.disabled = true;
        try {
          const r = await send({ type: 'us-run-now', id: s.id, tabId: tab.id });
          if (r && r.ok) showToast(tx('Injected on this tab', 'روی این تب تزریق شد'));
          else showToast((r && r.error) || tx('Injection failed', 'تزریق ناموفق بود'), 'error');
        } catch (err) {
          showToast(err.message || tx('Injection failed', 'تزریق ناموفق بود'), 'error');
        } finally {
          runNowBtn.disabled = false;
        }
      });

      const toggle = document.createElement('input');
      toggle.type = 'checkbox';
      toggle.className = 'gm-script-toggle';
      toggle.checked = enabled;
      toggle.title = enabled ? tx('Disable script', 'غیرفعال کردن') : tx('Enable script', 'فعال کردن');
      toggle.addEventListener('change', async () => {
        toggle.disabled = true;
        try {
          const tr = await send({ type: 'us-toggle', id: s.id, enabled: toggle.checked });
          if (tr && tr.ok) {
            box.classList.toggle('disabled', !toggle.checked);
            showToast(toggle.checked ? tx('Script enabled (reload page)', 'اسکریپت فعال شد (صفحه را بازخوانی کنید)') : tx('Script disabled', 'اسکریپت غیرفعال شد'));
          } else {
            toggle.checked = !toggle.checked;
          }
        } catch {
          toggle.checked = !toggle.checked;
        } finally {
          toggle.disabled = false;
        }
      });

      const editBtn = el('button', { className: 'gm-mini-btn', text: '✎' });
      editBtn.type = 'button';
      editBtn.title = tx('Edit script in Dashboard', 'ویرایش اسکریپت در داشبورد');
      editBtn.addEventListener('click', () => {
        chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html?edit=' + encodeURIComponent(s.id)) });
        window.close();
      });
      rightControls.append(runNowBtn, editBtn, toggle);
      head.append(nameEl, rightControls);
      box.appendChild(head);

      if (s.lastError) {
        box.appendChild(el('div', { className: 'gm-script-err', text: String(s.lastError) }));
      }

      const cmds = Array.isArray(s.commands) ? s.commands : [];
      if (!cmds.length) {
        box.appendChild(el('div', {
          className: 'muted-text',
          text: enabled
            ? (s.runEverywhere ? tx('Active on all sites', 'فعال روی همه سایت‌ها') : tx('Active on this site', 'روی این سایت فعال است'))
            : tx('Disabled on this site', 'غیرفعال روی این سایت')
        }));
      }
      for (const c of cmds) {
        const label = String(c.name || '') + (c.accessKey ? ` [${c.accessKey}]` : '');
        const btn = el('button', { className: 'gm-cmd', text: label });
        btn.type = 'button';
        btn.title = String(c.name || '');
        btn.disabled = !enabled;
        btn.addEventListener('click', async () => {
          btn.disabled = true;
          try {
            await send({ type: 'gm-menu-run', tabId: tab.id, scriptId: s.id, commandId: c.id });
            window.close();
          } catch (err) {
            showToast(err.message || tx('Could not run the command', 'اجرای فرمان ممکن نشد'), 'error');
            btn.disabled = false;
          }
        });
        box.appendChild(btn);
      }
      list.appendChild(box);
    }

    // Quick-inject ANY other installed script onto this tab on demand
    if (otherScripts.length) {
      const injectBox = el('div', { className: 'gm-inject-bar' });
      const sel = document.createElement('select');
      sel.className = 'gm-inject-select';
      for (const o of otherScripts) {
        const opt = document.createElement('option');
        opt.value = o.id;
        opt.textContent = String(o.name || 'Script');
        sel.appendChild(opt);
      }
      const runOther = el('button', { className: 'gm-mini-btn', text: tx('▶ Run', '▶ اجرا') });
      runOther.type = 'button';
      runOther.title = tx('Inject selected script on this tab now', 'تزریق فوری اسکریپت انتخاب‌شده روی این تب');
      runOther.addEventListener('click', async () => {
        runOther.disabled = true;
        try {
          const r = await send({ type: 'us-run-now', id: sel.value, tabId: tab.id });
          if (r && r.ok) showToast(tx('Injected on this tab', 'روی این تب تزریق شد'));
          else showToast((r && r.error) || tx('Injection failed', 'تزریق ناموفق بود'), 'error');
        } catch (err) {
          showToast(err.message || tx('Injection failed', 'تزریق ناموفق بود'), 'error');
        } finally {
          runOther.disabled = false;
        }
      });
      const addSiteBtn = el('button', { className: 'gm-mini-btn', text: tx('+ Site', '+ سایت') });
      addSiteBtn.type = 'button';
      addSiteBtn.title = tx(`Always match *://${host}/*`, `افزودن همیشگی به *://${host}/*`);
      addSiteBtn.addEventListener('click', async () => {
        addSiteBtn.disabled = true;
        try {
          const r = await send({ type: 'us-add-match', id: sel.value, pattern: `*://${host}/*` });
          if (r && r.ok) {
            showToast(tx(`Added to ${host}`, `به ${host} اضافه شد`));
            renderUserscripts().catch(() => {});
          } else {
            showToast((r && r.error) || tx('Failed', 'ناموفق'), 'error');
          }
        } finally {
          addSiteBtn.disabled = false;
        }
      });
      injectBox.append(sel, runOther, addSiteBtn);
      list.appendChild(injectBox);
    }

    sec.hidden = false;
  }
  async function activeDomain() {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    return normalizeHost(tabs[0]?.url || '');
  }

  /* ============================================================
     THREAT INTEL
     ============================================================ */
  function renderThreatStatus(report) {
    const statusEl = $('threatStatus');
    const statsEl = $('threatStats');
    const fillEl = $('riskBarFill');
    const pctEl = $('riskPercentText');
    const flagsEl = $('vtEnginesDetected');
    if (!statusEl || !statsEl) return;

    clearNode(statusEl);

    if (!report) {
      statusEl.appendChild(el('span', { text: t('popup.notAnalyzed', 'Not analyzed yet') }));
      statsEl.textContent = t('popup.clickToAnalyze', 'Click "Analyze" to query VirusTotal.');
      if (fillEl) fillEl.style.width = '0%';
      if (pctEl) { pctEl.textContent = t('popup.riskPct', '0% Risk'); pctEl.style.color = 'var(--accent)'; }
      if (flagsEl) { clearNode(flagsEl); flagsEl.appendChild(el('span', { text: t('popup.noData', 'No data available') })); }
      return;
    }

    if (report.error) {
      statusEl.appendChild(el('span', { style: { color: '#f87171' }, text: '⚠ ' + String(report.error) }));
      statsEl.textContent = '—';
      return;
    }

    const risk = Number(report.riskPercentage) || 0;
    const verdict = String(report.verdict || report.status || 'unknown').toLowerCase();

    if (fillEl) fillEl.style.width = `${risk}%`;
    if (pctEl) pctEl.textContent = `${risk}% ${t('popup.risk', 'Risk')}`;

    let color = '#10b981', fillColor = '#10b981';
    if (verdict === 'malicious') { color = '#f87171'; fillColor = '#f43f5e'; }
    else if (verdict === 'suspicious') { color = '#fbbf24'; fillColor = '#f59e0b'; }
    else if (report.status === 'allowlisted') { color = '#60a5fa'; fillColor = '#3b82f6'; }

    if (fillEl) fillEl.style.background = fillColor;
    if (pctEl) pctEl.style.color = color;

    if (report.status === 'allowlisted') {
      statusEl.appendChild(el('span', { style: { color: '#34d399' }, text: '✓ ' + t('popup.trustedSite', 'Trusted Site (Whitelisted)') }));
      statsEl.textContent = t('popup.wlNoQuota', 'Verified high-reputation domain — no VT quota used.');
      if (flagsEl) {
        clearNode(flagsEl);
        flagsEl.appendChild(el('span', { style: { color: '#34d399' }, text: '✓ ' + t('popup.onAllowlist', 'On trusted allowlist') }));
      }
      return;
    }

    if (verdict === 'malicious') {
      const malCount = Number(report.stats?.malicious) || 0;
      statusEl.appendChild(el('span', {
        style: { color: '#f87171', fontWeight: 'bold' },
        text: `⚠ ${t('popup.malicious', 'Malicious')} (${malCount} ${t('popup.engines', 'engines')})`
      }));
    } else if (verdict === 'suspicious') {
      const susCount = Number(report.stats?.suspicious) || 0;
      statusEl.appendChild(el('span', {
        style: { color: '#fbbf24' },
        text: `⚡ ${t('popup.suspicious', 'Suspicious')} (${susCount} ${t('popup.engines', 'engines')})`
      }));
    } else if (verdict === 'clean') {
      statusEl.appendChild(el('span', { style: { color: '#34d399' }, text: '✓ ' + t('popup.clean', 'Clean') }));
    } else {
      statusEl.appendChild(el('span', { text: t('popup.unknown', 'Unknown') + ` (${report.status || 'unrated'})` }));
    }

    if (flagsEl) {
      clearNode(flagsEl);
      const engines = Array.isArray(report.flaggedEngines) ? report.flaggedEngines : [];
      if (engines.length) {
        const prefix = verdict === 'malicious'
          ? '⚠ ' + t('popup.flaggedBy', 'Flagged by') + ': '
          : '⚡ ' + t('popup.flaggedBy', 'Flagged by') + ': ';
        flagsEl.appendChild(el('strong', { style: { color }, text: prefix }));
        const list = engines.slice(0, 6).join(', ');
        const more = engines.length > 6 ? ` +${engines.length - 6} ${t('popup.more', 'more')}` : '';
        flagsEl.appendChild(document.createTextNode(list + more));
      } else if (verdict === 'clean') {
        flagsEl.appendChild(el('span', {
          style: { color: '#34d399' },
          text: '✓ ' + t('popup.noEnginesFlagged', '0 / 70+ engines flagged this site')
        }));
      } else {
        flagsEl.appendChild(el('span', { text: t('popup.notIndexed', 'Not yet indexed by VirusTotal') }));
      }

      if (Array.isArray(report.heuristicSignals) && report.heuristicSignals.length) {
        const heur = report.heuristicSignals
          .map(s => s.message || s.kind)
          .slice(0, 2)
          .join(' • ');
        flagsEl.appendChild(el('div', {
          style: { marginTop: '4px', color: '#fbbf24' },
          text: `🧠 ${heur}`
        }));
      }
    }

    const harmless = Number(report.stats?.harmless) || 0;
    const malicious = Number(report.stats?.malicious) || 0;
    const suspicious = Number(report.stats?.suspicious) || 0;
    statsEl.textContent =
      `${t('popup.harmless', 'Harmless')}: ${harmless} • ` +
      `${t('popup.malicious', 'Malicious')}: ${malicious} • ` +
      `${t('popup.suspicious', 'Suspicious')}: ${suspicious}`;
  }

  function renderAutoArmBadge() {
    const card = document.querySelector('.vt-card');
    if (!card) return;

    let badge = card.querySelector('.auto-arm-badge');
    const profile = state.profile;
    const isAutoArmed = profile?.autoArmed === true;

    if (!isAutoArmed) {
      if (badge) badge.remove();
      return;
    }

    if (!badge) {
      badge = el('div', { className: 'auto-arm-badge' });
      card.appendChild(badge);
    }
    clearNode(badge);
    badge.appendChild(el('span', { text: '⚡ ' + t('popup.autoArmed', 'Auto-Armed') + ' — ' }));
    badge.appendChild(el('span', {
      className: 'auto-arm-reason',
      text: profile.autoArmReason || t('popup.triggeredByScan', 'triggered by threat scan')
    }));
  }

  async function loadThreatIntel() {
    if (!state.domain) return;
    const btn = $('scanDomainBtn');
    if (btn) btn.disabled = false;

    try {
      const res = await send({ type: 'get-threat-intel', domain: state.domain });
      let report = res?.report;

      if (!report && state.settings.threatIntelEnabled && state.settings.threatIntelAutoScan) {
        renderThreatStatus({ status: 'analyzing', riskPercentage: 0, verdict: 'unknown' });
        try {
          const q = await send({ type: 'query-threat-intel', domain: state.domain, force: false });
          report = q?.report;
        } catch {}
      }

      state.threatReport = report;
      renderThreatStatus(report);
      renderAutoArmBadge();
    } catch {
      renderThreatStatus({ error: t('popup.tiOffline', 'Threat intelligence offline') });
    }
  }

  /* ============================================================
     PROFILE / SHIELD BUTTON
     ============================================================ */
  function renderProfile() {
    const profile = state.profile;
    const isArmed = Boolean(profile?.protected === true && profile?.mode === 'fortress');
    const btn = $('instantShieldBtn');
    const btnText = $('shieldBtnText');
    const stateEl = $('profileState');

    if (stateEl) {
      if (isArmed && profile?.autoArmed === true) {
        stateEl.textContent = '⚡ ' + t('popup.stateAutoArmed', 'Auto-Armed: Popups blocked, navigation isolated');
      } else if (isArmed) {
        stateEl.textContent = '🛡️ ' + t('popup.stateFortressActive', 'Fortress Active: Popups blocked, navigation isolated');
      } else {
        stateEl.textContent = t('popup.stateVulnerable', 'Vulnerable: Default protection. Click to lock site');
      }
    }

    if (btn && btnText) {
      btn.disabled = !state.domain;
      if (isArmed) {
        btn.className = 'shield-btn armed';
        btnText.textContent = t('popup.disarm', 'Disarm Fortress');
      } else {
        btn.className = 'shield-btn';
        btnText.textContent = t('popup.addArm', 'Add & Arm Fortress');
      }
    }

    renderBlockedDestinations();
    renderAutoArmBadge();
  }

  function renderBlockedDestinations() {
    const list = $('blockedList');
    if (!list) return;
    clearNode(list);

    const blocked = Array.isArray(state.profile?.blockedDestinationDomains)
      ? state.profile.blockedDestinationDomains
      : [];

    if (blocked.length === 0) {
      list.appendChild(el('div', {
        style: { color: 'var(--text-muted)', fontSize: '11px', padding: '4px 0' },
        text: t('popup.noBlockedDest', 'No blocked destinations.')
      }));
      return;
    }

    for (const host of blocked) {
      const item = el('div', { className: 'blocked-item' });
      item.appendChild(el('span', { text: host }));
      item.appendChild(el('button', {
        text: '✕',
        attrs: { title: t('scripts.remove', 'Remove'), 'aria-label': `${t('scripts.remove', 'Remove')} ${host}` },
        on: { click: () => removeBlock(host) }
      }));
      list.appendChild(item);
    }
  }

  /* ============================================================
     AUTO-ARM CONTROLS
     ============================================================ */
  // Same rules as CorsairAutoArm.clampPct: only real numbers / non-empty numeric strings count
  // (Number(null) and Number('') are 0 and must never become a 1% threshold).
  function safePct(value, fallback) {
    let n = NaN;
    if (typeof value === 'number') n = value;
    else if (typeof value === 'string' && value.trim() !== '') n = Number(value);
    if (!Number.isFinite(n)) return fallback;
    return Math.min(100, Math.max(1, n));
  }

  function renderAutoArmControls() {
    const toggle = $('autoArmToggle');
    const armSlider = $('armThreshold');
    const blockSlider = $('blockThreshold');
    const armVal = $('armThresholdValue');
    const blockVal = $('blockThresholdValue');

    const enabled = state.settings.autoArmFortress !== false;
    const armThreshold = safePct(state.settings.autoArmFortressThreshold, 10);
    const blockThreshold = safePct(state.settings.autoBlockThreshold, 75);

    if (toggle) {
      toggle.textContent = enabled ? 'ON' : 'OFF';
      toggle.className = `status-badge ${enabled ? 'on' : 'off'}`;
    }
    if (armSlider) armSlider.value = String(armThreshold);
    if (blockSlider) blockSlider.value = String(blockThreshold);
    if (armVal) armVal.textContent = `${armThreshold}%`;
    if (blockVal) blockVal.textContent = `${blockThreshold}%`;
  }

  /* Explain, in plain words, what Auto-Arm decided for THIS site and why. */
  function describeAutoArm(st) {
    if (!st || !st.ok) return null;
    const armMin = st.thresholds ? st.thresholds.armMin : 10;
    const blockMin = st.thresholds ? st.thresholds.blockMin : 75;
    const d = st.diag;
    const risk = (d && Number.isFinite(d.risk)) ? d.risk : (Number.isFinite(st.risk) ? st.risk : null);

    if (!st.enabled) return { cls: 'warn', text: tx('Auto-Arm is OFF, so no site is armed automatically.', 'Auto-Arm خاموش است، پس هیچ سایتی خودکار فعال نمی‌شود.') };
    if (!st.scanEnabled && !d) return { cls: 'warn', text: tx('Threat scanning is off, so there is no risk score to compare with the threshold.', 'اسکن تهدید خاموش است، پس امتیاز ریسکی برای مقایسه با آستانه وجود ندارد.') };
    if (st.allowlisted) return { cls: '', text: tx('Trusted / allowlisted site: it is never armed automatically.', 'سایت مورد اعتماد (allowlist): هرگز خودکار فعال نمی‌شود.') };
    if (!d) {
      if (risk === null) return { cls: '', text: tx('No scan result yet for this site. Auto-Arm decides as soon as the scan finishes (a VirusTotal key helps).', 'هنوز نتیجه‌ی اسکنی برای این سایت نیست. Auto-Arm به‌محض پایان اسکن تصمیم می‌گیرد (کلید VirusTotal کمک می‌کند).') };
      return { cls: '', text: tx(`Last risk ${risk}%. Auto-Arm has not evaluated this site yet; reload the page.`, `آخرین ریسک ${risk}٪. Auto-Arm هنوز این سایت را ارزیابی نکرده؛ صفحه را دوباره بارگذاری کنید.`) };
    }
    switch (d.reason) {
      case 'arm':
        return d.applied
          ? { cls: 'ok', text: tx(`Armed automatically: risk ${risk}% ≥ ${armMin}%.`, `خودکار فعال شد: ریسک ${risk}٪ ≥ ${armMin}٪.`) }
          : { cls: 'bad', text: tx(`Should arm (risk ${risk}% ≥ ${armMin}%) but applying failed: ${d.error || 'unknown error'}. See Activity.`, `باید فعال می‌شد (ریسک ${risk}٪ ≥ ${armMin}٪) ولی اعمال نشد: ${d.error || 'خطای نامشخص'}. بخش Activity را ببینید.`) };
      case 'block':
        return d.applied
          ? { cls: 'ok', text: tx(`Blocked automatically: risk ${risk}% ≥ ${blockMin}%.`, `خودکار مسدود شد: ریسک ${risk}٪ ≥ ${blockMin}٪.`) }
          : { cls: 'bad', text: tx(`Should block (risk ${risk}% ≥ ${blockMin}%) but applying failed: ${d.error || 'unknown error'}.`, `باید مسدود می‌شد (ریسک ${risk}٪ ≥ ${blockMin}٪) ولی اعمال نشد: ${d.error || 'خطای نامشخص'}.`) };
      case 'below-threshold':
        return { cls: '', text: tx(`Not armed: risk ${risk}% is below your Arm-at threshold (${armMin}%).`, `فعال نشد: ریسک ${risk}٪ کمتر از آستانه‌ی «Arm at» شما (${armMin}٪) است.`) };
      case 'already-protected':
        return { cls: 'ok', text: tx(`Already protected (risk ${risk}%).`, `از قبل محافظت‌شده است (ریسک ${risk}٪).`) };
      case 'user-opt-out':
        return { cls: 'warn', text: tx(`Not armed: you turned Fortress off for this site (risk ${risk}% ≥ ${armMin}%). Arm it manually to protect it again.`, `فعال نشد: شما Fortress را برای این سایت خاموش کرده‌اید (ریسک ${risk}٪ ≥ ${armMin}٪). برای محافظت دوباره، دستی فعالش کنید.`) };
      case 'allowlisted':
        return { cls: '', text: tx('Trusted / allowlisted site: it is never armed automatically.', 'سایت مورد اعتماد (allowlist): هرگز خودکار فعال نمی‌شود.') };
      case 'report-error':
        return { cls: 'warn', text: tx('The last scan failed, so no decision was made. It will retry.', 'آخرین اسکن ناموفق بود و تصمیمی گرفته نشد. دوباره تلاش می‌شود.') };
      case 'disabled':
        return { cls: 'warn', text: tx('Auto-Arm is OFF.', 'Auto-Arm خاموش است.') };
      default:
        return null;
    }
  }

  async function renderAutoArmStatus() {
    const el = $('autoArmStatus');
    if (!el) return;
    try {
      if (!state.domain) { el.hidden = true; return; }
      const res = await send({ type: 'get-autoarm-status', domain: state.domain });
      const info = describeAutoArm(res);
      if (!info) { el.hidden = true; return; }
      el.hidden = false;
      el.className = 'auto-arm-status' + (info.cls ? ' ' + info.cls : '');
      el.textContent = info.text;
    } catch { el.hidden = true; }
  }

  async function persistThreshold(key, value) {
    try {
      const res = await send({ type: 'patch-settings', patch: { [key]: value } });
      state.settings = res.settings || state.settings;
      return true;
    } catch (err) {
      showToast(err.message, 'error');
      return false;
    }
  }

  /* ============================================================
     REFRESH
     ============================================================ */
  async function refresh() {
    try {
      state.domain = await activeDomain();
      const domainEl = $('domain');
      if (domainEl) domainEl.textContent = state.domain || t('popup.unsupported', 'Unsupported page');

      // runs in parallel (it waits a moment for the scripts to announce their commands)
      renderUserscripts().catch(() => {});

      if (!state.domain) {
        state.profile = null;
        renderProfile();
        return;
      }

      const [profileResult, diagResult, settingsResult, apiKeyResult] = await Promise.all([
        send({ type: 'get-profile', domain: state.domain }),
        send({ type: 'get-diagnostics' }),
        send({ type: 'get-settings' }),
        send({ type: 'get-api-key-secure' }).catch(() => ({ apiKey: '' }))
      ]);

      state.profile = profileResult.profile;
      state.diagnostics = diagResult.diagnostics;
      state.settings = settingsResult.settings || {};
      state.hasApiKey = Boolean(apiKeyResult?.apiKey);

      if (state.settings.threatIntelEnabled && state.settings.threatIntelAutoScan) {
        const cached = await send({ type: 'get-threat-intel', domain: state.domain }).catch(() => null);
        if (!cached?.report) {
          send({ type: 'query-threat-intel', domain: state.domain, force: false }).catch(() => {});
        }
      }

      const resolverBtn = $('resolver');
      if (resolverBtn) {
        const on = state.settings.resolverEnabled === true;
        resolverBtn.textContent = on ? 'ON' : 'OFF';
        resolverBtn.className = `status-badge ${on ? 'on' : 'off'}`;
      }

      if ($('dnrCount')) $('dnrCount').textContent = String(state.diagnostics?.dnrRuleCount || 0);
      if ($('graphCount')) $('graphCount').textContent = String(state.diagnostics?.graphNodeCount || 0);
      if ($('profileCount')) $('profileCount').textContent = String(state.diagnostics?.profileCount || 0);

      renderProfile();
      renderAutoArmControls();
      renderAutoArmStatus();
      await loadThreatIntel();
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  /* ============================================================
     ACTIONS
     ============================================================ */
  async function toggleInstantShield() {
    if (!state.domain) return;
    const isArmed = Boolean(state.profile?.protected === true && state.profile?.mode === 'fortress');
    const patch = isArmed
      ? { protected: false, mode: 'standard', autoArmed: false }
      : { protected: true, mode: 'fortress', autoContainRedirects: true, clickbaitGuard: true };

    try {
      const res = await send({ type: 'patch-profile', domain: state.domain, patch });
      state.profile = res.profile;
      renderProfile();
      showToast(isArmed
        ? t('popup.toastDisarmed', 'Fortress Disarmed.')
        : '⚡ ' + t('popup.toastArmed', 'Domain added & Fortress Armed!'));
      await refresh();
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  async function addBlock() {
    if (!state.domain) return;
    const input = $('destination');
    const destination = normalizeHost(input?.value?.trim() || '');
    if (!destination) {
      showToast(t('popup.invalidDest', 'Enter a valid destination domain'), 'error');
      return;
    }
    try {
      const current = Array.isArray(state.profile?.blockedDestinationDomains)
        ? state.profile.blockedDestinationDomains
        : [];
      const blocked = [...new Set([...current, destination])].slice(0, 1000);
      const res = await send({
        type: 'patch-profile',
        domain: state.domain,
        patch: { protected: true, mode: 'fortress', blockedDestinationDomains: blocked }
      });
      state.profile = res.profile;
      if (input) input.value = '';
      showToast(`${t('popup.toastBlocked', 'Blocked')} ${destination}`);
      await refresh();
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  async function removeBlock(destination) {
    if (!state.domain || !state.profile) return;
    try {
      const blocked = (state.profile.blockedDestinationDomains || []).filter(x => x !== destination);
      const res = await send({
        type: 'patch-profile',
        domain: state.domain,
        patch: { blockedDestinationDomains: blocked }
      });
      state.profile = res.profile;
      showToast(`${t('scripts.remove', 'Removed')} ${destination}`);
      await refresh();
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  /* ============================================================
     EVENT WIRING
     ============================================================ */
  $('instantShieldBtn')?.addEventListener('click', toggleInstantShield);
  $('addBlock')?.addEventListener('click', addBlock);
  $('destination')?.addEventListener('keydown', e => { if (e.key === 'Enter') addBlock(); });

  $('refreshBtn')?.addEventListener('click', async () => {
    await refresh();
    showToast(t('popup.toastSynced', 'State synced.'));
  });

  $('scanDomainBtn')?.addEventListener('click', async () => {
    if (!state.domain) return;

    // 1) Allowlisted domains never need a scan — even with a valid
    //    API key. Say so explicitly rather than pretending we scanned.
    if (state.threatReport?.status === 'allowlisted') {
      showToast(t('popup.scanSkippedTrusted',
        'Domain is on the trusted allowlist — no scan needed.'));
      return;
    }

    // 2) Without an API key there is nothing to scan with. Tell the
    //    user right away instead of showing a fake "scan requested"
    //    and then a fake "analysis updated".
    if (!state.hasApiKey) {
      showToast(t('popup.errSetKey', 'Set VirusTotal API Key in Dashboard!'), 'error');
      return;
    }

    const btn = $('scanDomainBtn');
    if (btn) btn.disabled = true;
    showToast(t('popup.toastScanRequested', 'VirusTotal scan requested (rate-limit active)…'));
    try {
      const res = await send({ type: 'query-threat-intel', domain: state.domain, force: true });
      if (res?.ok) {
        await loadThreatIntel();
        if (res.report?.status === 'allowlisted') {
          showToast(t('popup.scanSkippedTrusted',
            'Domain is on the trusted allowlist — no scan needed.'));
        } else {
          showToast(t('popup.toastScanDone', 'VirusTotal analysis updated!'));
        }
      } else {
        showToast(res?.error || 'Scan failed', 'error');
      }
    } catch (err) {
      showToast(err.message === 'no-api-key'
        ? t('popup.errSetKey', 'Set VirusTotal API Key in Dashboard!')
        : err.message, 'error');
    } finally {
      if (btn) btn.disabled = false;
    }
  });
  $('resolver')?.addEventListener('click', async () => {
    const next = state.settings.resolverEnabled !== true;
    try {
      const res = await send({ type: 'patch-settings', patch: { resolverEnabled: next } });
      state.settings = res.settings;
      const on = state.settings.resolverEnabled === true;
      $('resolver').textContent = on ? 'ON' : 'OFF';
      $('resolver').className = `status-badge ${on ? 'on' : 'off'}`;
      showToast(`${t('setting.resolverEnabled', 'Safe Redirect Resolver')} ${on ? '✓' : '✕'}`);
    } catch (err) {
      showToast(err.message, 'error');
    }
  });

  $('autoArmToggle')?.addEventListener('click', async () => {
    const next = state.settings.autoArmFortress === false;
    const ok = await persistThreshold('autoArmFortress', next);
    if (ok) {
      renderAutoArmControls();
      renderAutoArmStatus();
      showToast(`Auto-Arm ${next ? 'ON' : 'OFF'}`);
    }
  });

  $('armThreshold')?.addEventListener('input', () => {
    const v = $('armThreshold').value;
    if ($('armThresholdValue')) $('armThresholdValue').textContent = `${v}%`;
  });
  $('armThreshold')?.addEventListener('change', async () => {
    const v = Math.max(1, Math.min(100, Number($('armThreshold').value) || 10));
    const ok = await persistThreshold('autoArmFortressThreshold', v);
    if (ok) setTimeout(renderAutoArmStatus, 900);
    if (ok) showToast(`${t('popup.armAt', 'Arm at')} → ${v}%`);
  });

  $('blockThreshold')?.addEventListener('input', () => {
    const v = $('blockThreshold').value;
    if ($('blockThresholdValue')) $('blockThresholdValue').textContent = `${v}%`;
  });
  $('blockThreshold')?.addEventListener('change', async () => {
    const v = Math.max(1, Math.min(100, Number($('blockThreshold').value) || 75));
    const ok = await persistThreshold('autoBlockThreshold', v);
    if (ok) setTimeout(renderAutoArmStatus, 900);
    if (ok) showToast(`${t('popup.blockAt', 'Block at')} → ${v}%`);
  });

  $('openDashboard')?.addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') }).catch(() => {});
  });

  /* ============================================================
     THEME
     ============================================================ */
  const POPUP_THEMES = [
    { id: 'amethyst', en: 'Royal Amethyst', fa: 'بنفش سلطنتی' },
    { id: 'dark', en: 'Midnight Obsidian', fa: 'شب سرمه‌ای' },
    { id: 'cyber-cyan', en: 'Arctic Sentinel', fa: 'فیروزه‌ای سایبری' },
    { id: 'emerald-ops', en: 'Emerald Ops', fa: 'زمردی امنیتی' },
    { id: 'solar-gold', en: 'Solar Gold', fa: 'سفید و زرد طلایی' },
    { id: 'light', en: 'Porcelain Light', fa: 'روشن کلاسیک' }
  ];
  $('theme')?.addEventListener('click', async () => {
    const current = (await chrome.storage.local.get('theme')).theme || 'dark';
    const idx = POPUP_THEMES.findIndex(t => t.id === current);
    const nextObj = POPUP_THEMES[(idx + 1) % POPUP_THEMES.length];
    await chrome.storage.local.set({ theme: nextObj.id });
    document.body.dataset.theme = nextObj.id;
    showToast(tx('Theme: ' + nextObj.en, 'تم: ' + nextObj.fa));
  });

  /* ============================================================
     BOOT
     ============================================================ */
  (async () => {
    // Load language before rendering anything.
    try {
      if (window.CorsairI18n) await CorsairI18n.load();
    } catch {}

    try {
      const { theme = 'dark' } = await chrome.storage.local.get('theme');
      document.body.dataset.theme = theme;
      const btn = $('theme');
      if (btn) btn.textContent = '🎨';
    } catch {}

    applyI18n(document);
    await refresh();
    initAiStudioPopup().catch(() => {});

    // BUG FIX: keep the popup in sync when settings are changed in the dashboard while it is open.
    try {
      chrome.storage.onChanged.addListener((changes, area) => {
        if (area === 'local' && changes.theme && changes.theme.newValue) { document.body.dataset.theme = changes.theme.newValue; }
        if (area !== 'local' || !changes.globalSettings) return;
        const next = changes.globalSettings.newValue;
        if (!next || typeof next !== 'object') return;
        state.settings = { ...state.settings, ...next };
        renderAutoArmControls();
        renderAutoArmStatus();
      });
    } catch {}

    // Re-apply i18n when the user switches language from the dashboard.
    try {
      chrome.storage.onChanged.addListener((changes, area) => {
        if (area !== 'local' || !changes.language) return;
        if (window.CorsairI18n) {
          CorsairI18n.set(changes.language.newValue).catch(() => {});
          setTimeout(() => { applyI18n(document); refresh(); }, 50);
        }
      });
    } catch {}
  })();

  /* ============ AI SCRIPT STUDIO ENTRY (v1.13.0) ============ */
  async function initAiStudioPopup() {
    const sel = $('aiPopupProvider');
    const siteEl = $('aiPopupSite');
    const promptEl = $('aiPopupPrompt');
    const genBtn = $('aiPopupGenerateBtn');
    const openBtn = $('aiOpenFullBtn');
    const ctxEl = $('aiPopupCtx');
    const statusEl = $('aiPopupStatus');
    if (!sel || !openBtn) return;

    let originTabId = null;
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const t = tabs && tabs[0];
      if (t && Number.isInteger(t.id)) {
        originTabId = t.id;
        let host = '';
        try { host = new URL(t.url || '').hostname; } catch {}
        if (siteEl) siteEl.textContent = host ? `Target: ${host}` : 'Standalone mode';
      }
    } catch {}

    try {
      const r = await send({ type: 'ai-providers-list' });
      if (r && r.ok && Array.isArray(r.profiles)) {
        sel.textContent = '';
        for (const p of r.profiles) {
          const opt = document.createElement('option');
          opt.value = p.id;
          opt.textContent = `[${(p.locality || 'local').toUpperCase()}] ${p.name}${p.model ? ' · ' + p.model : ''}`;
          sel.appendChild(opt);
        }
        if (r.defaultProfileId) sel.value = r.defaultProfileId;
      }
    } catch {}

    const launchStudio = async (withPrompt) => {
      if (statusEl) statusEl.textContent = 'Opening AI Script Studio…';
      await send({
        type: 'ai-open-studio',
        tabId: originTabId,
        providerId: sel.value || '',
        prompt: withPrompt ? (promptEl?.value || '').trim() : '',
        includeContext: Boolean(ctxEl?.checked),
        autoGen: Boolean(withPrompt && (promptEl?.value || '').trim())
      });
    };

    openBtn.addEventListener('click', () => launchStudio(false));
    if (genBtn) genBtn.addEventListener('click', () => launchStudio(true));
    if (promptEl) {
      promptEl.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') { e.preventDefault(); launchStudio(true); }
      });
    }
  }

})();

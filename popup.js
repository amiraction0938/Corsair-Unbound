(() => {
  'use strict';

  const $ = id => document.getElementById(id);
  const t = (k, fb) => (window.CorsairI18n ? CorsairI18n.t(k, fb) : (fb || k));

  const state = {
    domain: '',
    profile: null,
    diagnostics: null,
    settings: {},
    threatReport: null
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
  function renderAutoArmControls() {
    const toggle = $('autoArmToggle');
    const armSlider = $('armThreshold');
    const blockSlider = $('blockThreshold');
    const armVal = $('armThresholdValue');
    const blockVal = $('blockThresholdValue');

    const enabled = state.settings.autoArmFortress !== false;
    const armThreshold = Number.isFinite(state.settings.autoArmFortressThreshold)
      ? state.settings.autoArmFortressThreshold
      : 10;
    const blockThreshold = Number.isFinite(state.settings.autoBlockThreshold)
      ? state.settings.autoBlockThreshold
      : 70;

    if (toggle) {
      toggle.textContent = enabled ? 'ON' : 'OFF';
      toggle.className = `status-badge ${enabled ? 'on' : 'off'}`;
    }
    if (armSlider) armSlider.value = String(armThreshold);
    if (blockSlider) blockSlider.value = String(blockThreshold);
    if (armVal) armVal.textContent = `${armThreshold}%`;
    if (blockVal) blockVal.textContent = `${blockThreshold}%`;
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

      if (!state.domain) {
        state.profile = null;
        renderProfile();
        return;
      }

      const [profileResult, diagResult, settingsResult] = await Promise.all([
        send({ type: 'get-profile', domain: state.domain }),
        send({ type: 'get-diagnostics' }),
        send({ type: 'get-settings' })
      ]);

      state.profile = profileResult.profile;
      state.diagnostics = diagResult.diagnostics;
      state.settings = settingsResult.settings || {};

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
    const btn = $('scanDomainBtn');
    if (btn) btn.disabled = true;
    showToast(t('popup.toastScanRequested', 'VirusTotal scan requested (rate-limit active)…'));
    try {
      const res = await send({ type: 'query-threat-intel', domain: state.domain, force: true });
      if (res?.ok) {
        await loadThreatIntel();
        showToast(t('popup.toastScanDone', 'VirusTotal analysis updated!'));
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
    if (ok) showToast(`${t('popup.armAt', 'Arm at')} → ${v}%`);
  });

  $('blockThreshold')?.addEventListener('input', () => {
    const v = $('blockThreshold').value;
    if ($('blockThresholdValue')) $('blockThresholdValue').textContent = `${v}%`;
  });
  $('blockThreshold')?.addEventListener('change', async () => {
    const v = Math.max(1, Math.min(100, Number($('blockThreshold').value) || 70));
    const ok = await persistThreshold('autoBlockThreshold', v);
    if (ok) showToast(`${t('popup.blockAt', 'Block at')} → ${v}%`);
  });

  $('openDashboard')?.addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') }).catch(() => {});
  });

  /* ============================================================
     THEME
     ============================================================ */
  $('theme')?.addEventListener('click', async () => {
    const current = (await chrome.storage.local.get('theme')).theme || 'dark';
    const next = current === 'light' ? 'dark' : 'light';
    await chrome.storage.local.set({ theme: next });
    document.body.dataset.theme = next;
    const btn = $('theme');
    if (btn) btn.textContent = next === 'light' ? '🌙' : '☀';
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
      if (btn) btn.textContent = theme === 'light' ? '🌙' : '☀';
    } catch {}

    applyI18n(document);
    await refresh();

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
})();
(() => {
  'use strict';

  const $ = id => document.getElementById(id);
  const state = {
    domain: '',
    profile: null,
    diagnostics: null,
    settings: {}
  };

  /* ============================================================
     TOAST — 2s auto-dismiss
     ============================================================ */
  function showToast(message, type = 'success') {
    const container = $('toastContainer');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `<span>${type === 'success' ? '✓' : '⚠'}</span> <span>${message}</span>`;
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
     THREAT INTEL DISPLAY
     ============================================================ */
  async function loadThreatIntel() {
    if (!state.domain) return;
    const statusEl = $('threatStatus');
    const statsEl = $('threatStats');
    const fillEl = $('riskBarFill');
    const pctEl = $('riskPercentText');
    const flagsEl = $('vtEnginesDetected');
    const btn = $('scanDomainBtn');
    if (!statusEl || !statsEl) return;

    try {
      const res = await send({ type: 'get-threat-intel', domain: state.domain });
      let report = res?.report;

      // Auto-scan if enabled and no cache
      if (!report && state.settings.threatIntelEnabled && state.settings.threatIntelAutoScan) {
        statusEl.textContent = 'Scanning in background…';
        if (flagsEl) flagsEl.textContent = 'Rate-limited query queued…';
        try {
          const q = await send({ type: 'query-threat-intel', domain: state.domain, force: false });
          report = q?.report;
        } catch {}
      }

      if (!report) {
        statusEl.textContent = 'Not analyzed yet';
        statsEl.textContent = 'Click "Analyze" to query VirusTotal.';
        if (fillEl) fillEl.style.width = '0%';
        if (pctEl) pctEl.textContent = '0% Risk';
        if (flagsEl) flagsEl.textContent = 'No data available';
        if (btn) btn.disabled = false;
        return;
      }

      const risk = report.riskPercentage || 0;
      if (fillEl) fillEl.style.width = `${risk}%`;
      if (pctEl) pctEl.textContent = `${risk}% Risk`;

      if (report.status === 'allowlisted') {
        statusEl.innerHTML = '<span style="color: #34d399;">✓ Trusted Site (Whitelisted)</span>';
        statsEl.textContent = 'Verified high-reputation domain — no VT quota used.';
        if (flagsEl) flagsEl.innerHTML = '<span style="color: #34d399;">✓ On trusted allowlist</span>';
        if (fillEl) fillEl.style.background = '#10b981';
        if (pctEl) pctEl.style.color = '#10b981';
        if (btn) btn.disabled = true;
        return;
      }

      if (report.verdict === 'malicious') {
        const malCount = report.stats?.malicious || 0;
        statusEl.innerHTML = `<span style="color: #f87171; font-weight: bold;">⚠ Malicious (${malCount} engines)</span>`;
        if (fillEl) fillEl.style.background = '#f43f5e';
        if (pctEl) pctEl.style.color = '#f43f5e';
        if (flagsEl) {
          const list = report.flaggedEngines || [];
          const engines = list.slice(0, 6).join(', ') || 'Various engines';
          const more = list.length > 6 ? ` +${list.length - 6} more` : '';
          flagsEl.innerHTML = `<strong style="color: #f87171;">⚠ Flagged by:</strong> ${engines}${more}`;
        }
      } else if (report.verdict === 'suspicious') {
        const susCount = report.stats?.suspicious || 0;
        statusEl.innerHTML = `<span style="color: #fbbf24;">⚡ Suspicious (${susCount} engines)</span>`;
        if (fillEl) fillEl.style.background = '#f59e0b';
        if (pctEl) pctEl.style.color = '#fbbf24';
        if (flagsEl) {
          const engines = (report.flaggedEngines || []).slice(0, 6).join(', ') || 'Suspicious signals';
          flagsEl.innerHTML = `<strong style="color: #fbbf24;">⚡ Flagged by:</strong> ${engines}`;
        }
      } else if (report.verdict === 'clean') {
        statusEl.innerHTML = '<span style="color: #34d399;">✓ Clean</span>';
        if (fillEl) fillEl.style.background = '#10b981';
        if (pctEl) pctEl.style.color = '#34d399';
        if (flagsEl) flagsEl.innerHTML = '<span style="color: #34d399;">✓ 0 / 70+ Antivirus Engines flagged this site</span>';
      } else {
        statusEl.textContent = `Unknown (${report.status || 'unrated'})`;
        if (flagsEl) flagsEl.textContent = 'Not yet indexed by VirusTotal';
      }

      // Show heuristics if present
      if (Array.isArray(report.heuristicSignals) && report.heuristicSignals.length && flagsEl) {
        const heur = report.heuristicSignals
          .map(s => s.message || s.kind)
          .slice(0, 2)
          .join(' • ');
        flagsEl.innerHTML += `<div style="margin-top:4px; color:#fbbf24;">🧠 ${heur}</div>`;
      }

      const harmless = report.stats?.harmless || 0;
      const malicious = report.stats?.malicious || 0;
      const suspicious = report.stats?.suspicious || 0;
      statsEl.textContent = `Harmless: ${harmless} • Malicious: ${malicious} • Suspicious: ${suspicious}`;
      if (btn) btn.disabled = false;
    } catch {
      statusEl.textContent = 'Threat intelligence offline';
      if (btn) btn.disabled = false;
    }
  }

  /* ============================================================
     PROFILE RENDERING
     ============================================================ */
  function renderProfile() {
    const profile = state.profile;
    const isArmed = Boolean(profile?.protected === true && profile?.mode === 'fortress');
    const btn = $('instantShieldBtn');
    const btnText = $('shieldBtnText');

    $('profileState').textContent = isArmed
      ? '🛡️ Fortress Active: Popups blocked, navigation isolated'
      : 'Vulnerable: Default protection. Click to lock site';

    if (btn && btnText) {
      btn.disabled = !state.domain;
      if (isArmed) {
        btn.className = 'shield-btn armed';
        btnText.textContent = 'Disarm Fortress';
      } else {
        btn.className = 'shield-btn';
        btnText.textContent = 'Add & Arm Fortress';
      }
    }

    const list = $('blockedList');
    list.textContent = '';
    const blocked = Array.isArray(profile?.blockedDestinationDomains) ? profile.blockedDestinationDomains : [];
    if (blocked.length === 0) {
      list.innerHTML = '<div style="color: var(--text-muted); font-size: 11px; padding: 4px 0;">No blocked destinations.</div>';
      return;
    }

    for (const host of blocked) {
      const item = document.createElement('div');
      item.className = 'blocked-item';
      item.innerHTML = `<span>${host}</span><button data-host="${host}" title="Remove block">✕</button>`;
      item.querySelector('button').addEventListener('click', () => removeBlock(host));
      list.appendChild(item);
    }
  }

  /* ============================================================
     REFRESH
     ============================================================ */
  async function refresh() {
    try {
      state.domain = await activeDomain();
      $('domain').textContent = state.domain || 'Unsupported page';
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

      // Auto-trigger VT scan on non-whitelisted sites if enabled
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
      ? { protected: false, mode: 'standard' }
      : {
          protected: true,
          mode: 'fortress',
          autoContainRedirects: true,
          clickbaitGuard: true
        };
    try {
      const res = await send({ type: 'patch-profile', domain: state.domain, patch });
      state.profile = res.profile;
      renderProfile();
      showToast(isArmed ? 'Fortress Disarmed.' : '⚡ Domain added & Fortress Armed!');
      await refresh();
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  async function addBlock() {
    if (!state.domain) return;
    const destination = normalizeHost($('destination').value.trim());
    if (!destination) {
      showToast('Enter a valid destination domain', 'error');
      return;
    }
    try {
      const current = Array.isArray(state.profile?.blockedDestinationDomains) ? state.profile.blockedDestinationDomains : [];
      const blocked = [...new Set([...current, destination])].slice(0, 1000);
      const res = await send({
        type: 'patch-profile',
        domain: state.domain,
        patch: { protected: true, mode: 'fortress', blockedDestinationDomains: blocked }
      });
      state.profile = res.profile;
      $('destination').value = '';
      showToast(`Blocked ${destination}`);
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
      showToast(`Removed ${destination}`);
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
    showToast('State synced.');
  });

  $('scanDomainBtn')?.addEventListener('click', async () => {
    if (!state.domain) return;
    const btn = $('scanDomainBtn');
    btn.disabled = true;
    showToast('VirusTotal scan requested (Rate-limit active)…');
    try {
      const res = await send({ type: 'query-threat-intel', domain: state.domain, force: true });
      if (res?.ok) {
        await loadThreatIntel();
        showToast('VirusTotal analysis updated!');
      }
    } catch (err) {
      showToast(err.message === 'no-api-key' ? 'Set VirusTotal API Key in Dashboard!' : err.message, 'error');
    } finally {
      btn.disabled = false;
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
      showToast(`Redirect Resolver ${on ? 'Enabled' : 'Disabled'}`);
    } catch (err) {
      showToast(err.message, 'error');
    }
  });

  $('openDashboard')?.addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') }).catch(() => {});
  });

  /* ============================================================
     THEME TOGGLE
     ============================================================ */
  $('theme')?.addEventListener('click', async () => {
    const current = (await chrome.storage.local.get('theme')).theme || 'dark';
    const next = current === 'light' ? 'dark' : 'light';
    await chrome.storage.local.set({ theme: next });
    document.body.dataset.theme = next;
    const btn = $('theme');
    if (btn) btn.textContent = next === 'light' ? '🌙' : '☀';
  });

  // Load initial theme
  chrome.storage.local.get('theme').then(({ theme = 'dark' }) => {
    document.body.dataset.theme = theme;
    const btn = $('theme');
    if (btn) btn.textContent = theme === 'light' ? '🌙' : '☀';
  }).catch(() => {});

  /* ============================================================
     BOOT
     ============================================================ */
  refresh();
})();
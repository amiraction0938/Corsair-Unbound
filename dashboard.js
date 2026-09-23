function send(m) {
  return new Promise(resolve => {
    try { chrome.runtime.sendMessage(m, resolve); }
    catch (e) { resolve({ ok: false, error: String(e?.message || e) }); }
  });
}

let profiles = {}, events = [], evidence = [], network = [], settings = {};
let safeDomains = [], userTrusted = [], customScripts = [];
let safeDomainSearch = '';
let safeDomainSelected = new Set();
let editingScript = null;

const $ = id => document.getElementById(id);
const safeOn = (id, event, handler) => { const el = $(id); if (el) el.addEventListener(event, handler); };
const t = (k, fb) => (window.CorsairI18n ? CorsairI18n.t(k, fb) : (fb || k));

/* ============================================================
   TOAST — 3s auto-dismiss
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
    toast.style.transform = 'translateX(30px)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

function downloadJSON(filename, data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = filename; a.style.display = 'none';
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function humanTime(ts) {
  const n = Number(ts);
  return new Date(Number.isFinite(n) ? n : Date.now()).toLocaleString();
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  })[c]);
}

function formatBytes(b) {
  const n = Number(b) || 0;
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / (1024 * 1024)).toFixed(2) + ' MB';
}

/* ============================================================
   THEME
   ============================================================ */
function applyTheme(theme) {
  document.body.dataset.theme = theme === 'light' ? 'light' : 'dark';
  const btn = $('theme');
  if (btn) btn.textContent = theme === 'light' ? '🌙' : '☀';
}

async function initTheme() {
  try {
    const r = await chrome.storage.local.get('theme');
    applyTheme(r.theme || 'dark');
  } catch { applyTheme('dark'); }
}

safeOn('theme', 'click', async () => {
  const current = (await chrome.storage.local.get('theme')).theme || 'dark';
  const next = current === 'light' ? 'dark' : 'light';
  await chrome.storage.local.set({ theme: next });
  applyTheme(next);
});

/* ============================================================
   LANGUAGE
   ============================================================ */
async function initLanguage() {
  if (!window.CorsairI18n) return;
  await CorsairI18n.load();
  buildLangMenu();
  CorsairI18n.apply(document);
  updateCurrentLangDisplay();
}

function updateCurrentLangDisplay() {
  if (!window.CorsairI18n) return;
  const cur = CorsairI18n.getCurrent();
  const lang = CorsairI18n.getLanguage(cur);
  const flagEl = $('currentFlag');
  const labelEl = $('currentLang');
  if (flagEl) flagEl.textContent = lang.flag;
  if (labelEl) labelEl.textContent = lang.code.toUpperCase();
  document.querySelectorAll('#langMenu button').forEach(b => {
    b.classList.toggle('active', b.dataset.lang === cur);
  });
}

function buildLangMenu() {
  const menu = $('langMenu');
  if (!menu || !window.CorsairI18n) return;
  menu.innerHTML = '';
  for (const lang of CorsairI18n.getLanguages()) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.dataset.lang = lang.code;
    btn.innerHTML = `<span>${lang.flag}</span><span>${escapeHtml(lang.label)}</span>`;
    btn.addEventListener('click', async () => {
      await CorsairI18n.set(lang.code);
      CorsairI18n.apply(document);
      updateCurrentLangDisplay();
      menu.classList.remove('open');
      renderCustomScripts();
      renderSafeDomains();
      renderTrustedList();
      renderSettings();
    });
    menu.appendChild(btn);
  }
}

safeOn('langToggle', 'click', (e) => {
  e.stopPropagation();
  const menu = $('langMenu');
  if (menu) menu.classList.toggle('open');
});

document.addEventListener('click', (e) => {
  const menu = $('langMenu');
  if (!menu) return;
  if (!menu.classList.contains('open')) return;
  if (e.target.closest && e.target.closest('#langSelector')) return;
  menu.classList.remove('open');
});

/* ============================================================
   PROFILES
   ============================================================ */
function renderProfiles() {
  const search = $('domainSearch'), box = $('profiles'); if (!box) return;
  const q = (search?.value || '').trim().toLowerCase(); box.innerHTML = '';
  const entries = Object.entries(profiles).filter(([d]) => !q || d.includes(q)).sort(([a], [b]) => a.localeCompare(b));

  if (!entries.length) {
    box.innerHTML = '<div class="empty">—</div>';
    return;
  }

  for (const [d, p] of entries) {
    const row = document.createElement('div'); row.className = 'profile';
    const left = document.createElement('div');
    const title = document.createElement('strong'); title.textContent = d;
    const sub = document.createElement('div'); sub.className = 'muted';
    sub.textContent = `${String(p.mode || 'custom').toUpperCase()} • blocked destinations: ${p.blockedDestinationDomains?.length || 0}`;
    left.append(title, sub);

    const right = document.createElement('div'); right.className = 'profile-actions';
    const delBtn = document.createElement('button');
    delBtn.className = 'btn-delete-profile';
    delBtn.textContent = t('scripts.remove', 'Remove');
    delBtn.addEventListener('click', async () => {
      const res = await send({ type: 'remove-profile', domain: d });
      if (res?.ok) { showToast(`Removed ${d}`); await refresh(); }
      else showToast(res?.error || 'Failed', 'error');
    });

    right.appendChild(delBtn);
    row.append(left, right);
    box.appendChild(row);
  }
}

/* ============================================================
   CUSTOM SCRIPTS
   ============================================================ */
function renderCustomScripts() {
  const box = $('scriptList');
  if (!box) return;
  box.innerHTML = '';

  if (!customScripts.length) {
    box.innerHTML = `<div class="empty">${escapeHtml(t('scripts.empty', 'No custom scripts yet. Add a domain above to begin.'))}</div>`;
    return;
  }

  for (const item of customScripts) {
    const host = item.host;
    const enabled = item.enabled !== false;
    const codePreview = (item.code || '').split('\n').slice(0, 3).join('\n') || '(empty)';

    const row = document.createElement('div');
    row.className = 'script-item' + (enabled ? '' : ' disabled');

    const head = document.createElement('div');
    head.className = 'script-item-head';

    const left = document.createElement('div');
    const title = document.createElement('div');
    title.className = 'script-host';
    title.textContent = host;
    const meta = document.createElement('div');
    meta.className = 'script-meta';
    const lines = (item.code || '').split('\n').length;
    meta.textContent = `${lines} ${t('scripts.lines', 'lines')} • ${enabled ? '✓' : '✕'} ${t('scripts.enable', 'Enabled')}`;
    left.append(title, meta);

    const actions = document.createElement('div');
    actions.className = 'script-actions';

    const toggleLabel = document.createElement('label');
    toggleLabel.className = 'script-toggle';
    const toggle = document.createElement('input');
    toggle.type = 'checkbox';
    toggle.checked = enabled;
    toggle.addEventListener('change', async () => {
      const res = await send({ type: 'toggle-custom-script', host, enabled: toggle.checked });
      if (res?.ok) {
        item.enabled = toggle.checked;
        row.classList.toggle('disabled', !toggle.checked);
        showToast(`${host}: ${toggle.checked ? 'enabled' : 'disabled'}`);
      } else {
        toggle.checked = !toggle.checked;
        showToast(res?.error || 'Failed', 'error');
      }
    });
    const toggleTxt = document.createElement('span');
    toggleTxt.textContent = t('scripts.enable', 'Enabled');
    toggleLabel.append(toggle, toggleTxt);

    const editBtn = document.createElement('button');
    editBtn.className = 'btn-script-edit';
    editBtn.textContent = t('scripts.edit', 'Edit');
    editBtn.addEventListener('click', () => openEditor(host, item.code || ''));

    const delBtn = document.createElement('button');
    delBtn.className = 'btn-script-remove';
    delBtn.textContent = t('scripts.remove', 'Remove');
    delBtn.addEventListener('click', async () => {
      if (!confirm(t('scripts.confirmRemove', 'Remove this script? This cannot be undone.'))) return;
      const res = await send({ type: 'remove-custom-script', host });
      if (res?.ok) { showToast(`Removed script for ${host}`); await refresh(); }
      else showToast(res?.error || 'Failed', 'error');
    });

    actions.append(toggleLabel, editBtn, delBtn);
    head.append(left, actions);
    row.appendChild(head);

    const preview = document.createElement('div');
    preview.className = 'script-preview';
    preview.textContent = codePreview;
    preview.addEventListener('click', () => openEditor(host, item.code || ''));
    row.appendChild(preview);

    box.appendChild(row);
  }
}

function addCustomScript() {
  const input = $('scriptDomain');
  if (!input) return;
  const raw = (input.value || '').trim();
  if (!raw) { showToast('Enter a domain first', 'error'); return; }

  let host = raw.toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/:\d+$/, '')
    .replace(/^www\./, '');
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(host)) {
    showToast('Invalid domain format', 'error');
    return;
  }

  input.value = '';
  openEditor(host, '');
}

/* ============================================================
   CODE EDITOR
   ============================================================ */
function openEditor(host, code) {
  editingScript = { host, code: code || '', originalCode: code || '' };
  const modal = $('editorModal');
  if (!modal) return;

  const hostEl = $('editorHost');
  const fileEl = $('editorFilename');
  const ta = $('editorCode');
  const tab = $('editorTab');

  if (hostEl) hostEl.textContent = host;
  if (fileEl) fileEl.textContent = host.replace(/[^a-z0-9.-]/gi, '_') + '.js';
  if (ta) { ta.value = code || ''; ta.focus(); }
  if (tab) tab.classList.remove('dirty');

  updateLineNumbers();
  modal.hidden = false;
  setTimeout(() => ta && ta.focus(), 50);
}

function closeEditor() {
  const modal = $('editorModal');
  if (modal) modal.hidden = true;
  editingScript = null;
}

async function saveEditor() {
  if (!editingScript) return;
  const ta = $('editorCode');
  const code = ta ? ta.value : '';

  const res = await send({
    type: 'upsert-custom-script',
    host: editingScript.host,
    code,
    enabled: true
  });

  if (res?.ok) {
    showToast(`Saved script for ${editingScript.host}`);
    closeEditor();
    await refresh();
  } else {
    showToast(res?.error || 'Failed to save', 'error');
  }
}

function updateLineNumbers() {
  const ta = $('editorCode');
  const gutter = $('editorGutter');
  const linesEl = $('editorLines');
  if (!ta || !gutter) return;

  const lines = ta.value.split('\n').length;
  const arr = [];
  for (let i = 1; i <= lines; i++) arr.push(String(i));
  gutter.textContent = arr.join('\n');
  gutter.scrollTop = ta.scrollTop;

  if (linesEl) {
    const dict = window.CorsairI18n ? CorsairI18n.t('scripts.lines', 'lines') : 'lines';
    linesEl.textContent = `${lines} ${dict}`;
  }
}

safeOn('editorCode', 'keydown', (e) => {
  const ta = $('editorCode');
  if (!ta) return;
  if (e.key === 'Tab') {
    e.preventDefault();
    const start = ta.selectionStart;
    const end = ta.selectionEnd;
    const val = ta.value;
    ta.value = val.substring(0, start) + '  ' + val.substring(end);
    ta.selectionStart = ta.selectionEnd = start + 2;
    updateLineNumbers();
  }
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') {
    e.preventDefault();
    saveEditor();
  }
  if (e.key === 'Escape') {
    e.preventDefault();
    closeEditor();
  }
});

safeOn('editorCode', 'input', () => {
  updateLineNumbers();
  const tab = $('editorTab');
  if (tab && editingScript && $('editorCode').value !== editingScript.originalCode) {
    tab.classList.add('dirty');
  }
});

safeOn('editorCode', 'scroll', () => {
  const ta = $('editorCode');
  const gutter = $('editorGutter');
  if (ta && gutter) gutter.scrollTop = ta.scrollTop;
});

safeOn('editorSave', 'click', saveEditor);
safeOn('editorClose', 'click', closeEditor);

safeOn('editorModal', 'click', (e) => {
  if (e.target && e.target.id === 'editorModal') closeEditor();
});

/* ============================================================
   SAFE SCANNED DOMAINS
   ============================================================ */
function renderSafeDomains() {
  const box = $('safeDomainsList');
  if (!box) return;
  box.innerHTML = '';

  const q = safeDomainSearch.trim().toLowerCase();
  const filtered = safeDomains.filter(d => !q || d.host.includes(q));

  if (!safeDomains.length) {
    box.innerHTML = `<div class="empty">${escapeHtml(t('safe.empty', 'No safe-scanned domains yet.'))}</div>`;
    updateSafeSelectedCount();
    return;
  }
  if (!filtered.length) {
    box.innerHTML = '<div class="empty">—</div>';
    updateSafeSelectedCount();
    return;
  }

  for (const item of filtered) {
    const host = item.host || '?';
    const stats = item.stats || {};
    const risk = Number(item.riskPercentage) || 0;
    const scannedAt = item.lastChecked ? humanTime(item.lastChecked) : '—';

    const row = document.createElement('div');
    row.className = 'safe-domain-item';
    if (safeDomainSelected.has(host)) row.classList.add('selected');

    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.className = 'safe-domain-cb';
    cb.checked = safeDomainSelected.has(host);
    cb.addEventListener('change', () => {
      if (cb.checked) safeDomainSelected.add(host);
      else safeDomainSelected.delete(host);
      row.classList.toggle('selected', cb.checked);
      updateSafeSelectedCount();
    });

    const left = document.createElement('div');
    left.className = 'safe-domain-left';
    const title = document.createElement('strong');
    title.textContent = host;
    title.className = 'safe-domain-host';
    const sub = document.createElement('div');
    sub.className = 'safe-domain-meta';
    sub.textContent = `Clean • ${risk}% risk • ${stats.harmless || 0}/${stats.malicious || 0}/${stats.suspicious || 0} • ${scannedAt}`;
    left.append(title, sub);

    const right = document.createElement('div');
    right.className = 'safe-domain-actions';
    const badge = document.createElement('span');
    badge.className = 'safe-domain-badge';
    badge.textContent = '✓ SAFE';
    const delBtn = document.createElement('button');
    delBtn.className = 'btn-remove-safe';
    delBtn.textContent = t('scripts.remove', 'Remove');
    delBtn.addEventListener('click', async () => {
      const res = await send({ type: 'remove-safe-scanned-domain', domain: host });
      if (res?.ok) { safeDomainSelected.delete(host); showToast(`Removed ${host}`); await refresh(); }
      else showToast(res?.error || 'Failed', 'error');
    });
    right.append(badge, delBtn);
    row.append(cb, left, right);
    box.appendChild(row);
  }

  updateSafeSelectedCount();
}

function updateSafeSelectedCount() {
  const el = $('safeSelectedCount');
  if (el) el.innerHTML = `${safeDomainSelected.size} <span data-i18n="safe.selected">${escapeHtml(t('safe.selected', 'selected'))}</span>`;
  const selectAll = $('safeSelectAll');
  if (selectAll) {
    const q = safeDomainSearch.trim().toLowerCase();
    const visible = safeDomains.filter(d => !q || d.host.includes(q));
    selectAll.checked = visible.length > 0 && visible.every(d => safeDomainSelected.has(d.host));
    selectAll.indeterminate = visible.length > 0 && !selectAll.checked && visible.some(d => safeDomainSelected.has(d.host));
  }
}

/* ============================================================
   USER TRUSTED DOMAINS
   ============================================================ */
function renderTrustedList() {
  const box = $('trustedList');
  if (!box) return;
  box.innerHTML = '';

  if (!userTrusted.length) {
    box.innerHTML = `<div class="empty">${escapeHtml(t('trusted.empty', 'No trusted domains yet.'))}</div>`;
    return;
  }

  for (const host of userTrusted) {
    const row = document.createElement('div');
    row.className = 'safe-domain-item';

    const left = document.createElement('div');
    left.className = 'safe-domain-left';
    const title = document.createElement('strong');
    title.textContent = host;
    title.className = 'safe-domain-host';
    left.appendChild(title);

    const right = document.createElement('div');
    right.className = 'safe-domain-actions';
    const badge = document.createElement('span');
    badge.className = 'safe-domain-badge';
    badge.style.background = 'rgba(59,130,246,0.15)';
    badge.style.color = '#60a5fa';
    badge.style.borderColor = 'rgba(59,130,246,0.3)';
    badge.textContent = '🛡️ TRUSTED';
    const delBtn = document.createElement('button');
    delBtn.className = 'btn-remove-safe';
    delBtn.textContent = t('scripts.remove', 'Untrust');
    delBtn.addEventListener('click', async () => {
      const res = await send({ type: 'untrust-domain', host });
      if (res?.ok) { showToast(`Untrusted ${host}`); await refresh(); }
      else showToast(res?.error || 'Failed', 'error');
    });
    right.append(badge, delBtn);
    row.append(left, right);
    box.appendChild(row);
  }
}

/* ============================================================
   STORAGE USAGE
   ============================================================ */
async function renderStorageStats() {
  try {
    const r = await send({ type: 'get-storage-usage' });
    if (!r?.ok || !r.usage) return;
    const u = r.usage;
    const set = (id, v) => { const el = $(id); if (el) el.textContent = String(v); };
    set('storageTotalBytes', formatBytes(u.totalBytes || 0));
    set('storageProfiles', u.profileCount || 0);
    set('storageTrusted', u.userTrustedCount || 0);
    set('storageSafeScanned', u.safeScannedCount || 0);
    set('storageCacheCount', u.threatCacheCount || 0);
  } catch {}
}

/* ============================================================
   SETTINGS (i18n-aware)
   ============================================================ */
function renderSettings() {
  const box = $('settingsForm'); if (!box) return; box.innerHTML = '';

  const bools = [
    ['resolverEnabled',            'setting.resolverEnabled'],
    ['notifications',              'setting.notifications'],
    ['siteVerdictBanner',          'setting.siteVerdictBanner'],
    ['notifyOnSafeSites',          'setting.notifyOnSafeSites'],
    ['logEvents',                  'setting.logEvents'],
    ['observationEnabled',         'setting.observationEnabled'],
    ['verificationEnabled',        'setting.verificationEnabled'],
    ['enforceSuspiciousRedirects', 'setting.enforceSuspiciousRedirects'],
    ['threatIntelEnabled',         'setting.threatIntelEnabled'],
    ['threatIntelAutoScan',        'setting.threatIntelAutoScan'],
    ['downloadGuard',              'setting.downloadGuard']
  ];

  for (const [key, i18nKey] of bools) {
    const l = document.createElement('label'); l.className = 'setting';
    const input = document.createElement('input'); input.type = 'checkbox'; input.dataset.key = key;
    input.checked = settings[key] !== false;
    const span = document.createElement('span'); span.textContent = t(i18nKey, key);
    l.append(input, span);
    box.appendChild(l);
  }

  const wrap = document.createElement('label'); wrap.className = 'setting';
  const span = document.createElement('span'); span.textContent = t('setting.maxRedirectHops', 'Global max redirect hops');
  const num = document.createElement('input'); num.type = 'number'; num.min = '1'; num.max = '32'; num.step = '1';
  num.value = settings.maxRedirectHops || 8; num.dataset.key = 'maxRedirectHops';
  wrap.append(span, num); box.appendChild(wrap);

  const apiBox = document.createElement('div');
  apiBox.className = 'api-box';
  apiBox.innerHTML = `
    <div style="display: flex; justify-content: space-between; align-items: center;">
      <strong style="font-size: 13px;">${escapeHtml(t('vt.title', 'VirusTotal API Key (BYOK)'))}</strong>
      <a href="https://www.virustotal.com/gui/my-apikey" target="_blank" class="api-link">${escapeHtml(t('vt.getKey', '🔑 Get Free API Key ↗'))}</a>
    </div>
    <div class="api-row">
      <input type="password" data-key="vtApiKey" value="${escapeHtml(settings.vtApiKey || '')}" placeholder="${escapeHtml(t('vt.placeholder', 'Paste your 64-char VirusTotal API Key'))}">
    </div>
    <small style="color: var(--text-muted); font-size: 11px;">${escapeHtml(t('vt.freeKeys', 'Free keys: 4 requests/min, 500 requests/day. All queries cached locally.'))}</small>
  `;
  box.appendChild(apiBox);

  const vtHint = document.createElement('div');
  vtHint.className = 'vt-hint-box';
  vtHint.innerHTML = `
    <strong>${escapeHtml(t('vt.hintTitle', '🔑 VirusTotal API Key:'))}</strong>
    <ol>
      <li>${escapeHtml(t('vt.step1', 'Free account:'))} <a href="https://www.virustotal.com/gui/join-us" target="_blank" rel="noopener">virustotal.com/gui/join-us</a></li>
      <li>${escapeHtml(t('vt.step2', 'API Key:'))} <a href="https://www.virustotal.com/gui/my-apikey" target="_blank" rel="noopener">virustotal.com/gui/my-apikey ↗</a></li>
      <li>${escapeHtml(t('vt.step3', 'Paste the 64-char key above, enable Threat Intelligence + Auto-Scan'))}</li>
    </ol>
    <div style="margin-top:8px; font-size:11px; color:#94a3b8;">
      <button id="syncWhitelistInline" style="margin-left:0; padding:3px 8px; font-size:11px;">${escapeHtml(t('vt.refreshWhitelist', '🔄 Refresh Whitelist'))}</button>
      <span id="whitelistStatsInline" style="margin-left:8px;">loading…</span>
    </div>
  `;
  box.appendChild(vtHint);

  (async () => {
    try {
      const r = await send({ type: 'get-allowlist-stats' });
      const el = $('whitelistStatsInline');
      if (r?.ok && r.stats && el) {
        el.textContent = `✓ ${r.stats.builtin + r.stats.remote + (r.stats.userTrusted || 0)} domains`;
        el.style.color = '#34d399';
      }
    } catch {}
  })();
}

function readSettingsForm() {
  const patch = {};
  document.querySelectorAll('#settingsForm [data-key]').forEach(el => {
    if (el.type === 'checkbox') patch[el.dataset.key] = el.checked;
    else if (el.type === 'number') patch[el.dataset.key] = Math.max(1, Math.min(32, Number(el.value) || 8));
    else patch[el.dataset.key] = el.value.trim();
  });
  return patch;
}

/* ============================================================
   STAT CARDS
   ============================================================ */
function renderNewStats() {
  const set = (id, v) => { const el = $(id); if (el) el.textContent = String(v); };
  set('statEvents', events.length);
  const protectionTypes = ['blocked', 'contained', 'popup_blocked', 'navigation_contained',
                            'navigation_blocked', 'new_tab_blocked', 'download_blocked'];
  const protectionCount = events.filter(e =>
    protectionTypes.some(t2 => String(e.type || '').includes(t2))
  ).length;
  set('statProtection', protectionCount);
  const blacklist = new Set();
  for (const p of Object.values(profiles || {})) {
    if (Array.isArray(p?.blockedDestinationDomains)) {
      for (const d of p.blockedDestinationDomains) blacklist.add(d);
    }
  }
  set('statBlacklist', blacklist.size);
  set('statGroups', Object.keys(profiles || {}).length);
}

/* ============================================================
   EVENTS / EVIDENCE / NETWORK / RISK
   ============================================================ */
function renderEvents() {
  const box = $('activity'); if (!box) return; box.innerHTML = '';
  if (!events.length) { box.innerHTML = '<div class="empty">—</div>'; return; }
  for (const e of events.slice(0, 200)) {
    const row = document.createElement('div'); row.className = 'event';
    const main = document.createElement('div'); main.className = 'event-main';
    const t2 = document.createElement('div'); t2.className = 'event-type'; t2.textContent = e.type || 'event';
    const m = document.createElement('div'); m.className = 'event-meta';
    m.textContent = `${humanTime(e.timestamp)} • ${e.domain || e.source || ''}${e.destination ? ` → ${e.destination}` : ''}${e.reason ? ` • ${e.reason}` : ''}`;
    main.append(t2, m);
    const sev = document.createElement('div'); sev.className = e.severity || 'low'; sev.textContent = String(e.severity || 'low').toUpperCase();
    row.append(main, sev); box.appendChild(row);
  }
}

function renderEvidence() {
  const box = $('evidence'); if (!box) return; box.innerHTML = '';
  if (!evidence.length) { box.innerHTML = '<div class="empty">—</div>'; return; }
  for (const e of evidence.slice(0, 200)) {
    const row = document.createElement('div'); row.className = 'event';
    const main = document.createElement('div'); main.className = 'event-main';
    const t2 = document.createElement('div'); t2.className = 'event-type'; t2.textContent = e.kind || 'observation';
    const m = document.createElement('div'); m.className = 'event-meta';
    m.textContent = `${humanTime(e.timestamp)} • ${e.origin || ''} • tab ${e.tabId ?? '-'}`;
    main.append(t2, m); row.append(main); box.appendChild(row);
  }
}

function renderNetwork() {
  const box = $('network'); if (!box) return; box.innerHTML = '';
  if (!network.length) { box.innerHTML = '<div class="empty">—</div>'; return; }
  for (const r of network.slice(0, 100)) {
    const row = document.createElement('div'); row.className = 'event';
    const main = document.createElement('div'); main.className = 'event-main';
    const t2 = document.createElement('div'); t2.className = 'event-type'; t2.textContent = r.resourceType || r.type || 'resource';
    const m = document.createElement('div'); m.className = 'event-meta';
    m.textContent = `${humanTime(r.timestamp)} • ${r.host || ''} • ${r.url || ''}`;
    main.append(t2, m); row.append(main); box.appendChild(row);
  }
}

function behaviorDomains() {
  const set = new Set(Object.keys(profiles));
  for (const e of events) { if (e.domain) set.add(e.domain); if (e.source) set.add(e.source); if (e.destination) set.add(e.destination); }
  return [...set].filter(Boolean).sort().slice(0, 60);
}

function renderRisk() {
  const box = $('riskBoard'); if (!box) return; box.innerHTML = '';
  const domains = behaviorDomains();
  if (!domains.length) { box.innerHTML = '<div class="empty">—</div>'; return; }
  for (const d of domains) {
    const row = document.createElement('div'); row.className = 'event';
    const main = document.createElement('div'); main.className = 'event-main';
    const t2 = document.createElement('div'); t2.className = 'event-type'; t2.textContent = d;
    const m = document.createElement('div'); m.className = 'event-meta'; m.textContent = 'Analyzing…';
    main.append(t2, m); row.append(main); box.appendChild(row);
    send({ type: 'assess-domain-risk', domain: d }).then(r => {
      if (r?.assessment) {
        const a = r.assessment;
        m.textContent = `${String(a.verdict || 'unknown').toUpperCase()} • Risk ${a.risk}/100 • ${Math.round((a.confidence || 0) * 100)}%${a.reasons?.length ? ' • ' + a.reasons.join(', ') : ''}`;
      } else m.textContent = '—';
    });
  }
}

/* ============================================================
   ANALYZER
   ============================================================ */
function renderAnalyzerResult(data) {
  const box = $('analyzerResult');
  if (!box) return;
  box.innerHTML = '';
  if (!data) { box.innerHTML = `<div class="empty">${escapeHtml(t('analyzer.placeholder', 'Enter a domain.'))}</div>`; return; }
  if (data.error) { box.innerHTML = `<div class="empty">⚠ ${escapeHtml(data.error)}</div>`; return; }

  const report = data.report || data;
  const host = report.host || data.host || '?';
  const verdict = String(report.verdict || report.status || 'unknown').toLowerCase();
  const risk = Number(report.riskPercentage) || 0;
  const flagged = Array.isArray(report.flaggedEngines) ? report.flaggedEngines : [];
  const stats = report.stats || {};

  const wrap = document.createElement('div');
  const vRow = document.createElement('div');
  vRow.className = 'analyzer-verdict';

  const badge = document.createElement('span');
  badge.className = `analyzer-badge ${verdict}`;
  const label = verdict === 'allowlisted' ? '✓ TRUSTED'
    : verdict === 'clean' ? '✓ CLEAN'
    : verdict === 'suspicious' ? '⚡ SUSPICIOUS'
    : verdict === 'malicious' ? '⚠ MALICIOUS'
    : '? UNKNOWN';
  badge.textContent = label;
  vRow.appendChild(badge);

  const bar = document.createElement('div');
  bar.className = 'analyzer-risk-bar';
  const fill = document.createElement('div');
  fill.className = 'analyzer-risk-fill';
  fill.style.width = `${risk}%`;
  fill.style.background = verdict === 'malicious' ? '#f43f5e'
    : verdict === 'suspicious' ? '#f59e0b' : '#10b981';
  bar.appendChild(fill);
  vRow.appendChild(bar);

  const pct = document.createElement('span');
  pct.style.fontFamily = "'JetBrains Mono', monospace";
  pct.style.fontSize = '14px';
  pct.style.fontWeight = '700';
  pct.style.color = verdict === 'malicious' ? '#f87171' : verdict === 'suspicious' ? '#fbbf24' : '#34d399';
  pct.textContent = `${risk}%`;
  vRow.appendChild(pct);
  wrap.appendChild(vRow);

  const meta = document.createElement('div');
  meta.className = 'analyzer-meta';
  const metaItems = [
    ['Domain', host], ['Status', report.status || '—'],
    ['Harmless', String(stats.harmless ?? '—')],
    ['Malicious', String(stats.malicious ?? '—')],
    ['Suspicious', String(stats.suspicious ?? '—')],
    ['Undetected', String(stats.undetected ?? '—')],
    ['Reputation', String(report.reputation ?? '—')],
    ['Checked', report.lastChecked ? humanTime(report.lastChecked) : '—']
  ];
  for (const [k, v] of metaItems) {
    const item = document.createElement('div');
    item.className = 'analyzer-meta-item';
    const s1 = document.createElement('strong'); s1.textContent = k;
    const s2 = document.createElement('span'); s2.textContent = v;
    item.append(s1, s2);
    meta.appendChild(item);
  }
  wrap.appendChild(meta);

  if (flagged.length) {
    const eng = document.createElement('div');
    eng.className = 'analyzer-engines';
    eng.innerHTML = `<b>Flagged by ${flagged.length} engine(s):</b> ${escapeHtml(flagged.join(', '))}`;
    wrap.appendChild(eng);
  } else if (verdict === 'clean' || verdict === 'allowlisted') {
    const eng = document.createElement('div');
    eng.className = 'analyzer-engines';
    eng.innerHTML = `<span style="color:#34d399;">✓ 0 / 70+ engines flagged this domain</span>`;
    wrap.appendChild(eng);
  }

  if (Array.isArray(report.heuristicSignals) && report.heuristicSignals.length) {
    const heur = document.createElement('div');
    heur.className = 'analyzer-engines';
    heur.style.borderLeft = '3px solid #fbbf24';
    heur.innerHTML = `<strong style="color:#fbbf24;">🧠 Heuristics:</strong> ${escapeHtml(report.heuristicSignals.map(s => s.message || s.kind).join(' • '))}`;
    wrap.appendChild(heur);
  }

  box.appendChild(wrap);
}

async function runAnalyzer(force = false) {
  const box = $('analyzerResult');
  const input = $('analyzerInput');
  if (!input || !box) return;
  const raw = (input.value || '').trim();
  if (!raw) { box.innerHTML = `<div class="empty">${escapeHtml(t('analyzer.placeholder', 'Enter a domain.'))}</div>`; return; }

  let host = raw.toLowerCase()
    .replace(/^https?:\/\//, '').replace(/\/.*$/, '')
    .replace(/:\d+$/, '').replace(/^www\./, '');
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(host)) { box.innerHTML = '<div class="empty">Invalid format</div>'; return; }

  box.innerHTML = '<div class="empty">Analyzing…</div>';

  try {
    if (force) {
      const r = await send({ type: 'query-threat-intel', domain: host, force: true });
      if (!r?.ok) throw new Error(r?.error || 'query-failed');
      renderAnalyzerResult({ report: r.report });
    } else {
      const cached = await send({ type: 'get-threat-intel', domain: host });
      if (cached?.report) renderAnalyzerResult({ report: cached.report });
      else {
        const r = await send({ type: 'query-threat-intel', domain: host, force: false });
        if (!r?.ok) throw new Error(r?.error || 'query-failed');
        renderAnalyzerResult({ report: r.report });
      }
    }
    refresh().catch(() => {});
  } catch (err) {
    renderAnalyzerResult({ error: err.message });
  }
}

/* ============================================================
   REFRESH
   ============================================================ */
async function loadCurrentTabId() {
  const input = $('networkTabId'); if (!input) return;
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const id = tabs?.[0]?.id;
    if (Number.isInteger(id)) input.value = String(id);
  } catch {}
}

async function refresh() {
  await loadCurrentTabId();
  const tabId = Number($('networkTabId')?.value);
  const requests = [
    send({ type: 'get-profiles' }),
    send({ type: 'get-events', limit: 300 }),
    send({ type: 'get-graph' }),
    send({ type: 'get-evidence', limit: 300 }),
    send({ type: 'get-settings' }),
    send({ type: 'get-safe-scanned-domains' }),
    send({ type: 'get-user-trusted' }),
    send({ type: 'get-custom-scripts' })
  ];
  requests.push(Number.isInteger(tabId) && tabId >= 0 ? send({ type: 'get-network-observation', tabId, limit: 200 }) : Promise.resolve({ observation: [] }));
  const [pr, ev, gr, ee, st, sd, ut, cs, no] = await Promise.all(requests);
  profiles = pr?.profiles || {};
  events = ev?.events || [];
  evidence = ee?.evidence || [];
  settings = st?.settings || {};
  safeDomains = sd?.domains || [];
  userTrusted = ut?.domains || [];
  customScripts = cs?.scripts || [];
  network = no?.observation || [];

  const nodes = Object.keys(gr?.graph?.nodes || {}).length;
  const set = (id, v) => { const el = $(id); if (el) el.textContent = String(v); };
  set('protected', Object.keys(profiles).length);
  set('events', events.length);
  set('blocked', events.filter(e => ['blocked', 'contained'].some(x => String(e.type).includes(x))).length);
  set('nodes', nodes);

  renderProfiles();
  renderCustomScripts();
  renderSafeDomains();
  renderTrustedList();
  renderSettings();
  renderNewStats();
  renderEvents();
  renderEvidence();
  renderNetwork();
  renderRisk();
  renderStorageStats();

  // Re-apply translations after dynamic content was rendered
  if (window.CorsairI18n) CorsairI18n.apply(document);

  const c = await send({ type: 'get-agent-context', tabId: Number.isInteger(tabId) && tabId >= 0 ? tabId : null, limit: 120 });
  const contextText = JSON.stringify(c?.context || {}, null, 2);
  if ($('agentContext')) $('agentContext').textContent = contextText;
}

/* ============================================================
   EXPORT / IMPORT
   ============================================================ */
async function doExport() {
  try {
    const r = await send({ type: 'export-config' });
    if (!r?.ok) throw new Error(r?.error || 'Export failed');
    downloadJSON(`corsair-unbound-${new Date().toISOString().replace(/[:.]/g, '-')}.corsair.json`, r.export);
    showToast('Exported.');
  } catch (e) { showToast(`Export failed: ${e.message}`, 'error'); }
}

function openImport() { const f = $('configFile'); if (f) { f.value = ''; f.click(); } }

async function handleImport(file) {
  try {
    if (!file) return;
    const text = await file.text();
    const data = JSON.parse(text);
    if (data?.format !== 'corsair-unbound') throw new Error('Invalid backup file.');
    const restoreTelemetry = $('restoreTelemetry')?.checked === true;
    const r = await send({ type: 'import-config', data, restoreTelemetry });
    if (!r?.ok) throw new Error(r?.error || 'Import failed');
    showToast(`Restored ${r.importedProfiles} profiles${restoreTelemetry ? ' with telemetry' : ''}.`);
    await refresh();
  } catch (e) { showToast(`Import failed: ${e.message}`, 'error'); }
}

/* ============================================================
   EVENT WIRING
   ============================================================ */
safeOn('refresh', 'click', refresh);
safeOn('domainSearch', 'input', renderProfiles);

safeOn('safeDomainSearch', 'input', () => {
  safeDomainSearch = $('safeDomainSearch').value || '';
  renderSafeDomains();
});

safeOn('safeSelectAll', 'change', () => {
  const cb = $('safeSelectAll');
  const q = safeDomainSearch.trim().toLowerCase();
  const visible = safeDomains.filter(d => !q || d.host.includes(q));
  if (cb.checked) for (const d of visible) safeDomainSelected.add(d.host);
  else for (const d of visible) safeDomainSelected.delete(d.host);
  renderSafeDomains();
});

safeOn('removeSelected', 'click', async () => {
  if (!safeDomainSelected.size) { showToast('No domains selected', 'error'); return; }
  if (!confirm(`Remove ${safeDomainSelected.size} domain(s)?`)) return;
  const hosts = [...safeDomainSelected];
  const r = await send({ type: 'bulk-remove-safe-scanned', hosts });
  if (r?.ok) {
    showToast(`Removed ${r.removed || hosts.length}`);
    safeDomainSelected.clear();
    await refresh();
  } else showToast(r?.error || 'Failed', 'error');
});

safeOn('clearSafeDomains', 'click', async () => {
  if (!confirm('Remove ALL safe-scanned domains?')) return;
  const r = await send({ type: 'clear-safe-scanned-domains' });
  if (r?.ok) { showToast(`Cleared ${r.removed || 0}`); safeDomainSelected.clear(); await refresh(); }
  else showToast(r?.error || 'Failed', 'error');
});

safeOn('exportSafeList', 'click', async () => {
  try {
    const r = await send({ type: 'export-safe-list' });
    if (!r?.ok) throw new Error(r?.error || 'failed');
    downloadJSON(`corsair-safe-list-${new Date().toISOString().slice(0,10)}.json`, r.export);
    showToast('Exported.');
  } catch (e) { showToast(`Failed: ${e.message}`, 'error'); }
});

safeOn('importSafeList', 'click', () => { const f = $('safeListFile'); if (f) { f.value = ''; f.click(); } });
safeOn('safeListFile', 'change', async (e) => {
  try {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    const data = JSON.parse(text);
    const r = await send({ type: 'import-safe-list', data });
    if (!r?.ok) throw new Error(r?.error || 'failed');
    showToast(`Imported ${r.imported} / ${r.total}`);
    await refresh();
  } catch (err) { showToast(`Failed: ${err.message}`, 'error'); }
});

safeOn('refreshStorage', 'click', renderStorageStats);
safeOn('wipeAllData', 'click', async () => {
  if (!confirm('⚠️ Delete ALL local data? Continue?')) return;
  if (!confirm('Absolutely sure? Cannot be undone.')) return;
  const r = await send({ type: 'wipe-all-data' });
  if (r?.ok) { showToast('Wiped.'); setTimeout(() => location.reload(), 800); }
  else showToast(r?.error || 'Failed', 'error');
});

safeOn('clearEvents', 'click', async () => { await send({ type: 'clear-events' }); await refresh(); showToast('Events cleared'); });
safeOn('clearTelemetry', 'click', async () => { await send({ type: 'clear-telemetry' }); await refresh(); showToast('Graph cleared'); });
safeOn('clearEvidence', 'click', async () => { await send({ type: 'clear-evidence' }); await refresh(); showToast('Evidence cleared'); });
safeOn('networkTabId', 'change', refresh);
safeOn('refreshNetwork', 'click', refresh);
safeOn('clearNetwork', 'click', async () => {
  const tabId = Number($('networkTabId')?.value);
  if (Number.isInteger(tabId) && tabId >= 0) await send({ type: 'clear-network-observation', tabId });
  await refresh();
  showToast('Network cleared');
});

safeOn('runRegression', 'click', async () => {
  const box = $('regression'); if (!box) return;
  box.innerHTML = '<div class="empty">Running…</div>';
  const r = await send({ type: 'run-regressions' });
  box.innerHTML = '';
  if (!r?.ok) { box.innerHTML = '<div class="empty">Failed.</div>'; return; }
  const s = document.createElement('div'); s.className = 'event';
  s.textContent = `Passed ${r.result?.passedCount || 0} / ${r.result?.total || 0}`;
  box.appendChild(s);
  for (const item of (r.result?.results || [])) {
    const row = document.createElement('div'); row.className = 'event';
    const main = document.createElement('div'); main.className = 'event-main';
    const t2 = document.createElement('div'); t2.className = 'event-type'; t2.textContent = item.title || item.caseId;
    const m = document.createElement('div'); m.className = 'event-meta';
    m.textContent = `${item.passed ? 'PASS' : 'FAIL'} • Expected ${item.expected?.verdict || '—'} • Risk ${item.actual?.risk ?? '—'}`;
    main.append(t2, m); row.appendChild(main); box.appendChild(row);
  }
});

safeOn('copyContext', 'click', async () => {
  const c = await send({ type: 'get-agent-context', tabId: Number($('networkTabId')?.value), limit: 120 });
  const text = JSON.stringify(c?.context || {}, null, 2);
  if ($('agentContext')) $('agentContext').textContent = text;
  try { await navigator.clipboard?.writeText(text); showToast('Copied'); } catch {}
});

safeOn('saveSettings', 'click', async () => {
  const r = await send({ type: 'patch-settings', patch: readSettingsForm() });
  if (r?.settings) { settings = r.settings; showToast('Settings saved.'); }
  else showToast(r?.error || 'Failed', 'error');
});

safeOn('exportConfig2', 'click', doExport);
safeOn('importConfig2', 'click', openImport);
safeOn('configFile', 'change', e => handleImport(e.target.files?.[0]));

safeOn('analyzerBtn', 'click', () => runAnalyzer(false));
safeOn('analyzerForceBtn', 'click', () => runAnalyzer(true));
safeOn('analyzerInput', 'keydown', e => { if (e.key === 'Enter') runAnalyzer(false); });

safeOn('scriptAddBtn', 'click', addCustomScript);
safeOn('scriptDomain', 'keydown', e => { if (e.key === 'Enter') addCustomScript(); });

safeOn('syncWhitelistBtn', 'click', async () => {
  showToast('Syncing…');
  const r = await send({ type: 'sync-whitelist' });
  if (r?.ok && r.result?.ok) showToast(`✓ Synced ${r.result.count} domains`);
  else showToast(r?.result?.error || r?.error || 'Failed', 'error');
});

document.addEventListener('click', async e => {
  if (e.target?.id === 'syncWhitelistInline') {
    showToast('Syncing…');
    const r = await send({ type: 'sync-whitelist' });
    const el = $('whitelistStatsInline');
    if (r?.ok && r.result?.ok && el) {
      el.textContent = `✓ ${r.stats.builtin + r.stats.remote + (r.stats.userTrusted || 0)} domains`;
      el.style.color = '#34d399';
    } else if (el) {
      el.textContent = `⚠ Failed`;
      el.style.color = '#f87171';
    }
  }
});

/* ============================================================
   BOOT
   ============================================================ */
(async () => {
  await initLanguage();
  await initTheme();
  await refresh();
})();
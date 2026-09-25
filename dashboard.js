/* ============================================================
   CORSAIR UNBOUND — DASHBOARD LOGIC
   Security Command Center UI
   ============================================================ */

function send(m) {
  return new Promise(resolve => {
    try { chrome.runtime.sendMessage(m, resolve); }
    catch (e) { resolve({ ok: false, error: String(e?.message || e) }); }
  });
}

/* ============================================================
   STATE
   ============================================================ */
const state = {
  profiles: {},
  events: [],
  evidence: [],
  settings: {},
  currentApiKey: '',
  safeDomains: [],
  userTrusted: [],
  userBlocked: [],
  customScripts: [],
  safeDomainSearch: '',
  safeDomainSelected: new Set(),
  editingScript: null,
  activeView: 'overview',
  apiKeyVisible: false,
  updateInfo: null
};

const $ = id => document.getElementById(id);
const $$ = sel => document.querySelectorAll(sel);
const safeOn = (id, event, handler) => { const el = $(id); if (el) el.addEventListener(event, handler); };
const t = (k, fb) => (window.CorsairI18n ? CorsairI18n.t(k, fb) : (fb || k));

/* ============================================================
   TOAST
   ============================================================ */
function showToast(message, type = 'success') {
  const container = $('toastContainer');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span>${type === 'success' ? '✓' : '⚠'}</span> <span>${escapeHtml(message)}</span>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(30px)';
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

function downloadJSON(filename, data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.style.display = 'none';
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
   VIEW NAVIGATION
   ============================================================ */
const VIEW_KEYS = {
  overview: 'view.overview',
  activity: 'view.activity',
  domains: 'view.domains',
  security: 'view.security',
  privacy: 'view.privacy',
  api: 'view.api',
  settings: 'view.settings',
  about: 'view.about'
};

function getViewTitle(viewName) {
  const key = VIEW_KEYS[viewName];
  const fb = viewName.charAt(0).toUpperCase() + viewName.slice(1);
  return key ? t(key, fb) : fb;
}

function switchView(viewName) {
  if (!VIEW_KEYS[viewName]) return;

  $$('.nav-item').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.view === viewName);
  });

  $$('.view').forEach(view => {
    view.classList.toggle('active', view.id === `view-${viewName}`);
  });

  const titleEl = $('viewTitle');
  if (titleEl) titleEl.textContent = getViewTitle(viewName);

  state.activeView = viewName;

  if (window.innerWidth <= 900) {
    const sidebar = $('sidebar');
    if (sidebar) sidebar.classList.remove('open');
  }

  if (!document.body.classList.contains('tour-active')) {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }
}

function initNavigation() {
  $$('.nav-item').forEach(btn => {
    btn.addEventListener('click', () => switchView(btn.dataset.view));
  });

  $$('[data-navigate]').forEach(btn => {
    btn.addEventListener('click', () => switchView(btn.dataset.navigate));
  });

  safeOn('sidebarToggle', 'click', () => {
    const sidebar = $('sidebar');
    if (sidebar) sidebar.classList.toggle('open');
  });

  document.addEventListener('click', e => {
    if (window.innerWidth > 900) return;
    const sidebar = $('sidebar');
    const toggle = $('sidebarToggle');
    if (!sidebar || !sidebar.classList.contains('open')) return;
    if (sidebar.contains(e.target)) return;
    if (toggle && toggle.contains(e.target)) return;
    sidebar.classList.remove('open');
  });
}

/* ============================================================
   NUMBER ANIMATION
   ============================================================ */
function animateNumber(el, target, duration = 600) {
  if (!el) return;
  const start = Number(el.textContent) || 0;
  const end = Number(target) || 0;
  if (start === end) { el.textContent = String(end); return; }

  const startTime = performance.now();
  function tick(now) {
    const elapsed = now - startTime;
    const progress = Math.min(1, elapsed / duration);
    const eased = 1 - Math.pow(1 - progress, 3);
    const current = Math.round(start + (end - start) * eased);
    el.textContent = String(current);
    if (progress < 1) requestAnimationFrame(tick);
    else el.textContent = String(end);
  }
  requestAnimationFrame(tick);
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
  const titleEl = $('viewTitle');
  if (titleEl) titleEl.textContent = getViewTitle(state.activeView);
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
      renderBlockedList();
      renderSettings();
      renderRecentActivity();
      renderApiStatus();
      const titleEl = $('viewTitle');
      if (titleEl) titleEl.textContent = getViewTitle(state.activeView);
      translateNavItems();
    });
    menu.appendChild(btn);
  }
}

function translateNavItems() {
  $$('.nav-item').forEach(btn => {
    const view = btn.dataset.view;
    const label = btn.querySelector('.nav-label');
    if (label && view) label.textContent = t(`nav.${view}`, label.textContent);
  });
  const brandSub = document.querySelector('.brand-sub');
  if (brandSub) brandSub.textContent = t('brand.sub', 'Security Command Center');
  const tourLabel = document.querySelector('#startTourBtn span:last-child');
  if (tourLabel) tourLabel.textContent = t('actions.tour', 'Take Tour');
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
  const search = $('domainSearch');
  const box = $('profiles');
  if (!box) return;

  const q = (search?.value || '').trim().toLowerCase();
  box.innerHTML = '';
  const entries = Object.entries(state.profiles)
    .filter(([d]) => !q || d.includes(q))
    .sort(([a], [b]) => a.localeCompare(b));

  if (!entries.length) {
    box.innerHTML = '<div class="empty">—</div>';
    return;
  }

  for (const [d, p] of entries) {
    const row = document.createElement('div');
    row.className = 'profile';

    const left = document.createElement('div');
    const title = document.createElement('strong');
    title.textContent = d;
    if (p.autoArmed === true) {
      const badge = document.createElement('span');
      badge.className = 'auto-armed-badge';
      badge.textContent = '⚡ AUTO';
      badge.title = p.autoArmReason || 'Auto-armed';
      title.appendChild(badge);
    }
    const sub = document.createElement('div');
    sub.className = 'muted';
    const mode = String(p.mode || 'custom').toUpperCase();
    const blockedCount = p.blockedDestinationDomains?.length || 0;
    sub.textContent = `${mode} • blocked destinations: ${blockedCount}`;
    left.append(title, sub);

    const right = document.createElement('div');
    right.className = 'profile-actions';
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

  if (!state.customScripts.length) {
    box.innerHTML = `<div class="empty">${escapeHtml(t('scripts.empty', 'No custom scripts yet. Add a domain above to begin.'))}</div>`;
    return;
  }

  for (const item of state.customScripts) {
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
  state.editingScript = { host, code: code || '', originalCode: code || '' };
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
  state.editingScript = null;
}

async function saveEditor() {
  if (!state.editingScript) return;
  const ta = $('editorCode');
  const code = ta ? ta.value : '';

  const res = await send({
    type: 'upsert-custom-script',
    host: state.editingScript.host,
    code,
    enabled: true
  });

  if (res?.ok) {
    showToast(`Saved script for ${state.editingScript.host}`);
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
  if (tab && state.editingScript && $('editorCode').value !== state.editingScript.originalCode) {
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

  const q = state.safeDomainSearch.trim().toLowerCase();
  const filtered = state.safeDomains.filter(d => !q || d.host.includes(q));

  if (!state.safeDomains.length) {
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
    if (state.safeDomainSelected.has(host)) row.classList.add('selected');

    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.className = 'safe-domain-cb';
    cb.checked = state.safeDomainSelected.has(host);
    cb.addEventListener('change', () => {
      if (cb.checked) state.safeDomainSelected.add(host);
      else state.safeDomainSelected.delete(host);
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
      if (res?.ok) { state.safeDomainSelected.delete(host); showToast(`Removed ${host}`); await refresh(); }
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
  if (el) el.innerHTML = `${state.safeDomainSelected.size} <span data-i18n="safe.selected">${escapeHtml(t('safe.selected', 'selected'))}</span>`;
  const selectAll = $('safeSelectAll');
  if (selectAll) {
    const q = state.safeDomainSearch.trim().toLowerCase();
    const visible = state.safeDomains.filter(d => !q || d.host.includes(q));
    selectAll.checked = visible.length > 0 && visible.every(d => state.safeDomainSelected.has(d.host));
    selectAll.indeterminate = visible.length > 0 && !selectAll.checked && visible.some(d => state.safeDomainSelected.has(d.host));
  }
}

/* ============================================================
   USER TRUSTED / BLOCKED DOMAINS
   ============================================================ */
function normalizeHostInput(raw) {
  const host = (raw || '').trim().toLowerCase()
    .replace(/^https?:\/\//, '').replace(/\/.*$/, '')
    .replace(/:\d+$/, '').replace(/^www\./, '');
  return /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(host) ? host : null;
}

async function addTrustedDomain() {
  const input = $('trustedDomainInput');
  if (!input) return;
  const host = normalizeHostInput(input.value);
  if (!host) { showToast(t('trusted.invalid', 'Invalid domain format'), 'error'); return; }
  const res = await send({ type: 'trust-domain', host });
  if (res?.ok) {
    input.value = '';
    showToast(t('trusted.added', 'Trusted {host}').replace('{host}', host));
    await refresh();
  } else {
    showToast(res?.error || 'Failed', 'error');
  }
}

function renderTrustedList() {
  const box = $('trustedList');
  if (!box) return;
  box.innerHTML = '';

  if (!state.userTrusted.length) {
    box.innerHTML = `<div class="empty">${escapeHtml(t('trusted.empty', 'No trusted domains yet.'))}</div>`;
    return;
  }

  for (const host of state.userTrusted) {
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

async function addBlockedDomain() {
  const input = $('blockedDomainInput');
  if (!input) return;
  const host = normalizeHostInput(input.value);
  if (!host) { showToast(t('blocked.invalid', 'Invalid domain format'), 'error'); return; }
  const res = await send({ type: 'block-domain-global', host });
  if (res?.ok) {
    input.value = '';
    showToast(t('blocked.added', 'Blocked {host}').replace('{host}', host));
    await refresh();
  } else {
    showToast(res?.error || 'Failed', 'error');
  }
}

function renderBlockedList() {
  const box = $('blockedList');
  if (!box) return;
  box.innerHTML = '';

  if (!state.userBlocked.length) {
    box.innerHTML = `<div class="empty">${escapeHtml(t('blocked.empty', 'No manually blocked domains yet.'))}</div>`;
    return;
  }

  for (const host of state.userBlocked) {
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
    badge.style.background = 'rgba(244,63,94,0.15)';
    badge.style.color = '#f87171';
    badge.style.borderColor = 'rgba(244,63,94,0.3)';
    badge.textContent = '🚫 BLOCKED';
    const delBtn = document.createElement('button');
    delBtn.className = 'btn-remove-safe';
    delBtn.textContent = t('blocked.unblock', 'Unblock');
    delBtn.addEventListener('click', async () => {
      const res = await send({ type: 'unblock-domain-global', host });
      if (res?.ok) { showToast(`Unblocked ${host}`); await refresh(); }
      else showToast(res?.error || 'Failed', 'error');
    });
    right.append(badge, delBtn);
    row.append(left, right);
    box.appendChild(row);
  }
}

/* ============================================================
   API STATUS
   ============================================================ */
function renderApiStatus() {
  const box = $('apiStatusBox');
  const title = $('apiStatusTitle');
  const detail = $('apiStatusDetail');
  const field = $('vtApiKeyField');
  if (!box || !title || !detail) return;

  const hasKey = Boolean(state.currentApiKey && state.currentApiKey.length > 0);

  box.classList.remove('connected', 'error');
  if (hasKey) {
    box.classList.add('connected');
    title.textContent = t('api.connected', 'Connected');
    detail.textContent = t('api.connectedDetail', 'VirusTotal API key configured. Threat intelligence is active.');
    if (field) {
      field.value = state.apiKeyVisible
        ? state.currentApiKey
        : '•'.repeat(Math.min(64, state.currentApiKey.length));
    }
  } else {
    title.textContent = t('api.notConfigured', 'Not configured');
    detail.textContent = t('api.notConfiguredDetail', 'Paste your 64-character VirusTotal API key below to enable threat intelligence.');
    if (field) field.value = '';
  }
}

safeOn('apiKeyToggle', 'click', () => {
  state.apiKeyVisible = !state.apiKeyVisible;
  const field = $('vtApiKeyField');
  if (!field) return;
  if (state.apiKeyVisible) {
    field.type = 'text';
    field.value = state.currentApiKey || '';
  } else {
    field.type = 'password';
    field.value = state.currentApiKey ? '•'.repeat(Math.min(64, state.currentApiKey.length)) : '';
  }
});

safeOn('apiKeySave', 'click', async () => {
  const field = $('vtApiKeyField');
  if (!field) return;

  const rawValue = field.value.trim();
  const isMasked = /^•+$/.test(rawValue);
  const newKey = isMasked ? state.currentApiKey : rawValue;

  try {
    await send({ type: 'set-api-key-secure', apiKey: newKey });
    state.currentApiKey = newKey;
    state.apiKeyVisible = false;
    renderApiStatus();
    showToast(newKey ? t('api.saved', 'API key saved.') : t('api.cleared', 'API key cleared.'));
  } catch (err) {
    showToast(err.message || t('api.saveFailed', 'Failed to save API key'), 'error');
  }
});

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
    set('storageBlocked', u.userBlockedCount || 0);
    set('storageSafeScanned', u.safeScannedCount || 0);
    set('storageCacheCount', u.threatCacheCount || 0);
    set('storageCustomScripts', u.customScriptsCount || 0);
  } catch {}
}

/* ============================================================
   SETTINGS
   ============================================================ */
function renderSettings() {
  const box = $('settingsForm');
  if (!box) return;
  box.innerHTML = '';

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
    const l = document.createElement('label');
    l.className = 'setting';
    const input = document.createElement('input');
    input.type = 'checkbox';
    input.dataset.key = key;
    input.checked = state.settings[key] !== false;
    const span = document.createElement('span');
    span.textContent = t(i18nKey, key);
    l.append(input, span);
    box.appendChild(l);
  }

  const wrap = document.createElement('label');
  wrap.className = 'setting';
  const span = document.createElement('span');
  span.textContent = t('setting.maxRedirectHops', 'Global max redirect hops');
  const num = document.createElement('input');
  num.type = 'number';
  num.min = '1';
  num.max = '32';
  num.step = '1';
  num.value = state.settings.maxRedirectHops || 8;
  num.dataset.key = 'maxRedirectHops';
  wrap.append(span, num);
  box.appendChild(wrap);

  const autoBlock = document.createElement('div');
  autoBlock.className = 'setting-block';

  const header = document.createElement('div');
  header.className = 'setting-block-header';

  const headerText = document.createElement('div');
  const strong = document.createElement('strong');
  strong.textContent = '⚡ ' + t('onboarding.step5.autoArm.title', 'Auto-Arm Fortress');
  const caption = document.createElement('div');
  caption.className = 'muted';
  caption.textContent = t('onboarding.step5.autoArm.desc', 'Automatically shield sites flagged as risky.');
  headerText.append(strong, caption);

  const toggleLabel = document.createElement('label');
  toggleLabel.className = 'custom-switch-label';
  const toggleInput = document.createElement('input');
  toggleInput.type = 'checkbox';
  toggleInput.dataset.key = 'autoArmFortress';
  toggleInput.checked = state.settings.autoArmFortress !== false;
  const toggleTrack = document.createElement('span');
  toggleTrack.className = 'slider-track';
  toggleLabel.append(toggleInput, toggleTrack);

  header.append(headerText, toggleLabel);
  autoBlock.appendChild(header);

  const armValue = Number.isFinite(state.settings.autoArmFortressThreshold)
    ? state.settings.autoArmFortressThreshold
    : 10;
  const blockValue = Number.isFinite(state.settings.autoBlockThreshold)
    ? state.settings.autoBlockThreshold
    : 70;

  const armRow = makeSliderRow({
    label: 'Arm at',
    key: 'autoArmFortressThreshold',
    value: armValue,
    min: 1, max: 100, step: 1
  });
  const blockRow = makeSliderRow({
    label: 'Block at',
    key: 'autoBlockThreshold',
    value: blockValue,
    min: 1, max: 100, step: 1
  });
  autoBlock.append(armRow, blockRow);
  box.appendChild(autoBlock);
}

function makeSliderRow({ label, key, value, min, max, step }) {
  const row = document.createElement('div');
  row.className = 'setting-slider-row';

  const labelEl = document.createElement('span');
  labelEl.className = 'setting-slider-label';
  labelEl.textContent = label;

  const slider = document.createElement('input');
  slider.type = 'range';
  slider.className = 'setting-slider';
  slider.min = String(min);
  slider.max = String(max);
  slider.step = String(step);
  slider.value = String(value);
  slider.dataset.sliderKey = key;

  const valueEl = document.createElement('span');
  valueEl.className = 'setting-slider-value';
  valueEl.textContent = `${value}%`;
  valueEl.dataset.sliderValue = key;

  slider.addEventListener('input', () => {
    valueEl.textContent = `${slider.value}%`;
  });

  row.append(labelEl, slider, valueEl);
  return row;
}

function readSettingsForm() {
  const patch = {};
  document.querySelectorAll('#settingsForm [data-key]').forEach(el => {
    if (el.dataset.key === 'vtApiKey') return;
    if (el.type === 'checkbox') patch[el.dataset.key] = el.checked;
    else if (el.type === 'number') patch[el.dataset.key] = Math.max(1, Math.min(32, Number(el.value) || 8));
    else patch[el.dataset.key] = el.value.trim();
  });
  document.querySelectorAll('#settingsForm [data-slider-key]').forEach(el => {
    const key = el.dataset.sliderKey;
    const v = Math.max(1, Math.min(100, Number(el.value) || 10));
    patch[key] = v;
  });
  return patch;
}

/* ============================================================
   STATS + HERO
   ============================================================ */
function renderNewStats() {
  animateNumber($('statEvents'), state.events.length);

  const protectionTypes = [
    'blocked', 'contained', 'popup_blocked', 'navigation_contained',
    'navigation_blocked', 'new_tab_blocked', 'download_blocked',
    'auto_block', 'auto_fortress_armed'
  ];
  const protectionCount = state.events.filter(e =>
    protectionTypes.some(t2 => String(e.type || '').includes(t2))
  ).length;
  animateNumber($('statProtection'), protectionCount);

  const blacklist = new Set();
  for (const p of Object.values(state.profiles || {})) {
    if (Array.isArray(p?.blockedDestinationDomains)) {
      for (const d of p.blockedDestinationDomains) blacklist.add(d);
    }
  }
  for (const d of state.userBlocked || []) blacklist.add(d);
  animateNumber($('statBlacklist'), blacklist.size);
  animateNumber($('statGroups'), Object.keys(state.profiles || {}).length);
}

function updateHero() {
  const hero = $('heroStatus');
  const title = $('heroTitle');
  const sub = $('heroSub');
  const label = document.querySelector('.hero-label');
  if (!hero || !title || !sub) return;

  hero.classList.remove('warning', 'danger');

  if (label) label.textContent = t('hero.label', 'SYSTEM STATUS');

  const profileCount = Object.keys(state.profiles).length;
  const hasApi = Boolean(state.currentApiKey);
  const threatIntel = state.settings.threatIntelEnabled !== false;

  if (!threatIntel) {
    hero.classList.add('warning');
    title.textContent = t('hero.limited', 'Protection Limited');
    sub.textContent = t('hero.subLimited', 'Threat intelligence is disabled. Enable it in Settings.');
  } else if (!hasApi) {
    hero.classList.add('warning');
    title.textContent = t('hero.apiMissing', 'API Not Configured');
    sub.textContent = t('hero.subApiMissing', 'Add a VirusTotal API key to enable threat analysis.');
  } else if (profileCount > 0) {
    title.textContent = t('hero.active', 'Protection Active');
    sub.textContent = t('hero.subActive', '{count} profiles protected • All systems operational')
      .replace('{count}', profileCount);
  } else {
    title.textContent = t('hero.standby', 'Standby');
    sub.textContent = t('hero.subStandby', 'System ready. Arm Fortress on a site to begin.');
  }
}

/* ============================================================
   EVENTS / EVIDENCE / RISK
   ============================================================ */
function renderEvents() {
  const box = $('activity');
  if (!box) return;
  box.innerHTML = '';
  if (!state.events.length) { box.innerHTML = '<div class="empty">—</div>'; return; }
  for (const e of state.events.slice(0, 200)) {
    const row = document.createElement('div');
    row.className = 'event';
    const main = document.createElement('div');
    main.className = 'event-main';
    const t2 = document.createElement('div');
    t2.className = 'event-type';
    t2.textContent = e.type || 'event';
    const m = document.createElement('div');
    m.className = 'event-meta';
    m.textContent = `${humanTime(e.timestamp)} • ${e.domain || e.source || ''}${e.destination ? ` → ${e.destination}` : ''}${e.reason ? ` • ${e.reason}` : ''}`;
    main.append(t2, m);
    const sev = document.createElement('div');
    sev.className = e.severity || 'low';
    sev.textContent = String(e.severity || 'low').toUpperCase();
    row.append(main, sev);
    box.appendChild(row);
  }
}

function renderRecentActivity() {
  const box = $('recentActivity');
  if (!box) return;
  box.innerHTML = '';
  const recent = state.events.slice(0, 5);
  if (!recent.length) {
    box.innerHTML = '<div class="empty">No recent activity.</div>';
    return;
  }
  for (const e of recent) {
    const row = document.createElement('div');
    row.className = 'event';
    const main = document.createElement('div');
    main.className = 'event-main';
    const t2 = document.createElement('div');
    t2.className = 'event-type';
    t2.textContent = e.type || 'event';
    const m = document.createElement('div');
    m.className = 'event-meta';
    m.textContent = `${humanTime(e.timestamp)} • ${e.domain || e.source || ''}${e.destination ? ` → ${e.destination}` : ''}`;
    main.append(t2, m);
    const sev = document.createElement('div');
    sev.className = e.severity || 'low';
    sev.textContent = String(e.severity || 'low').toUpperCase();
    row.append(main, sev);
    box.appendChild(row);
  }
}

function renderEvidence() {
  const box = $('evidence');
  if (!box) return;
  box.innerHTML = '';
  if (!state.evidence.length) { box.innerHTML = '<div class="empty">—</div>'; return; }
  for (const e of state.evidence.slice(0, 200)) {
    const row = document.createElement('div');
    row.className = 'event';
    const main = document.createElement('div');
    main.className = 'event-main';
    const t2 = document.createElement('div');
    t2.className = 'event-type';
    t2.textContent = e.kind || 'observation';
    const m = document.createElement('div');
    m.className = 'event-meta';
    m.textContent = `${humanTime(e.timestamp)} • ${e.origin || ''} • tab ${e.tabId ?? '-'}`;
    main.append(t2, m);
    row.append(main);
    box.appendChild(row);
  }
}

function behaviorDomains() {
  const set = new Set(Object.keys(state.profiles));
  for (const e of state.events) {
    if (e.domain) set.add(e.domain);
    if (e.source) set.add(e.source);
    if (e.destination) set.add(e.destination);
  }
  return [...set].filter(Boolean).sort().slice(0, 60);
}

async function renderRisk() {
  const box = $('riskBoard');
  if (!box) return;
  box.innerHTML = '';
  const domains = behaviorDomains();
  if (!domains.length) { box.innerHTML = '<div class="empty">—</div>'; return; }

  const rows = new Map();
  for (const d of domains) {
    const row = document.createElement('div');
    row.className = 'event';
    const main = document.createElement('div');
    main.className = 'event-main';
    const t2 = document.createElement('div');
    t2.className = 'event-type';
    t2.textContent = d;
    const m = document.createElement('div');
    m.className = 'event-meta';
    m.textContent = 'Analyzing…';
    main.append(t2, m);
    row.append(main);
    box.appendChild(row);
    rows.set(d, m);
  }

  const CONCURRENCY = 6;
  let cursor = 0;
  async function worker() {
    while (cursor < domains.length) {
      const d = domains[cursor++];
      const m = rows.get(d);
      if (!m || !box.contains(m)) continue;
      try {
        const r = await send({ type: 'assess-domain-risk', domain: d });
        if (r?.assessment) {
          const a = r.assessment;
          m.textContent = `${String(a.verdict || 'unknown').toUpperCase()} • Risk ${a.risk}/100 • ${Math.round((a.confidence || 0) * 100)}%${a.reasons?.length ? ' • ' + a.reasons.join(', ') : ''}`;
        } else {
          m.textContent = '—';
        }
      } catch {
        m.textContent = 'Error';
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, domains.length) }, worker));
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
  if (report.bestPopularityRank) {
    metaItems.push(['Popularity rank', `#${Number(report.bestPopularityRank).toLocaleString()}`]);
  }
  if (report.totalVotes && (report.totalVotes.harmless || report.totalVotes.malicious)) {
    metaItems.push(['Community votes', `👍 ${report.totalVotes.harmless || 0}  👎 ${report.totalVotes.malicious || 0}`]);
  }
  if (report.certIssuer) {
    metaItems.push(['TLS certificate', report.certIssuer]);
  }
  for (const [k, v] of metaItems) {
    const item = document.createElement('div');
    item.className = 'analyzer-meta-item';
    const s1 = document.createElement('strong');
    s1.textContent = k;
    const s2 = document.createElement('span');
    s2.textContent = v;
    item.append(s1, s2);
    meta.appendChild(item);
  }
  wrap.appendChild(meta);

  if (Array.isArray(report.tags) && report.tags.length) {
    const tagRow = document.createElement('div');
    tagRow.className = 'analyzer-tags';
    for (const tag of report.tags.slice(0, 10)) {
      const chip = document.createElement('span');
      chip.className = 'analyzer-tag-chip';
      chip.textContent = tag;
      tagRow.appendChild(chip);
    }
    wrap.appendChild(tagRow);
  }

  const catList = report.categories && typeof report.categories === 'object'
    ? [...new Set(Object.values(report.categories))].filter(Boolean)
    : [];
  if (catList.length) {
    const catRow = document.createElement('div');
    catRow.className = 'analyzer-engines';
    catRow.innerHTML = `<b>${escapeHtml(t('analyzer.categories', 'Categories'))}:</b> ${escapeHtml(catList.join(', '))}`;
    wrap.appendChild(catRow);
  }

  if (Array.isArray(report.dnsRecords) && report.dnsRecords.length) {
    const dnsRow = document.createElement('div');
    dnsRow.className = 'analyzer-engines';
    const lines = report.dnsRecords.map(r => `${r.type} → ${r.value}`).join('\n');
    dnsRow.innerHTML = `<b>${escapeHtml(t('analyzer.dns', 'DNS records'))}:</b>`;
    const pre = document.createElement('div');
    pre.style.whiteSpace = 'pre-wrap';
    pre.style.marginTop = '4px';
    pre.textContent = lines;
    dnsRow.appendChild(pre);
    wrap.appendChild(dnsRow);
  }

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

  if (report.relationships && typeof report.relationships === 'object') {
    const rel = report.relationships;

    if (Array.isArray(rel.subdomains) && rel.subdomains.length) {
      const subSec = document.createElement('div');
      subSec.className = 'analyzer-engines';
      subSec.style.borderLeft = '3px solid #7c3aed';
      subSec.innerHTML = `<strong style="color:#a78bfa;">🌐 Subdomains (${rel.subdomains.length}):</strong> `;
      const list = document.createElement('div');
      list.style.whiteSpace = 'pre-wrap';
      list.style.marginTop = '4px';
      list.style.maxHeight = '180px';
      list.style.overflow = 'auto';
      list.textContent = rel.subdomains.join('\n');
      subSec.appendChild(list);
      wrap.appendChild(subSec);
    }

    const renderFileList = (title, files, color) => {
      if (!Array.isArray(files) || !files.length) return;
      const sec = document.createElement('div');
      sec.className = 'analyzer-engines';
      sec.style.borderLeft = `3px solid ${color}`;
      sec.innerHTML = `<strong style="color:${color};">${escapeHtml(title)} (${files.length}):</strong>`;
      const list = document.createElement('div');
      list.style.marginTop = '4px';
      for (const f of files) {
        const line = document.createElement('div');
        line.style.padding = '2px 0';
        const malBadge = f.malicious > 0
          ? `<span style="color:#f87171; font-weight:700;">⚠ ${f.malicious}</span>`
          : `<span style="color:#34d399;">✓ 0</span>`;
        line.innerHTML = `<code>${escapeHtml(f.name || (f.sha256 || '').slice(0, 16))}</code> ` +
          `<span style="color:#94a3b8;">(${escapeHtml(f.type || 'file')}, ${formatBytes(f.size || 0)})</span> ` +
          `— mal: ${malBadge} / sus: ${f.suspicious}`;
        list.appendChild(line);
      }
      sec.appendChild(list);
      wrap.appendChild(sec);
    };

    renderFileList('📦 Communicating Files', rel.communicatingFiles, '#f59e0b');
    renderFileList('⬇ Downloaded Files', rel.downloadedFiles, '#3b82f6');
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

async function runDeepScan() {
  const box = $('analyzerResult');
  const input = $('analyzerInput');
  if (!input || !box) return;

  const raw = (input.value || '').trim();
  if (!raw) {
    box.innerHTML = `<div class="empty">${escapeHtml(t('analyzer.placeholder', 'Enter a domain.'))}</div>`;
    return;
  }

  let host = raw.toLowerCase()
    .replace(/^https?:\/\//, '').replace(/\/.*$/, '')
    .replace(/:\d+$/, '').replace(/^www\./, '');
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(host)) {
    box.innerHTML = '<div class="empty">Invalid format</div>';
    return;
  }

  box.innerHTML = `<div class="empty">🔎 Deep-scanning… this makes 4 VirusTotal requests (rate-limited, ~1 min).</div>`;

  try {
    const r = await send({ type: 'deep-scan-domain', domain: host });
    if (!r?.ok) throw new Error(r?.error || 'deep-scan-failed');
    renderAnalyzerResult({ report: r.report });
    refresh().catch(() => {});
  } catch (err) {
    renderAnalyzerResult({ error: err.message });
  }
}

function renderUrlScanResult(data) {
  const box = $('urlScanResult');
  if (!box) return;
  box.innerHTML = '';
  if (!data) return;
  if (data.error) { box.innerHTML = `<div class="empty">⚠ ${escapeHtml(data.error)}</div>`; return; }

  const r = data.result || {};
  const verdict = String(r.verdict || r.status || 'unknown').toLowerCase();
  const wrap = document.createElement('div');

  const vRow = document.createElement('div');
  vRow.className = 'analyzer-verdict';
  const badge = document.createElement('span');
  badge.className = `analyzer-badge ${verdict}`;
  badge.textContent = verdict === 'clean' ? '✓ CLEAN'
    : verdict === 'suspicious' ? '⚡ SUSPICIOUS'
    : verdict === 'malicious' ? '⚠ MALICIOUS'
    : verdict === 'pending' ? '⏳ PENDING'
    : '? UNKNOWN';
  vRow.appendChild(badge);
  const urlLabel = document.createElement('span');
  urlLabel.style.fontSize = '11px';
  urlLabel.style.color = '#94a3b8';
  urlLabel.style.wordBreak = 'break-all';
  urlLabel.textContent = r.url || '';
  vRow.appendChild(urlLabel);
  wrap.appendChild(vRow);

  if (r.status === 'pending') {
    const note = document.createElement('div');
    note.className = 'empty';
    note.textContent = t('analyzer.urlPending', 'VirusTotal is still analyzing this URL — try again in a moment.');
    wrap.appendChild(note);
  } else if (Array.isArray(r.flaggedEngines) && r.flaggedEngines.length) {
    const eng = document.createElement('div');
    eng.className = 'analyzer-engines';
    eng.innerHTML = `<b>Flagged by ${r.flaggedEngines.length} engine(s):</b> ${escapeHtml(r.flaggedEngines.join(', '))}`;
    wrap.appendChild(eng);
  } else if (r.status === 'analyzed') {
    const eng = document.createElement('div');
    eng.className = 'analyzer-engines';
    eng.innerHTML = `<span style="color:#34d399;">✓ No engines flagged this exact URL</span>`;
    wrap.appendChild(eng);
  }

  box.appendChild(wrap);
}

async function runUrlScan() {
  const box = $('urlScanResult');
  const input = $('urlScanInput');
  if (!input || !box) return;
  const raw = (input.value || '').trim();
  if (!raw) return;
  let url = raw;
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
  try {
    new URL(url);
  } catch {
    box.innerHTML = '<div class="empty">Invalid URL</div>';
    return;
  }

  box.innerHTML = `<div class="empty">${escapeHtml(t('analyzer.urlScanning', 'Submitting to VirusTotal… this can take up to 30s.'))}</div>`;
  try {
    const r = await send({ type: 'scan-url', url });
    if (!r?.ok) throw new Error(r?.error || 'scan-failed');
    renderUrlScanResult({ result: r.result });
  } catch (err) {
    renderUrlScanResult({ error: err.message });
  }
}

/* ============================================================
   REFRESH
   ============================================================ */
   /**
 * Snapshot the current form values before re-rendering. If the user
 * is mid-edit and a background refresh fires, we restore their typed
 * value instead of blowing it away.
 */
function snapshotSettingsForm() {
  const snap = {};
  document.querySelectorAll('#settingsForm [data-key]').forEach(el => {
    snap[el.dataset.key] = el.type === 'checkbox' ? el.checked : el.value;
  });
  document.querySelectorAll('#settingsForm [data-slider-key]').forEach(el => {
    snap[el.dataset.sliderKey] = el.value;
  });
  return snap;
}

function restoreSettingsForm(snap) {
  if (!snap) return;
  document.querySelectorAll('#settingsForm [data-key]').forEach(el => {
    const k = el.dataset.key;
    if (!(k in snap)) return;
    if (el.type === 'checkbox') el.checked = !!snap[k];
    else el.value = snap[k];
  });
  document.querySelectorAll('#settingsForm [data-slider-key]').forEach(el => {
    const k = el.dataset.sliderKey;
    if (!(k in snap)) return;
    el.value = snap[k];
    const valueEl = document.querySelector(`[data-slider-value="${k}"]`);
    if (valueEl) valueEl.textContent = `${el.value}%`;
  });
}

/**
 * Called on save → after a successful save, refresh() may be invoked
 * and rebuild the form. This flag tells renderSettings to skip the
 * re-render so the user's edits are not lost.
 */
let _skipSettingsRender = false;

async function refresh() {
  const [pr, ev, gr, ee, st, sd, ut, ub, cs, ak] = await Promise.all([
    send({ type: 'get-profiles' }),
    send({ type: 'get-events', limit: 300 }),
    send({ type: 'get-graph' }),
    send({ type: 'get-evidence', limit: 300 }),
    send({ type: 'get-settings' }),
    send({ type: 'get-safe-scanned-domains' }),
    send({ type: 'get-user-trusted' }),
    send({ type: 'get-user-blocked' }),
    send({ type: 'get-custom-scripts' }),
    send({ type: 'get-api-key-secure' })
  ]);

  state.profiles = pr?.profiles || {};
  state.events = ev?.events || [];
  state.evidence = ee?.evidence || [];
  state.settings = st?.settings || {};
  state.safeDomains = sd?.domains || [];
  state.userTrusted = ut?.domains || [];
  state.userBlocked = ub?.domains || [];
  state.customScripts = cs?.scripts || [];
  state.currentApiKey = ak?.apiKey || '';

  const settingsSnapshot = snapshotSettingsForm();

  updateHero();
  renderProfiles();
  renderCustomScripts();
  renderSafeDomains();
  renderTrustedList();
  renderBlockedList();
  if (!_skipSettingsRender) renderSettings();
  else restoreSettingsForm(settingsSnapshot);
  renderNewStats();
  renderRecentActivity();
  renderEvents();
  renderEvidence();
  renderRisk();
  renderStorageStats();
  renderApiStatus();

  if (window.CorsairI18n) CorsairI18n.apply(document);
  const titleEl = $('viewTitle');
  if (titleEl) titleEl.textContent = getViewTitle(state.activeView);
  translateNavItems();
}

/* ============================================================
   EXPORT / IMPORT
   ============================================================ */
async function doExport() {
  try {
    const r = await send({ type: 'export-config' });
    if (!r?.ok) throw new Error(r?.error || 'Export failed');

    const exp = r.export || {};
    const s = exp.summary || {};

    // Ask for confirmation, showing a detailed preview of what the
    // file will contain. This makes it obvious that EVERYTHING the
    // user cares about — custom scripts, locked domains, telemetry —
    // is included.
    const lines = [
      `Corsair Unbound Backup`,
      ``,
      `This file will contain:`,
      `  • ${s.profileCount || 0} domain profiles`,
      `  • ${s.customScriptsCount || 0} custom scripts`,
      `  • ${s.trustedCount || 0} trusted domains`,
      `  • ${s.blockedCount || 0} manually blocked domains`,
      `  • ${s.threatCacheCount || 0} threat cache entries`,
      `  • ${s.regressionCasesCount || 0} regression cases`,
      `  • ${s.dnrRuleCount || 0} DNR rules (rebuilt on import)`,
      `  • Settings, preferences, theme, language`,
      ``,
      `Telemetry (events, evidence, chains, graph):`,
      `  • ${s.eventCount || 0} events`,
      `  • ${s.evidenceCount || 0} evidence entries`,
      `  • ${s.chainCount || 0} redirect chains`,
      `  • ${s.graphNodeCount || 0} graph nodes`,
      ``,
      `The VirusTotal API key is NEVER included.`,
      ``,
      `Download this backup now?`
    ];
    if (!confirm(lines.join('\n'))) return;

    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    downloadJSON(`corsair-unbound-${stamp}.corsair.json`, exp);
    showToast(`Exported: ${s.profileCount || 0} profiles, ${s.customScriptsCount || 0} scripts, ${s.blockedCount || 0} blocked`);
  } catch (e) {
    showToast(`Export failed: ${e.message}`, 'error');
  }
}

function openImport() {
  const f = $('configFile');
  if (f) { f.value = ''; f.click(); }
}

async function handleImport(file) {
  try {
    if (!file) return;
    const text = await file.text();
    const data = JSON.parse(text);

    if (data?.format !== 'corsair-unbound') {
      throw new Error('This file is not a Corsair Unbound backup.');
    }

    // Show a preview of what's about to be imported so the user can
    // confirm before any destructive action.
    const s = data.summary || {};
    const v = data.version || '?';
    const lines = [
      `Restore Corsair Unbound Backup?`,
      ``,
      `Backup version: v${v}`,
      `Exported at: ${data.exportedAt ? new Date(data.exportedAt).toLocaleString() : '—'}`,
      ``,
      `This will RESTORE:`,
      `  • ${s.profileCount ?? '—'} domain profiles`,
      `  • ${s.customScriptsCount ?? '—'} custom scripts`,
      `  • ${s.trustedCount ?? '—'} trusted domains`,
      `  • ${s.blockedCount ?? '—'} blocked domains`,
      `  • ${s.threatCacheCount ?? '—'} threat cache entries`,
      `  • Settings, preferences, theme, language`,
      ``,
      `Existing data of these types will be OVERWRITTEN.`,
      ``,
      `Telemetry: ${$('restoreTelemetry')?.checked === true ? 'WILL also be restored' : 'will NOT be restored (unchecked)'}.`,
      ``,
      `Continue?`
    ];
    if (!confirm(lines.join('\n'))) return;

    const restoreTelemetry = $('restoreTelemetry')?.checked === true;
    const r = await send({ type: 'import-config', data, restoreTelemetry });
    if (!r?.ok) throw new Error(r?.error || 'Import failed');

    const parts = [`${r.importedProfiles ?? 0} profiles`];
    if (r.importedCustomScripts) parts.push(`${r.importedCustomScripts} scripts`);
    if (r.importedUserTrusted) parts.push(`${r.importedUserTrusted} trusted`);
    if (r.importedUserBlocked) parts.push(`${r.importedUserBlocked} blocked`);
    if (r.importedThreatCache) parts.push(`${r.importedThreatCache} cache entries`);
    if (restoreTelemetry) parts.push('telemetry');
    showToast(`Restored: ${parts.join(', ')}`);
    await refresh();
  } catch (e) {
    showToast(`Import failed: ${e.message}`, 'error');
  }
}

/* ============================================================
   UPDATE CHECK
   ============================================================ */
async function initUpdateCheck() {
  if (typeof CorsairUpdater === 'undefined') return;

  const aboutBadge = $('aboutVersionBadge');
  const currentVersion = CorsairUpdater.getCurrentVersion();
  if (aboutBadge) aboutBadge.textContent = `v${currentVersion}`;

  const githubLink = $('aboutGithubLink');
  if (githubLink) githubLink.href = CorsairUpdater.repoUrl;

  try {
    const r = await send({ type: 'check-for-update', force: false });
    const result = r?.result || await CorsairUpdater.checkForUpdates({ force: false });
    state.updateInfo = result;
    applyUpdateResult(result);

    const params = new URLSearchParams(location.search);
    if (params.get('update') === '1' && result?.hasUpdate) {
      setTimeout(() => openUpdateModal(), 300);
    }
  } catch {}
}

function applyUpdateResult(result) {
  if (!result) return;
  state.updateInfo = result;

  const banner = $('updateBanner');
  const bannerTitle = $('updateBannerTitle');
  const bannerDetail = $('updateBannerDetail');
  const bannerLink = $('updateBannerLink');
  const dismissed = sessionStorage.getItem('updateBannerDismissed');

  if (bannerTitle) bannerTitle.textContent = t('update.banner.title', 'New version available');

  if (result.hasUpdate && banner && !dismissed) {
    if (bannerDetail) {
      bannerDetail.textContent = t('update.banner.detail', 'v{version} is ready. Download & install — your data will be preserved.')
        .replace('{version}', result.latest || '?');
    }
    if (bannerLink) {
      bannerLink.href = '#';
      bannerLink.textContent = t('update.banner.button', 'Download v{version}')
        .replace('{version}', result.latest || '?');
    }
    banner.hidden = false;
  } else if (banner) {
    banner.hidden = true;
  }

  const statusBox = $('aboutUpdateStatus');
  const statusText = $('aboutCheckUpdateText');
  if (statusText) statusText.textContent = t('about.check', 'Check for updates');

  const githubLink = $('aboutGithubLink');
  if (githubLink) {
    const githubLabel = githubLink.querySelector('span:last-child');
    if (githubLabel) githubLabel.textContent = t('about.github', 'View on GitHub');
  }

  const aboutTagline = document.querySelector('.about-text p:not(.muted)');
  if (aboutTagline) aboutTagline.textContent = t('about.tagline', 'Local-first browser shield — deterministic isolation, intelligence & recovery.');
  const aboutPrivacy = document.querySelector('.about-text p.muted');
  if (aboutPrivacy) aboutPrivacy.textContent = t('about.privacyNote', 'All data stored locally. No telemetry. No cloud.');

  if (!statusBox) return;
  statusBox.hidden = false;
  statusBox.className = 'about-update-status';

  if (result.error && !result.latest) {
    statusBox.classList.add('error');
    statusBox.textContent = t('about.error', '⚠ Could not check for updates ({error}).')
      .replace('{error}', result.error);
  } else if (result.hasUpdate) {
    statusBox.classList.add('warn');
    statusBox.innerHTML = t('about.hasUpdate', '🎉 v{latest} is available (you have v{current}).')
      .replace('{latest}', escapeHtml(result.latest))
      .replace('{current}', escapeHtml(result.current))
      + ` <a href="#" id="openUpdateModal">${escapeHtml(t('about.hasUpdateLink', 'Update now →'))}</a>`;
    setTimeout(() => {
      const link = $('openUpdateModal');
      if (link) link.addEventListener('click', (e) => {
        e.preventDefault();
        openUpdateModal();
      });
    }, 0);
  } else if (result.upToDate) {
    statusBox.classList.add('ok');
    statusBox.textContent = t('about.upToDate', "✓ You're on the latest version (v{version}).")
      .replace('{version}', result.current);
  } else if (result.isAhead) {
    statusBox.classList.add('ok');
    statusBox.textContent = t('about.ahead', '✓ Development build (v{current}) — ahead of public release (v{latest}).')
      .replace('{current}', result.current)
      .replace('{latest}', result.latest);
  } else {
    statusBox.textContent = t('about.lastChecked', 'Last checked: {time}.').replace('{time}', humanTime(result.checkedAt));
  }
}

safeOn('updateBannerDismiss', 'click', () => {
  const banner = $('updateBanner');
  if (banner) banner.hidden = true;
  sessionStorage.setItem('updateBannerDismissed', '1');
});

safeOn('updateBannerLink', 'click', (e) => {
  e.preventDefault();
  openUpdateModal();
});

safeOn('aboutCheckUpdate', 'click', async () => {
  if (typeof CorsairUpdater === 'undefined') return;
  const btn = $('aboutCheckUpdate');
  const text = $('aboutCheckUpdateText');
  if (btn) btn.disabled = true;
  if (text) text.textContent = t('about.checking', 'Checking…');

  const r = await send({ type: 'check-for-update', force: true });
  const result = r?.result || await CorsairUpdater.checkForUpdates({ force: true });
  applyUpdateResult(result);

  if (btn) btn.disabled = false;
});

/* ---------- UPDATE MODAL ---------- */
function translateUpdateModal() {
  const latest = state.updateInfo?.latest || '?';
  const setText = (id, key, fb) => {
    const el = $(id);
    if (el) el.textContent = t(key, fb);
  };

  setText('updateModalTitle', 'update.modal.title', 'A new version is available');

  const sub = $('updateModalSubtitle');
  if (sub) {
    sub.innerHTML = t('update.modal.subtitle', 'Corsair Unbound v{version} is ready.')
      .replace('{version}', `<span id="updateModalLatest">v${escapeHtml(latest)}</span>`);
  }

  /* Rebuild the download button while PRESERVING its child <span>.
   *
   * The previous implementation did `dlBtn.innerHTML = ''` and then
   * appended a single text node — which permanently destroyed the
   * <span id="updateDownloadVersion"> that applyUpdateResult() relies
   * on to update the version number. Once the modal had been opened
   * once, subsequent calls to applyUpdateResult() would silently fail
   * to find the span and the version digit inside the button would
   * stop updating.
   *
   * The new implementation:
   *   1. reads the localized "⬇ Download v{version}" template
   *   2. splits off the prefix that precedes the version number
   *   3. writes the prefix as a text node
   *   4. (re)creates the version <span> after it
   * This keeps the button label in sync with the active language AND
   * keeps the span alive for every subsequent applyUpdateResult() call.
   */
  const dlBtn = $('updateDownloadBtn');
  if (dlBtn) {
    const fullText = t('update.modal.step1.button', '⬇ Download v{version}')
      .replace('{version}', latest);
    const prefix = fullText.endsWith(latest)
      ? fullText.slice(0, fullText.length - latest.length)
      : fullText;

    dlBtn.textContent = '';
    dlBtn.appendChild(document.createTextNode(prefix));

    const versionSpan = document.createElement('span');
    versionSpan.id = 'updateDownloadVersion';
    versionSpan.textContent = latest;
    dlBtn.appendChild(versionSpan);
  }

  const stepNodes = document.querySelectorAll('.update-step-body strong');
  const stepDescs = document.querySelectorAll('.update-step-body > span');
  const keys = [
    ['update.modal.step1.title', 'update.modal.step1.desc'],
    ['update.modal.step2.title', 'update.modal.step2.desc'],
    ['update.modal.step3.title', 'update.modal.step3.desc'],
    ['update.modal.step4.title', 'update.modal.step4.desc'],
    ['update.modal.step5.title', 'update.modal.step5.desc']
  ];
  stepNodes.forEach((node, i) => {
    if (keys[i]) node.textContent = t(keys[i][0], node.textContent);
  });
  stepDescs.forEach((node, i) => {
    if (keys[i]) node.textContent = t(keys[i][1], node.textContent);
  });

  setText('updateCopyPathBtn', 'update.modal.step3.button', '📋 Copy the path');
  setText('updateOpenExtensionsBtn', 'update.modal.step4.button', '🔗 Copy chrome://extensions');
  setText('updateSkipVersion', 'update.modal.snooze', 'Remind me later');
  setText('updateModalDone', 'update.modal.done', 'Got it');
}

function openUpdateModal() {
  const modal = $('updateModal');
  if (!modal) return;
  translateUpdateModal();
  modal.hidden = false;
}

function closeUpdateModal() {
  const modal = $('updateModal');
  if (modal) modal.hidden = true;
}

safeOn('updateModalClose', 'click', closeUpdateModal);
safeOn('updateModalDone', 'click', closeUpdateModal);

safeOn('updateModal', 'click', (e) => {
  if (e.target && e.target.id === 'updateModal') closeUpdateModal();
});

safeOn('updateSkipVersion', 'click', () => {
  closeUpdateModal();
  showToast(t('update.snoozed', 'Reminder snoozed for this session.'));
});

safeOn('updateDownloadBtn', 'click', async () => {
  const btn = $('updateDownloadBtn');
  const status = $('updateDownloadStatus');
  if (btn) btn.disabled = true;
  if (status) {
    status.hidden = false;
    status.className = 'update-download-status';
    status.textContent = t('update.download.starting', '⏳ Starting download…');
  }

  const r = await send({ type: 'download-update' });
  if (r?.ok) {
    if (status) {
      status.className = 'update-download-status success';
      status.textContent = t('update.download.success', '✅ Downloaded! Check your Downloads folder, then follow steps 2–4.');
    }
    showToast(t('update.download.success', 'Update ZIP downloaded.'));
  } else {
    if (status) {
      status.className = 'update-download-status error';
      status.textContent = t('update.download.failed', '⚠ Download failed: {error}').replace('{error}', r?.error || 'unknown');
    }
    showToast(t('update.download.failed', 'Download failed.').replace('{error}', r?.error || '?'), 'error');
  }
  if (btn) btn.disabled = false;
});

safeOn('updateCopyPathBtn', 'click', async () => {
  try {
    await navigator.clipboard.writeText(t('update.copy.pathHint', 'Open your Corsair Unbound extension folder'));
    showToast(t('update.copy.success', 'Copied to clipboard.'));
  } catch {
    showToast(t('update.copy.failed', 'Could not copy — copy manually.'), 'error');
  }
});

safeOn('updateOpenExtensionsBtn', 'click', async () => {
  try {
    await navigator.clipboard.writeText('chrome://extensions');
    showToast(t('update.copy.extensions', 'Copied: chrome://extensions'));
  } catch {
    showToast(t('update.copy.extensionsManual', 'Paste chrome://extensions in the URL bar.'), 'error');
  }
});

/* ============================================================
   ONBOARDING WIZARD
   ============================================================ */
const ONBOARDING_KEY = 'onboardingCompletedV1';

async function shouldShowOnboarding() {
  try {
    const r = await chrome.storage.local.get(ONBOARDING_KEY);
    return !r[ONBOARDING_KEY];
  } catch { return false; }
}

async function markOnboardingComplete() {
  try { await chrome.storage.local.set({ [ONBOARDING_KEY]: true }); }
  catch {}
}

const ONBOARDING_STEPS = [
  () => ({
    icon: '🌍',
    titleKey: 'onboarding.step0.title',
    titleFb: 'Choose your language',
    subtitleKey: 'onboarding.step0.subtitle',
    subtitleFb: 'Corsair speaks many languages. You can change this anytime.',
    body: () => {
      const langs = (window.CorsairI18n ? CorsairI18n.getLanguages() : []);
      const current = window.CorsairI18n ? CorsairI18n.getCurrent() : 'en';
      return `
        <div class="onboarding-language-grid">
          ${langs.map(l => `
            <button type="button"
              class="lang-choice ${l.code === current ? 'selected' : ''}"
              data-lang="${l.code}">
              <span class="lang-choice-flag">${l.flag}</span>
              <span class="lang-choice-label">${escapeHtml(l.label)}</span>
            </button>
          `).join('')}
        </div>
      `;
    },
    primaryKey: 'onboarding.step2.primary',
    primaryFb: 'Continue →',
    showBack: false,
    onMount: () => {
      document.querySelectorAll('.lang-choice').forEach(btn => {
        btn.addEventListener('click', async () => {
          const code = btn.dataset.lang;
          if (window.CorsairI18n) {
            await CorsairI18n.set(code);
            CorsairI18n.apply(document);
            updateCurrentLangDisplay();
          }
          renderOnboardingStep();
          const titleEl = $('viewTitle');
          if (titleEl) titleEl.textContent = getViewTitle(state.activeView);
          translateNavItems();
          renderSettings();
          renderRecentActivity();
          renderApiStatus();
        });
      });
    }
  }),

  () => ({
    icon: '🏴‍☠️',
    titleKey: 'onboarding.step1.title',
    titleFb: 'Welcome to Corsair Unbound',
    subtitleKey: 'onboarding.step1.subtitle',
    subtitleFb: 'A local-first browser shield. No accounts. No cloud. Everything stays on your device.',
    body: () => '',
    primaryKey: 'onboarding.step1.primary',
    primaryFb: 'Get Started →',
    showBack: false
  }),

  () => ({
    icon: '🛡️',
    titleKey: 'onboarding.step2.title',
    titleFb: 'What Corsair does for you',
    subtitleKey: 'onboarding.step2.subtitle',
    subtitleFb: 'Four layers of defense that work together automatically.',
    body: () => `
      <div class="onboarding-features">
        <div class="onboarding-feature">
          <span class="onboarding-feature-icon">⚡</span>
          <div class="onboarding-feature-body">
            <strong>${escapeHtml(t('onboarding.step2.f1.title', 'Fortress Mode'))}</strong>
            <span>${escapeHtml(t('onboarding.step2.f1.desc', 'Locks down individual sites.'))}</span>
          </div>
        </div>
        <div class="onboarding-feature">
          <span class="onboarding-feature-icon">🔬</span>
          <div class="onboarding-feature-body">
            <strong>${escapeHtml(t('onboarding.step2.f2.title', 'Threat Intelligence'))}</strong>
            <span>${escapeHtml(t('onboarding.step2.f2.desc', 'Checks any domain against 70+ engines.'))}</span>
          </div>
        </div>
        <div class="onboarding-feature">
          <span class="onboarding-feature-icon">🧠</span>
          <div class="onboarding-feature-body">
            <strong>${escapeHtml(t('onboarding.step2.f3.title', 'Heuristic Analysis'))}</strong>
            <span>${escapeHtml(t('onboarding.step2.f3.desc', 'Detects typosquatting and homograph attacks.'))}</span>
          </div>
        </div>
        <div class="onboarding-feature">
          <span class="onboarding-feature-icon">🚫</span>
          <div class="onboarding-feature-body">
            <strong>${escapeHtml(t('onboarding.step2.f4.title', 'Manual Blocklist'))}</strong>
            <span>${escapeHtml(t('onboarding.step2.f4.desc', 'One-click block from any verdict banner.'))}</span>
          </div>
        </div>
      </div>
    `,
    primaryKey: 'onboarding.step2.primary',
    primaryFb: 'Continue →',
    showBack: true
  }),

  () => ({
    icon: '🔑',
    titleKey: 'onboarding.step3.title',
    titleFb: 'Unlock deeper analysis',
    subtitleKey: 'onboarding.step3.subtitle',
    subtitleFb: 'Connecting a free VirusTotal key enables full threat intelligence.',
    body: () => `
      <ol class="onboarding-instructions" style="list-style:none; padding:0;">
        <li>${t('onboarding.step3.li1', 'Open virustotal.com/gui/join-us and create a free account.')}</li>
        <li>${t('onboarding.step3.li2', 'Sign in to your new account.')}</li>
        <li>${t('onboarding.step3.li3', 'Go to virustotal.com/gui/my-apikey to see your API key.')}</li>
        <li>${t('onboarding.step3.li4', 'Click the copy icon to copy your 64-character key.')}</li>
        <li>${t('onboarding.step3.li5', 'Come back here and paste it in the next step.')}</li>
      </ol>
    `,
    primaryKey: 'onboarding.step3.primary',
    primaryFb: 'I have my key →',
    secondaryKey: 'onboarding.step3.secondary',
    secondaryFb: 'Skip for now',
    showBack: true
  }),

  () => ({
    icon: '📋',
    titleKey: 'onboarding.step4.title',
    titleFb: 'Paste your API key',
    subtitleKey: 'onboarding.step4.subtitle',
    subtitleFb: 'Stored in memory only. Never written to disk.',
    body: () => `
      <div class="onboarding-input">
        <input type="password" id="onboardingApiKey" placeholder="${escapeHtml(t('onboarding.step4.placeholder', 'Paste your 64-char VirusTotal API Key'))}" autocomplete="off" spellcheck="false">
      </div>
      <div id="onboardingApiStatus" class="onboarding-status" hidden></div>
    `,
    primaryKey: 'onboarding.step4.primary',
    primaryFb: 'Save & Verify',
    secondaryKey: 'onboarding.step4.secondary',
    secondaryFb: 'Skip',
    showBack: true,
    onMount: () => {
      const input = $('onboardingApiKey');
      if (input) setTimeout(() => input.focus(), 200);
    },
    onPrimary: async () => {
      const input = $('onboardingApiKey');
      const status = $('onboardingApiStatus');
      const key = input?.value?.trim() || '';

      if (!key) {
        if (status) {
          status.hidden = false;
          status.className = 'onboarding-status error';
          status.textContent = t('onboarding.step4.errEmpty', '⚠ Please paste your API key first.');
        }
        return false;
      }
      if (key.length !== 64) {
        if (status) {
          status.hidden = false;
          status.className = 'onboarding-status error';
          status.textContent = t('onboarding.step4.errLength', '⚠ VirusTotal keys are 64 characters (yours is {len}).').replace('{len}', key.length);
        }
        return false;
      }

      if (status) {
        status.hidden = false;
        status.className = 'onboarding-status loading';
        status.textContent = t('onboarding.step4.verifying', '⏳ Verifying with VirusTotal…');
      }

      try {
        await send({ type: 'set-api-key-secure', apiKey: key });
        state.currentApiKey = key;

        const test = await send({ type: 'query-threat-intel', domain: 'example.com', force: false });
        if (!test?.ok && test?.error === 'invalid-api-key') {
          throw new Error(t('onboarding.step4.errInvalid', 'Invalid API key — VirusTotal rejected it.'));
        }

        if (status) {
          status.className = 'onboarding-status success';
          status.textContent = t('onboarding.step4.success', '✅ API key saved. Threat intelligence is active.');
        }

        refresh().catch(() => {});
        await new Promise(r => setTimeout(r, 700));
        return true;
      } catch (err) {
        if (status) {
          status.className = 'onboarding-status error';
          status.textContent = '⚠ ' + (err.message || 'Verification failed.');
        }
        return false;
      }
    }
  }),

  () => ({
    icon: '⚙️',
    titleKey: 'onboarding.step5.title',
    titleFb: 'A couple of preferences',
    subtitleKey: 'onboarding.step5.subtitle',
    subtitleFb: 'You can change all of these later in Settings.',
    body: () => `
      <div class="onboarding-prefs">
        <label class="onboarding-pref">
          <input type="checkbox" id="onboardingTheme" ${state.settings.theme === 'light' ? 'checked' : ''}>
          <div class="onboarding-pref-body">
            <strong>${escapeHtml(t('onboarding.step5.theme.title', 'Light theme'))}</strong>
            <span>${escapeHtml(t('onboarding.step5.theme.desc', 'Use a bright interface.'))}</span>
          </div>
        </label>
        <label class="onboarding-pref">
          <input type="checkbox" id="onboardingAutoArm" ${state.settings.autoArmFortress !== false ? 'checked' : ''}>
          <div class="onboarding-pref-body">
            <strong>${escapeHtml(t('onboarding.step5.autoArm.title', 'Auto-Arm Fortress'))}</strong>
            <span>${escapeHtml(t('onboarding.step5.autoArm.desc', 'Automatically shield risky sites.'))}</span>
          </div>
        </label>
        <label class="onboarding-pref">
          <input type="checkbox" id="onboardingBanner" ${state.settings.siteVerdictBanner !== false ? 'checked' : ''}>
          <div class="onboarding-pref-body">
            <strong>${escapeHtml(t('onboarding.step5.banner.title', 'In-page verdict banner'))}</strong>
            <span>${escapeHtml(t('onboarding.step5.banner.desc', 'Show a banner on analyzed sites.'))}</span>
          </div>
        </label>
      </div>
    `,
    primaryKey: 'onboarding.step5.primary',
    primaryFb: 'Finish setup',
    showBack: true,
    onMount: () => {
      const themeCb = $('onboardingTheme');
      if (themeCb) {
        themeCb.addEventListener('change', async () => {
          const next = themeCb.checked ? 'light' : 'dark';
          await chrome.storage.local.set({ theme: next });
          applyTheme(next);
        });
      }
    },
    onPrimary: async () => {
      const autoArm = $('onboardingAutoArm')?.checked;
      const banner = $('onboardingBanner')?.checked;
      try {
        await send({
          type: 'patch-settings',
          patch: {
            autoArmFortress: autoArm !== false,
            siteVerdictBanner: banner !== false
          }
        });
      } catch {}
      return true;
    }
  }),

  () => ({
    icon: '🎉',
    titleKey: 'onboarding.step6.title',
    titleFb: "You're ready to sail.",
    subtitleKey: 'onboarding.step6.subtitle',
    subtitleFb: 'Corsair is fully configured and protecting your browsing.',
    body: () => '',
    primaryKey: 'onboarding.step6.primary',
    primaryFb: 'Start Exploring',
    secondaryKey: 'onboarding.step6.secondary',
    secondaryFb: 'Take the tour',
    showBack: false,
    onSecondary: async () => {
      await completeOnboarding();
      setTimeout(() => startTour(), 400);
    }
  })
];

let _onboardingStep = 0;

function renderOnboardingStep() {
  const overlay = $('onboardingOverlay');
  if (!overlay) return;

  const factory = ONBOARDING_STEPS[_onboardingStep];
  if (!factory) return;
  const step = factory();

  let card = overlay.querySelector('.onboarding-card');
  if (!card) {
    card = document.createElement('div');
    card.className = 'onboarding-card';
    overlay.appendChild(card);
  }
  card.innerHTML = '';

  const skipBtn = document.createElement('button');
  skipBtn.className = 'onboarding-skip';
  skipBtn.type = 'button';
  skipBtn.textContent = t('onboarding.skip', 'Skip');
  skipBtn.addEventListener('click', completeOnboarding);
  card.appendChild(skipBtn);

  const body = document.createElement('div');
  body.className = 'onboarding-body';

  const stepEl = document.createElement('div');
  stepEl.className = 'onboarding-step active';

  const icon = document.createElement('div');
  icon.className = 'onboarding-icon';
  icon.textContent = step.icon || '🏴‍☠️';
  stepEl.appendChild(icon);

  const title = document.createElement('h2');
  title.className = 'onboarding-title';
  title.textContent = t(step.titleKey, step.titleFb || '');
  stepEl.appendChild(title);

  if (step.subtitleKey || step.subtitleFb) {
    const sub = document.createElement('p');
    sub.className = 'onboarding-subtitle';
    sub.textContent = t(step.subtitleKey, step.subtitleFb || '');
    stepEl.appendChild(sub);
  }

  const stepBodyHtml = typeof step.body === 'function' ? step.body() : '';
  if (stepBodyHtml) {
    const bodyWrap = document.createElement('div');
    bodyWrap.innerHTML = stepBodyHtml;
    stepEl.appendChild(bodyWrap);
  }

  const progress = document.createElement('div');
  progress.className = 'onboarding-progress';
  for (let i = 0; i < ONBOARDING_STEPS.length; i++) {
    const dot = document.createElement('div');
    dot.className = 'onboarding-dot';
    if (i < _onboardingStep) dot.classList.add('done');
    if (i === _onboardingStep) dot.classList.add('active');
    progress.appendChild(dot);
  }
  stepEl.appendChild(progress);

  body.appendChild(stepEl);
  card.appendChild(body);

  const nav = document.createElement('div');
  nav.className = 'onboarding-nav';

  if (step.showBack && _onboardingStep > 0) {
    const backBtn = document.createElement('button');
    backBtn.className = 'tool-btn';
    backBtn.type = 'button';
    backBtn.textContent = t('onboarding.back', '← Back');
    backBtn.addEventListener('click', () => {
      _onboardingStep = Math.max(0, _onboardingStep - 1);
      renderOnboardingStep();
    });
    nav.appendChild(backBtn);
  } else {
    const spacer = document.createElement('div');
    spacer.className = 'spacer';
    nav.appendChild(spacer);
  }

  if (step.secondaryKey || step.secondaryFb) {
    const secBtn = document.createElement('button');
    secBtn.className = 'tool-btn';
    secBtn.type = 'button';
    secBtn.textContent = t(step.secondaryKey, step.secondaryFb || '');
    secBtn.addEventListener('click', async () => {
      if (typeof step.onSecondary === 'function') {
        step.onSecondary();
      } else {
        _onboardingStep = Math.min(ONBOARDING_STEPS.length - 1, _onboardingStep + 1);
        renderOnboardingStep();
      }
    });
    nav.appendChild(secBtn);
  }

  const primaryBtn = document.createElement('button');
  primaryBtn.className = 'btn-primary';
  primaryBtn.type = 'button';
  primaryBtn.textContent = t(step.primaryKey, step.primaryFb || 'Continue →');
  primaryBtn.addEventListener('click', async () => {
    primaryBtn.disabled = true;
    try {
      if (typeof step.onPrimary === 'function') {
        const proceed = await step.onPrimary();
        if (proceed === false) return;
      }
      if (_onboardingStep >= ONBOARDING_STEPS.length - 1) {
        await completeOnboarding();
      } else {
        _onboardingStep++;
        renderOnboardingStep();
      }
    } finally {
      primaryBtn.disabled = false;
    }
  });
  nav.appendChild(primaryBtn);

  card.appendChild(nav);

  if (typeof step.onMount === 'function') {
    setTimeout(() => step.onMount(), 100);
  }
}

function openOnboarding() {
  const overlay = $('onboardingOverlay');
  if (!overlay) return;
  _onboardingStep = 0;
  overlay.hidden = false;
  renderOnboardingStep();
}

async function completeOnboarding() {
  const overlay = $('onboardingOverlay');
  if (overlay) overlay.hidden = true;
  await markOnboardingComplete();
}

/* ============================================================
   EVENT WIRING
   ============================================================ */
safeOn('refresh', 'click', refresh);
safeOn('domainSearch', 'input', renderProfiles);

safeOn('safeDomainSearch', 'input', () => {
  state.safeDomainSearch = $('safeDomainSearch').value || '';
  renderSafeDomains();
});

safeOn('safeSelectAll', 'change', () => {
  const cb = $('safeSelectAll');
  const q = state.safeDomainSearch.trim().toLowerCase();
  const visible = state.safeDomains.filter(d => !q || d.host.includes(q));
  if (cb.checked) for (const d of visible) state.safeDomainSelected.add(d.host);
  else for (const d of visible) state.safeDomainSelected.delete(d.host);
  renderSafeDomains();
});

safeOn('removeSelected', 'click', async () => {
  if (!state.safeDomainSelected.size) { showToast('No domains selected', 'error'); return; }
  if (!confirm(`Remove ${state.safeDomainSelected.size} domain(s)?`)) return;
  const hosts = [...state.safeDomainSelected];
  const r = await send({ type: 'bulk-remove-safe-scanned', hosts });
  if (r?.ok) {
    showToast(`Removed ${r.removed || hosts.length}`);
    state.safeDomainSelected.clear();
    await refresh();
  } else showToast(r?.error || 'Failed', 'error');
});

safeOn('clearSafeDomains', 'click', async () => {
  if (!confirm('Remove ALL safe-scanned domains?')) return;
  const r = await send({ type: 'clear-safe-scanned-domains' });
  if (r?.ok) {
    showToast(`Cleared ${r.removed || 0}`);
    state.safeDomainSelected.clear();
    await refresh();
  } else showToast(r?.error || 'Failed', 'error');
});

safeOn('exportSafeList', 'click', async () => {
  try {
    const r = await send({ type: 'export-safe-list' });
    if (!r?.ok) throw new Error(r?.error || 'failed');
    downloadJSON(`corsair-safe-list-${new Date().toISOString().slice(0,10)}.json`, r.export);
    showToast('Exported.');
  } catch (e) { showToast(`Failed: ${e.message}`, 'error'); }
});

safeOn('importSafeList', 'click', () => {
  const f = $('safeListFile');
  if (f) { f.value = ''; f.click(); }
});

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

safeOn('clearEvents', 'click', async () => {
  await send({ type: 'clear-events' });
  await refresh();
  showToast('Events cleared');
});

safeOn('clearTelemetry', 'click', async () => {
  await send({ type: 'clear-telemetry' });
  await refresh();
  showToast('Graph cleared');
});

safeOn('clearEvidence', 'click', async () => {
  await send({ type: 'clear-evidence' });
  await refresh();
  showToast('Evidence cleared');
});

safeOn('saveSettings', 'click', async () => {
  const r = await send({ type: 'patch-settings', patch: readSettingsForm() });
  if (r?.ok !== false) {
    if (r?.settings) state.settings = r.settings;
    showToast('Settings saved.');
    _skipSettingsRender = true;
    try {
      renderSettings();
      updateHero();
    } finally {
      _skipSettingsRender = false;
    }
  } else {
    showToast(r?.error || 'Failed', 'error');
  }
});

safeOn('exportConfig2', 'click', doExport);
safeOn('importConfig2', 'click', openImport);
safeOn('configFile', 'change', e => handleImport(e.target.files?.[0]));

safeOn('analyzerBtn', 'click', () => runAnalyzer(false));
safeOn('analyzerForceBtn', 'click', () => runAnalyzer(true));
safeOn('analyzerDeepBtn', 'click', runDeepScan);
safeOn('analyzerInput', 'keydown', e => { if (e.key === 'Enter') runAnalyzer(false); });

safeOn('urlScanBtn', 'click', runUrlScan);
safeOn('urlScanInput', 'keydown', e => { if (e.key === 'Enter') runUrlScan(); });

safeOn('trustedDomainBtn', 'click', addTrustedDomain);
safeOn('trustedDomainInput', 'keydown', e => { if (e.key === 'Enter') addTrustedDomain(); });

safeOn('blockedDomainBtn', 'click', addBlockedDomain);
safeOn('blockedDomainInput', 'keydown', e => { if (e.key === 'Enter') addBlockedDomain(); });

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
   PRODUCT TOUR
   ============================================================ */
let _tourActive = false;
let _tourIndex = 0;
let _tourStops = [];
let _tourResizeHandler = null;

const TOUR_STOP_DEFS = [
  {
    view: null,
    target: '.sidebar-brand',
    titleKey: 'tour.step1.title',
    titleFb: 'Welcome aboard',
    descKey: 'tour.step1.desc',
    descFb: 'This is your security command center.',
    placement: 'right'
  },
  {
    view: 'overview',
    target: '.hero',
    titleKey: 'tour.step2.title',
    titleFb: 'Security status',
    descKey: 'tour.step2.desc',
    descFb: 'Your live protection state.',
    placement: 'bottom'
  },
  {
    view: 'overview',
    target: '.quick-stats',
    titleKey: 'tour.step3.title',
    titleFb: 'Live counters',
    descKey: 'tour.step3.desc',
    descFb: 'Four at-a-glance metrics.',
    placement: 'bottom'
  },
  {
    view: 'overview',
    target: '#recentActivity',
    titleKey: 'tour.step4.title',
    titleFb: 'Recent activity feed',
    descKey: 'tour.step4.desc',
    descFb: 'Every security action lands here.',
    placement: 'bottom'
  },
  {
    view: 'domains',
    target: '.analyzer-panel',
    titleKey: 'tour.step5.title',
    titleFb: 'Domain Intelligence',
    descKey: 'tour.step5.desc',
    descFb: 'Analyze any domain against VirusTotal.',
    placement: 'bottom'
  },
  {
    view: 'security',
    target: '.grid-2col',
    titleKey: 'tour.step6.title',
    titleFb: 'Security Controls',
    descKey: 'tour.step6.desc',
    descFb: 'Manage trust and blocklists.',
    placement: 'bottom'
  },
  {
    view: 'api',
    target: '#apiStatusBox',
    titleKey: 'tour.step7.title',
    titleFb: 'Connect VirusTotal',
    descKey: 'tour.step7.desc',
    descFb: 'Add a free API key to unlock 70+ engines.',
    placement: 'bottom'
  }
];

function isRTL() {
  return document.body.classList.contains('rtl') ||
         document.documentElement.getAttribute('dir') === 'rtl';
}

function flipPlacementForRTL(placement) {
  if (!isRTL()) return placement;
  if (placement === 'left') return 'right';
  if (placement === 'right') return 'left';
  return placement;
}

function getViewportSize() {
  return {
    vw: document.documentElement.clientWidth,
    vh: document.documentElement.clientHeight
  };
}

function startTour() {
  if (_tourActive) return;
  _tourActive = true;
  _tourIndex = 0;

  _tourStops = TOUR_STOP_DEFS.map(def => ({
    ...def,
    title: t(def.titleKey, def.titleFb),
    desc: t(def.descKey, def.descFb)
  }));

  document.body.classList.add('tour-active');
  const overlay = $('tourOverlay');
  if (overlay) overlay.hidden = false;

  _tourResizeHandler = () => {
    if (!_tourActive) return;
    const stop = _tourStops[_tourIndex];
    if (!stop) return;
    const target = document.querySelector(stop.target);
    if (target) {
      const rect = target.getBoundingClientRect();
      positionTourSpotlight(rect, stop.placement);
    }
  };
  window.addEventListener('resize', _tourResizeHandler);
  window.addEventListener('scroll', _tourResizeHandler, true);

  document.addEventListener('keydown', _tourKeyHandler);

  showTourStop(0);
}

function _tourKeyHandler(e) {
  if (!_tourActive) return;
  if (e.key === 'Escape') { endTour(); }
  else if (e.key === 'ArrowRight' || e.key === 'ArrowDown') { e.preventDefault(); nextTourStop(); }
  else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') { e.preventDefault(); prevTourStop(); }
}

async function showTourStop(index) {
  if (!_tourActive) return;
  if (index < 0 || index >= _tourStops.length) return;
  _tourIndex = index;

  const stop = _tourStops[index];

  if (stop.view && state.activeView !== stop.view) {
    switchView(stop.view);
    await new Promise(r => setTimeout(r, 400));
  }

  const target = document.querySelector(stop.target);
  if (!target) {
    if (index < _tourStops.length - 1) return showTourStop(index + 1);
    return endTour();
  }

  try {
    target.scrollIntoView({ behavior: 'auto', block: 'center', inline: 'center' });
  } catch {
    try { target.scrollIntoView(); } catch {}
  }
  await new Promise(r => setTimeout(r, 120));

  const titleEl = $('tourTitle');
  const descEl = $('tourDesc');
  const counterEl = $('tourStepCounter');
  const backBtn = $('tourBack');
  const nextBtn = $('tourNext');

  if (titleEl) titleEl.textContent = stop.title;
  if (descEl) descEl.textContent = stop.desc;
  if (counterEl) {
    counterEl.textContent = t('tour.counter', '{current} / {total}')
      .replace('{current}', index + 1)
      .replace('{total}', _tourStops.length);
  }
  if (backBtn) {
    backBtn.style.visibility = index === 0 ? 'hidden' : 'visible';
    backBtn.textContent = t('tour.back', '← Back');
  }
  if (nextBtn) {
    nextBtn.textContent = index === _tourStops.length - 1
      ? t('tour.done', 'Start Exploring')
      : t('tour.next', 'Next →');
  }

  const progress = $('tourProgress');
  if (progress) {
    progress.innerHTML = '';
    for (let i = 0; i < _tourStops.length; i++) {
      const dot = document.createElement('div');
      dot.className = 'tour-progress-dot';
      if (i < index) dot.classList.add('done');
      if (i === index) dot.classList.add('active');
      progress.appendChild(dot);
    }
  }

  const rect = target.getBoundingClientRect();
  positionTourSpotlight(rect, stop.placement);

  requestAnimationFrame(() => {
    const r2 = target.getBoundingClientRect();
    positionTourSpotlight(r2, stop.placement);
  });
}

function positionTourSpotlight(targetRect, preferredPlacement = 'bottom') {
  const spotlight = $('tourSpotlight');
  const tooltip = $('tourTooltip');
  if (!spotlight || !tooltip) return;

  const placement = flipPlacementForRTL(preferredPlacement);

  const { vw, vh } = getViewportSize();
  const padding = 8;

  const sx = Math.max(0, targetRect.left - padding);
  const sy = Math.max(0, targetRect.top - padding);
  const sw = Math.min(vw - sx, targetRect.width + padding * 2);
  const sh = Math.min(vh - sy, targetRect.height + padding * 2);

  spotlight.style.left = `${sx}px`;
  spotlight.style.top = `${sy}px`;
  spotlight.style.width = `${sw}px`;
  spotlight.style.height = `${sh}px`;

  const tooltipRect = tooltip.getBoundingClientRect();
  const tw = Math.max(280, tooltipRect.width || 340);
  const th = Math.max(140, tooltipRect.height || 180);
  const gap = 16;

  let tx = 0;
  let ty = 0;

  const computePos = (p) => {
    if (p === 'bottom') {
      return { x: sx + sw / 2 - tw / 2, y: sy + sh + gap };
    }
    if (p === 'top') {
      return { x: sx + sw / 2 - tw / 2, y: sy - th - gap };
    }
    if (p === 'right') {
      return { x: sx + sw + gap, y: sy + sh / 2 - th / 2 };
    }
    if (p === 'left') {
      return { x: sx - tw - gap, y: sy + sh / 2 - th / 2 };
    }
    return { x: sx, y: sy };
  };

  const fits = (pos) => (
    pos.x >= 8 &&
    pos.y >= 8 &&
    pos.x + tw <= vw - 8 &&
    pos.y + th <= vh - 8
  );

  const fallbackOrder = ['bottom', 'top', 'right', 'left'];
  const order = [placement, ...fallbackOrder.filter(p => p !== placement)];

  let placed = false;
  for (const p of order) {
    const pos = computePos(p);
    if (fits(pos)) {
      tx = pos.x;
      ty = pos.y;
      placed = true;
      break;
    }
  }

  if (!placed) {
    let best = null;
    let bestScore = -1;
    for (const p of order) {
      const pos = computePos(p);
      const visibleW = Math.min(vw - 8, pos.x + tw) - Math.max(8, pos.x);
      const visibleH = Math.min(vh - 8, pos.y + th) - Math.max(8, pos.y);
      const score = Math.max(0, visibleW) * Math.max(0, visibleH);
      if (score > bestScore) {
        bestScore = score;
        best = pos;
      }
    }
    if (best) { tx = best.x; ty = best.y; }
  }

  tx = Math.max(8, Math.min(vw - tw - 8, tx));
  ty = Math.max(8, Math.min(vh - th - 8, ty));

  tooltip.style.left = `${tx}px`;
  tooltip.style.top = `${ty}px`;
}

function nextTourStop() {
  if (!_tourActive) return;
  if (_tourIndex >= _tourStops.length - 1) {
    endTour();
    return;
  }
  showTourStop(_tourIndex + 1);
}

function prevTourStop() {
  if (!_tourActive) return;
  if (_tourIndex <= 0) return;
  showTourStop(_tourIndex - 1);
}

function endTour() {
  if (!_tourActive) return;
  _tourActive = false;

  const overlay = $('tourOverlay');
  if (overlay) overlay.hidden = true;

  document.body.classList.remove('tour-active');

  if (_tourResizeHandler) {
    window.removeEventListener('resize', _tourResizeHandler);
    window.removeEventListener('scroll', _tourResizeHandler, true);
    _tourResizeHandler = null;
  }
  document.removeEventListener('keydown', _tourKeyHandler);

  try { chrome.storage.local.set({ tourCompleted: true }); } catch {}

  switchView('overview');
}

safeOn('startTourBtn', 'click', startTour);
safeOn('tourClose', 'click', endTour);
safeOn('tourBack', 'click', prevTourStop);
safeOn('tourNext', 'click', nextTourStop);

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local' || !changes.language) return;
  if (_tourActive) {
    _tourStops = TOUR_STOP_DEFS.map(def => ({
      ...def,
      title: t(def.titleKey, def.titleFb),
      desc: t(def.descKey, def.descFb)
    }));
    showTourStop(_tourIndex);
  }
});

/* ============================================================
   BOOT
   ============================================================ */
(async () => {
  initNavigation();
  await initLanguage();
  await initTheme();
  await refresh();

  initUpdateCheck().catch(() => {});

  const show = await shouldShowOnboarding();
  if (show) {
    setTimeout(() => openOnboarding(), 400);
  }
})();
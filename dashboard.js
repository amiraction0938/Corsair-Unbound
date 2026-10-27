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
  userscriptAvailability: null,
  scriptQuery: '',
  guideLang: '',
  guideTab: 'how',
  highlightScriptId: '',
  extensionId: '',
  safeDomainSearch: '',
  safeDomainSelected: new Set(),
  editingScript: null,
  activeView: 'overview',
  apiKeyVisible: false,
  updateInfo: null,
  analyticsRange: 14,
  activityFilters: {
    search: '',
    severity: 'all',
    type: 'all'
  }
};

const $ = id => document.getElementById(id);
const $$ = sel => document.querySelectorAll(sel);
const safeOn = (id, event, handler) => { const el = $(id); if (el) el.addEventListener(event, handler); };
const t = (k, fb) => (window.CorsairI18n ? CorsairI18n.t(k, fb) : (fb || k));

/* Local EN/FA text for the newer UI parts (kept out of the 8-language files). */
const isFaUi = () => String(window.CorsairI18n?.getCurrent?.() || '').toLowerCase().startsWith('fa');
const tx = (en, fa) => (isFaUi() ? fa : en);

function applyBilingual(root) {
  const fa = isFaUi();
  (root || document).querySelectorAll('[data-en]').forEach(el => {
    const txt = fa ? el.dataset.fa : el.dataset.en;
    if (txt) el.textContent = txt;
  });
}

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
  analytics: 'view.analytics',
  activity: 'view.activity',
  domains: 'view.domains',
  security: 'view.security',
  privacy: 'view.privacy',
  scripts: 'view.scripts',
  api: 'view.api',
  settings: 'view.settings',
  about: 'view.about'
};

function getViewTitle(viewName) {
  if (viewName === 'scripts') return tx('Userscripts', 'اسکریپت‌ها');
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
      renderAnalytics();
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

if (typeof chrome !== 'undefined' && chrome.storage?.onChanged) {
  chrome.storage.onChanged.addListener(async (changes, area) => {
    if (area !== 'local' || !changes.activityLog) return;
    try {
      const res = await send({ type: 'get-events', limit: 300 });
      state.events = res?.events || [];
      renderRecentActivity();
      renderEvents();
      renderAnalytics();
    } catch {}
  });
}

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
/* ============================================================
   USERSCRIPT GUIDE (English + Persian) and "prompt for AI"
   ============================================================ */
const US_GUIDE = {
  en: {
    title: '\u{1F4D8} How userscripts work',
    subtitle: 'Everything you (or an AI) need to know to write a working script.',
    tabHow: 'How it works',
    tabPrompt: 'Prompt for AI',
    cards: [
      {
        h: '1. What is a userscript?', wide: true,
        p: [
          'A userscript is a small JavaScript file that starts with a "header": a few lines like `// @key value`. Corsair Unbound injects it automatically into every page whose address matches the header, exactly like Tampermonkey.',
          'It needs Chrome 120 or newer, and "Allow User Scripts" must be switched on once for this extension in `chrome://extensions` > Details. If it is off, a notice appears above the script list.'
        ]
      },
      {
        h: '2. The header', wide: true,
        def: [
          ['@name', 'Required. The name shown in the list.'],
          ['@match', 'Which pages to run on. Repeat the line for several sites. `https://example.com/*` = that site only, `*://*.example.com/*` = the site and all subdomains, `<all_urls>` = everywhere. A script with no @match / @include never runs.'],
          ['@exclude / @exclude-match', 'Pages to skip.'],
          ['@include', 'Like @match, but with `*` and `?` wildcards, or a regular expression between slashes, e.g. `/^https:\\/\\/a\\.com\\/.*$/`.'],
          ['@run-at', 'When to run: `document-start` (earliest), `document-body`, `document-end`, `document-idle` (default, after the page loaded).'],
          ['@grant', 'Which GM_ functions the script may use. `none` = none.'],
          ['@require', 'URL of a library. It is downloaded once, cached, and loaded before your code (use a URL with a pinned version).'],
          ['@resource', 'A helper file (CSS, text, image): `@resource name URL`, read with `GM_getResourceText` / `GM_getResourceURL`.'],
          ['@noframes', 'Run only in the top page, not inside iframes.'],
          ['@inject-into', '`page` or `content`: force the run mode (see below).'],
          ['@version, @description, @namespace, @author', 'Informational. Importing a script with the same @name + @namespace (or from the same URL) updates the existing one instead of creating a duplicate.']
        ]
      },
      {
        h: '3. Two run modes: page or sandbox',
        ul: [
          '**Page mode** (`@grant none`, or only local helpers such as `GM_addStyle`): the script lives inside the page and can read the site\'s own JavaScript variables through `window` / `unsafeWindow`. Storage and network GM functions are not available.',
          '**Sandbox mode** (when you grant `GM_getValue`, `GM_setValue`, `GM_xmlhttpRequest`, `GM_notification`, `GM_openInTab` or `GM_download`): the script sees the page DOM but not the site\'s JavaScript variables.',
          'Rule of thumb: need the site\'s variables? Use `@grant none`. Need to save data or call another website? Grant the GM functions.'
        ]
      },
      {
        h: '4. Available GM functions',
        def: [
          ['GM_getValue(key, default)\nGM_setValue(key, value)\nGM_deleteValue(key)\nGM_listValues()', 'Permanent storage for this script (survives reloads). Bulk versions: `GM_getValues`, `GM_setValues`, `GM_deleteValues`.'],
          ['GM_xmlhttpRequest({ method, url, headers, data, responseType, timeout, onload, onerror })', 'Request to ANY website, without CORS limits. The answer arrives in `onload` with `status` and `responseText`.'],
          ['GM_addStyle(css)', 'Add CSS to the page.'],
          ['GM_addElement(tag, attrs)', 'Create an element in the page.'],
          ['GM_setClipboard(text)', 'Copy text to the clipboard.'],
          ['GM_registerMenuCommand(name, fn)', 'A menu entry: a small \u{1F9E9} button appears at the bottom-right of the page.'],
          ['GM_notification / GM_openInTab / GM_download', 'System notification / open a tab / download a file.'],
          ['GM_getResourceText / GM_getResourceURL / GM_log / GM_info', 'Read @resource files / log to the console / info about the script.'],
          ['GM.getValue, GM.setValue, ...', 'Promise versions (use with `await`) of all functions above.'],
          ['', 'Only the functions you list in `@grant` are defined.']
        ]
      },
      {
        h: '5. Good to know', wide: true,
        ul: [
          'A script runs once per page load. On single-page sites (YouTube, X, ...) that change content without reloading, use a `MutationObserver`.',
          'It runs in every frame of the page unless you add `@noframes`.',
          'There are no restrictions on the code (no content filter, no size limit). Corsair does not scan or block your code, so only install scripts you trust.',
          'It also works on sites with a strict Content-Security-Policy (such as GitHub).',
          'Your code is wrapped in an async function, so top-level `await` and `return` work and you do not need your own IIFE.',
          'Errors appear in the page\'s DevTools console (F12) prefixed with `[Corsair Userscripts]`.',
          'Automatic updates from `@updateURL` are not available yet: to update a script, import its URL again.',
          'Backups include your scripts, their saved values and (optionally) your API keys.'
        ]
      }
    ],
    promptIntro: 'To get a correct, ready-to-use script from an AI (ChatGPT, Claude, ...), always tell it:',
    promptChecklist: [
      'The exact site address or pattern (e.g. `https://example.com/*`).',
      'What the script must do, in plain and precise words.',
      'The HTML of the relevant part of the page, or the CSS selectors (in the browser: right-click the element > Inspect > right-click its line > Copy > Copy outerHTML).',
      'When it should run (on page open, after full load, on a button click).',
      'Whether data must be remembered between visits.',
      'Whether it must call another website, and which domain.',
      'Whether the site is a single-page app that changes content after loading.'
    ],
    promptLabel: 'Ready-made prompt (copy it and fill in the <...> parts):',
    copy: 'Copy prompt',
    copied: 'Copied \u2713',
    prompt: [
      'Write ONE complete userscript for Corsair Unbound (Tampermonkey-compatible, Chrome, Manifest V3, built on chrome.userScripts).',
      '',
      'GOAL: <describe exactly what the script must do, in plain words>',
      'TARGET SITE(S): <full URLs or patterns, e.g. https://example.com/*>',
      'PAGE DETAILS: <paste the relevant HTML, or the CSS selectors / element texts the script must find>',
      'RUN WHEN: <on page open / after the page fully loaded / as early as possible>',
      'NEEDS DATA SAVED BETWEEN VISITS: <yes/no - what>',
      'NEEDS REQUESTS TO OTHER WEBSITES: <yes/no - which domains>',
      '',
      'RULES:',
      '1. Output exactly one .user.js file in a single code block. It must start with a // ==UserScript== header that ends with // ==/UserScript==, followed by the code.',
      '2. The header must contain @name, @namespace, @version, @description, one or more exact @match lines (do not guess the pattern) and @grant.',
      '3. Use "@grant none" when no GM_ function is needed (the script then runs inside the page and can use window variables). Otherwise list ONLY the GM_ functions you really use (e.g. GM_getValue, GM_setValue, GM_xmlhttpRequest, GM_addStyle). Never call a GM_ function that is not granted.',
      '4. Use GM_xmlhttpRequest (not fetch/XHR) for requests to other domains, and GM_getValue/GM_setValue (not localStorage) for data that must survive page reloads.',
      '5. The script runs once per page load. If the site is a single-page app or loads content late, use a MutationObserver (or a short interval) and make the code safe to run several times (mark processed elements).',
      '6. When you use GM_ functions the script runs in an isolated world, so do not rely on the site\'s JavaScript variables. If you need them, use "@grant none" instead.',
      '7. The code is wrapped in an async function: top-level await and return are allowed, and you do not need your own IIFE.',
      '8. Do not use external libraries unless really necessary; if you do, use @require with a pinned-version URL.',
      '9. Add short comments, handle missing elements gracefully, and at the end tell me which @match and @grant lines you chose and why.'
    ].join('\n')
  },

  fa: {
    title: '\u{1F4D8} راهنمای اسکریپت‌ها',
    subtitle: 'هرچه خودتان یا یک هوش مصنوعی برای نوشتن اسکریپتِ درست و کارا باید بداند.',
    tabHow: 'سیستم چطور کار می‌کند',
    tabPrompt: 'پرامپت برای هوش مصنوعی',
    cards: [
      {
        h: '۱. اسکریپت کاربر چیست؟', wide: true,
        p: [
          'اسکریپت کاربر (Userscript) یک فایل جاوااسکریپت کوچک است که اولش یک «هدر» دارد؛ یعنی چند خط به شکل `// @کلید مقدار`. Corsair Unbound این فایل را خودکار داخل هر صفحه‌ای که با هدر جور باشد اجرا می‌کند، دقیقاً مثل Tampermonkey.',
          'به Chrome نسخه‌ی ۱۲۰ یا بالاتر نیاز دارد و باید یک بار در `chrome://extensions` ← جزئیات اکستنشن، گزینه‌ی «Allow User Scripts» را روشن کنید. اگر خاموش باشد، بالای لیست اسکریپت‌ها یک هشدار نشان داده می‌شود.'
        ]
      },
      {
        h: '۲. هدر (اطلاعات اسکریپت)', wide: true,
        def: [
          ['@name', 'اسم اسکریپت؛ لازم است و در لیست نشان داده می‌شود.'],
          ['@match', 'اسکریپت روی کدام صفحه‌ها اجرا شود. برای چند سایت چند خط بنویسید. `https://example.com/*` یعنی فقط همان سایت، `*://*.example.com/*` یعنی سایت و همه‌ی زیردامنه‌ها، `<all_urls>` یعنی همه‌جا. اگر هیچ @match یا @include نباشد اسکریپت هیچ‌جا اجرا نمی‌شود.'],
          ['@exclude / @exclude-match', 'صفحه‌هایی که باید نادیده گرفته شوند.'],
          ['@include', 'مثل @match ولی با ستاره (`*`) و علامت سؤال (`?`)، یا یک عبارت منظم بین دو اسلش، مثل `/^https:\\/\\/a\\.com\\/.*$/`.'],
          ['@run-at', 'زمان اجرا: `document-start` (زودترین)، `document-body`، `document-end`، `document-idle` (پیش‌فرض؛ بعد از لود صفحه).'],
          ['@grant', 'اجازه‌ی استفاده از توابع GM_ . مقدار `none` یعنی هیچ‌کدام.'],
          ['@require', 'آدرس یک کتابخانه. یک بار دانلود و ذخیره می‌شود و قبل از کد شما اجرا می‌شود (آدرسی با نسخه‌ی مشخص بدهید).'],
          ['@resource', 'یک فایل کمکی (CSS، متن، تصویر) با فرمت `@resource اسم آدرس` که با `GM_getResourceText` یا `GM_getResourceURL` خوانده می‌شود.'],
          ['@noframes', 'فقط در صفحه‌ی اصلی اجرا شود، نه داخل iframeها.'],
          ['@inject-into', '`page` یا `content`: حالت اجرا را اجباری می‌کند (بخش بعد را ببینید).'],
          ['@version, @description, @namespace, @author', 'اطلاعات توضیحی. اگر اسکریپتی با همان @name و @namespace (یا از همان لینک) دوباره وارد شود، اسکریپت قبلی به‌روز می‌شود و نسخه‌ی تکراری ساخته نمی‌شود.']
        ]
      },
      {
        h: '۳. دو حالت اجرا: داخل صفحه یا ایزوله',
        ul: [
          '**حالت صفحه** (`@grant none` یا فقط توابع کمکیِ محلی مثل `GM_addStyle`): اسکریپت داخل خود صفحه اجرا می‌شود و می‌تواند متغیرهای جاوااسکریپتِ خودِ سایت را با `window` / `unsafeWindow` بخواند. توابع ذخیره‌سازی و شبکه‌ی GM در دسترس نیستند.',
          '**حالت ایزوله (sandbox)** وقتی یکی از `GM_getValue`، `GM_setValue`، `GM_xmlhttpRequest`، `GM_notification`، `GM_openInTab` یا `GM_download` را grant کنید: اسکریپت DOM صفحه را می‌بیند ولی به متغیرهای جاوااسکریپتِ سایت دسترسی ندارد.',
          'قاعده‌ی سرانگشتی: اگر به متغیرهای خودِ سایت نیاز دارید `@grant none` بگذارید؛ اگر باید اطلاعات ذخیره کنید یا به سایت دیگری درخواست بزنید، توابع GM را grant کنید.'
        ]
      },
      {
        h: '۴. توابع GM قابل استفاده',
        def: [
          ['GM_getValue(key, default)\nGM_setValue(key, value)\nGM_deleteValue(key)\nGM_listValues()', 'ذخیره‌ی دائمی اطلاعات برای همین اسکریپت (با رفرش از بین نمی‌رود). نسخه‌های گروهی: `GM_getValues`، `GM_setValues`، `GM_deleteValues`.'],
          ['GM_xmlhttpRequest({ method, url, headers, data, responseType, timeout, onload, onerror })', 'درخواست به هر سایت دیگری، بدون محدودیت CORS. جواب در `onload` با `status` و `responseText` می‌آید.'],
          ['GM_addStyle(css)', 'اضافه کردن CSS به صفحه.'],
          ['GM_addElement(tag, attrs)', 'ساختن یک المنت در صفحه.'],
          ['GM_setClipboard(text)', 'کپی متن در کلیپ‌بورد.'],
          ['GM_registerMenuCommand(name, fn)', 'یک گزینه‌ی منو؛ گوشه‌ی پایین-راست صفحه یک دکمه‌ی کوچک \u{1F9E9} ظاهر می‌شود.'],
          ['GM_notification / GM_openInTab / GM_download', 'اعلان سیستم / باز کردن تب / دانلود فایل.'],
          ['GM_getResourceText / GM_getResourceURL / GM_log / GM_info', 'خواندن فایل‌های @resource / لاگ در کنسول / اطلاعات خود اسکریپت.'],
          ['GM.getValue, GM.setValue, ...', 'نسخه‌ی Promise (با `await`) همه‌ی توابع بالا.'],
          ['', 'فقط توابعی که در `@grant` نوشته‌اید تعریف می‌شوند.']
        ]
      },
      {
        h: '۵. نکته‌های مهم', wide: true,
        ul: [
          'اسکریپت در هر بار بارگذاری صفحه فقط یک بار اجرا می‌شود. در سایت‌های تک‌صفحه‌ای (مثل یوتیوب و X) که محتوا بدون رفرش عوض می‌شود، از `MutationObserver` استفاده کنید.',
          'اسکریپت در همه‌ی فریم‌های صفحه اجرا می‌شود، مگر اینکه `@noframes` بگذارید.',
          'هیچ محدودیتی روی کد وجود ندارد (نه فیلتر محتوا، نه سقف حجم). Corsair کد شما را بررسی یا مسدود نمی‌کند؛ پس فقط اسکریپتی را نصب کنید که به آن اعتماد دارید.',
          'روی سایت‌هایی که Content-Security-Policy سخت‌گیرانه دارند (مثل GitHub) هم کار می‌کند.',
          'کد شما داخل یک تابع async قرار می‌گیرد؛ پس `await` و `return` در سطح بالا مجازند و نیازی به IIFE نیست.',
          'خطاها در کنسول صفحه (کلید F12) با پیشوند `[Corsair Userscripts]` نمایش داده می‌شوند.',
          'به‌روزرسانی خودکار از `@updateURL` هنوز وجود ندارد؛ برای آپدیت، همان لینک را دوباره Import کنید.',
          'اسکریپت‌ها، مقدارهای ذخیره‌شده‌شان و (در صورت انتخاب) کلیدهای API داخل بکاپ تنظیمات هم قرار می‌گیرند.'
        ]
      }
    ],
    promptIntro: 'برای اینکه هوش مصنوعی (ChatGPT، Claude و ...) اسکریپتِ درست و آماده‌ی استفاده بنویسد، این موارد را حتماً به او بگویید:',
    promptChecklist: [
      'آدرس دقیق سایت یا الگوی آدرس (مثلاً `https://example.com/*`).',
      'کار مورد نظر را ساده و دقیق توضیح دهید.',
      'کد HTML همان بخش از صفحه یا سلکتورهای CSS (در مرورگر روی المنت راست‌کلیک ← Inspect ← روی خط راست‌کلیک ← Copy ← Copy outerHTML).',
      'چه زمانی اجرا شود (با باز شدن صفحه، بعد از لود کامل، یا با کلیک روی یک دکمه).',
      'آیا اطلاعاتی باید بین دفعات بازدید ذخیره بماند؟',
      'آیا باید به سایت دیگری درخواست بزند؟ کدام دامنه؟',
      'آیا سایت تک‌صفحه‌ای است و محتوا بعد از لود عوض می‌شود؟'
    ],
    promptLabel: 'پرامپت آماده (کپی کنید و قسمت‌های <...> را پر کنید):',
    copy: 'کپی پرامپت',
    copied: 'کپی شد \u2713',
    prompt: [
      'یک اسکریپت کاربر (Userscript) کامل برای Corsair Unbound بنویس (سازگار با Tampermonkey، مرورگر Chrome، Manifest V3 با chrome.userScripts). توضیح‌هایت فارسی باشد ولی کد و کامنت‌ها انگلیسی.',
      '',
      'هدف: <دقیقاً توضیح بده اسکریپت چه کاری باید بکند>',
      'سایت(های) هدف: <آدرس کامل یا الگو، مثلاً https://example.com/*>',
      'جزئیات صفحه: <HTML بخش مورد نظر، یا سلکتورهای CSS / متن المنت‌هایی که باید پیدا شوند>',
      'زمان اجرا: <با باز شدن صفحه / بعد از لود کامل / در زودترین زمان ممکن>',
      'نیاز به ذخیره‌ی اطلاعات بین دفعات بازدید: <بله/خیر - چه اطلاعاتی>',
      'نیاز به درخواست به سایت‌های دیگر: <بله/خیر - کدام دامنه‌ها>',
      '',
      'قوانین:',
      '۱. خروجی دقیقاً یک فایل .user.js کامل داخل یک بلوک کد باشد. با هدر // ==UserScript== شروع شود، با // ==/UserScript== تمام شود و بعد از آن کد بیاید.',
      '۲. هدر باید شامل @name، @namespace، @version، @description، یک یا چند خط @match دقیق (الگو را حدس نزن) و @grant باشد.',
      '۳. اگر به هیچ تابع GM_ نیاز نیست @grant none بگذار (اسکریپت داخل خود صفحه اجرا می‌شود و به متغیرهای window دسترسی دارد). در غیر این صورت فقط توابع GM_ ای را که واقعاً استفاده می‌کنی بنویس (مثل GM_getValue، GM_setValue، GM_xmlhttpRequest، GM_addStyle). هرگز تابعی را که grant نشده صدا نزن.',
      '۴. برای درخواست به دامنه‌های دیگر از GM_xmlhttpRequest استفاده کن (نه fetch/XHR) و برای داده‌ای که باید بعد از رفرش بماند از GM_getValue/GM_setValue (نه localStorage).',
      '۵. اسکریپت در هر بار لود صفحه فقط یک بار اجرا می‌شود. اگر سایت تک‌صفحه‌ای است یا محتوا دیر لود می‌شود، از MutationObserver (یا یک interval کوتاه) استفاده کن و کد را طوری بنویس که چندبار اجرا شدن مشکلی ایجاد نکند (المنت‌های پردازش‌شده را علامت بزن).',
      '۶. وقتی از توابع GM_ استفاده می‌کنی اسکریپت در محیط ایزوله اجرا می‌شود؛ پس به متغیرهای جاوااسکریپتِ خودِ سایت تکیه نکن. اگر به آن‌ها نیاز داری به‌جایش @grant none بگذار.',
      '۷. کد داخل یک تابع async قرار می‌گیرد: await و return در سطح بالا مجاز است و IIFE لازم نیست.',
      '۸. از کتابخانه‌ی خارجی استفاده نکن مگر واقعاً لازم باشد؛ در آن صورت از @require با آدرسِ نسخه‌ی مشخص استفاده کن.',
      '۹. کامنت‌های کوتاه بنویس، نبودنِ المنت‌ها را بدون خطا مدیریت کن، و در آخر بگو چه @match و @grant ای انتخاب کردی و چرا.'
    ].join('\n')
  }
};

/** `code` and **bold** inline markup -> safe DOM nodes. */
function usRich(parent, str) {
  String(str).split('**').forEach((boldPart, bi) => {
    const host = bi % 2 ? parent.appendChild(document.createElement('strong')) : parent;
    boldPart.split('`').forEach((part, ci) => {
      if (!part) return;
      if (ci % 2) { const c = document.createElement('code'); c.textContent = part; host.appendChild(c); }
      else host.appendChild(document.createTextNode(part));
    });
  });
}

function renderUserscriptGuide() {
  const box = $('usGuide');
  if (!box) return;
  const lang = state.guideLang || (isFaUi() ? 'fa' : 'en');
  const g = US_GUIDE[lang];

  const setText = (id, txt) => { const el = $(id); if (el) el.textContent = txt; };
  setText('usGuideTitle', g.title);
  setText('usGuideSubtitle', g.subtitle);
  setText('usTabHow', g.tabHow);
  setText('usTabPrompt', g.tabPrompt);
  document.querySelectorAll('[data-guide-lang]').forEach(b => b.classList.toggle('active', b.dataset.guideLang === lang));
  document.querySelectorAll('[data-guide-tab]').forEach(b => b.classList.toggle('active', b.dataset.guideTab === state.guideTab));

  box.dir = lang === 'fa' ? 'rtl' : 'ltr';
  box.lang = lang;
  box.textContent = '';

  if (state.guideTab === 'prompt') {
    const intro = document.createElement('p');
    usRich(intro, g.promptIntro);
    box.appendChild(intro);

    const ul = document.createElement('ul');
    ul.className = 'us-list';
    g.promptChecklist.forEach(item => { const li = document.createElement('li'); usRich(li, item); ul.appendChild(li); });
    box.appendChild(ul);

    const bar = document.createElement('div');
    bar.className = 'us-prompt-bar';
    bar.style.marginTop = '16px';
    const label = document.createElement('strong');
    label.textContent = g.promptLabel;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn-primary';
    btn.textContent = g.copy;
    btn.addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(g.prompt); }
      catch {
        const ta = document.createElement('textarea');
        ta.value = g.prompt; document.body.appendChild(ta); ta.select();
        try { document.execCommand('copy'); } catch {}
        ta.remove();
      }
      btn.textContent = g.copied;
      setTimeout(() => { btn.textContent = g.copy; }, 1800);
    });
    bar.append(label, btn);
    box.appendChild(bar);

    const pre = document.createElement('pre');
    pre.className = 'us-prompt' + (lang === 'fa' ? ' fa' : '');
    pre.dir = lang === 'fa' ? 'rtl' : 'ltr';
    pre.textContent = g.prompt;
    box.appendChild(pre);
    return;
  }

  const grid = document.createElement('div');
  grid.className = 'us-guide-grid';
  for (const card of g.cards) {
    const el = document.createElement('div');
    el.className = 'us-card' + (card.wide ? ' wide' : '');
    const h = document.createElement('h3');
    h.textContent = card.h;
    el.appendChild(h);
    (card.p || []).forEach(txt => { const p = document.createElement('p'); usRich(p, txt); el.appendChild(p); });
    if (card.ul) {
      const ul = document.createElement('ul');
      ul.className = 'us-list';
      card.ul.forEach(txt => { const li = document.createElement('li'); usRich(li, txt); ul.appendChild(li); });
      el.appendChild(ul);
    }
    if (card.def) {
      const dl = document.createElement('dl');
      dl.className = 'us-def';
      card.def.forEach(([k, v]) => {
        const dt = document.createElement('dt');
        dt.textContent = k;
        dt.style.whiteSpace = 'pre-line';
        const dd = document.createElement('dd');
        usRich(dd, v);
        dl.append(dt, dd);
      });
      el.appendChild(dl);
    }
    grid.appendChild(el);
  }
  box.appendChild(grid);
}

const USERSCRIPT_TEMPLATE = [
  '// ==UserScript==',
  '// @name         New Script',
  '// @namespace    https://corsair.local/',
  '// @version      0.1',
  '// @description  Describe what this script does',
  '// @match        https://example.com/*',
  '// @grant        none',
  '// @run-at       document-idle',
  '// ==/UserScript==',
  '',
  '(function () {',
  "  'use strict';",
  '',
  '  // Your code here',
  '})();',
  ''
].join('\n');

const USERSCRIPT_DEMOS = {
  hello: [
    '// ==UserScript==',
    '// @name         Demo 1: Hello banner',
    '// @namespace    https://corsair.local/demo',
    '// @version      1.0',
    '// @description  Shows a purple banner on example.com to prove userscripts work',
    '// @match        https://example.com/*',
    '// @grant        none',
    '// ==/UserScript==',
    '',
    "const bar = document.createElement('div');",
    "bar.textContent = '✅ Corsair userscripts are working!';",
    "bar.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:2147483647;padding:10px;text-align:center;background:#6d28d9;color:#fff;font:600 15px system-ui';",
    'document.documentElement.appendChild(bar);',
    ''
  ].join('\n'),
  counter: [
    '// ==UserScript==',
    '// @name         Demo 2: Visit counter',
    '// @namespace    https://corsair.local/demo',
    '// @version      1.0',
    '// @description  Counts your visits with GM_setValue and adds a menu command',
    '// @match        https://example.com/*',
    '// @grant        GM_getValue',
    '// @grant        GM_setValue',
    '// @grant        GM_addStyle',
    '// @grant        GM_registerMenuCommand',
    '// ==/UserScript==',
    '',
    "const visits = GM_getValue('visits', 0) + 1;",
    "GM_setValue('visits', visits);",
    "GM_addStyle('#cu-visits{position:fixed;top:56px;left:12px;z-index:2147483647;padding:8px 12px;border-radius:8px;background:#111;color:#fff;font:14px system-ui}');",
    "const el = document.createElement('div');",
    "el.id = 'cu-visits';",
    "el.textContent = 'Visit #' + visits + ' (saved between page loads)';",
    'document.body.appendChild(el);',
    "GM_registerMenuCommand('Reset counter', () => { GM_setValue('visits', 0); el.textContent = 'Counter reset'; });",
    ''
  ].join('\n'),
  xhr: [
    '// ==UserScript==',
    '// @name         Demo 3: Cross-site request',
    '// @namespace    https://corsair.local/demo',
    '// @version      1.0',
    '// @description  Calls another website with GM_xmlhttpRequest (no CORS limits)',
    '// @match        https://example.com/*',
    '// @grant        GM_xmlhttpRequest',
    '// @connect      api.github.com',
    '// ==/UserScript==',
    '',
    "const box = document.createElement('div');",
    "box.style.cssText = 'position:fixed;bottom:0;left:0;right:0;z-index:2147483647;padding:10px;text-align:center;background:#065f46;color:#fff;font:15px system-ui';",
    "box.textContent = 'Loading from api.github.com…';",
    'document.documentElement.appendChild(box);',
    'GM_xmlhttpRequest({',
    "  method: 'GET',",
    "  url: 'https://api.github.com/zen',",
    "  onload: (r) => { box.textContent = 'GitHub says: ' + r.responseText; },",
    "  onerror: () => { box.textContent = 'Request failed'; box.style.background = '#991b1b'; }",
    '});',
    ''
  ].join('\n')
};

async function installUserscriptDemo(key) {
  const code = USERSCRIPT_DEMOS[key];
  if (!code) return;
  const res = await send({ type: 'us-save', code });
  if (reportSaveResult(res)) {
    showToast('Demo installed. Now open example.com in a new tab.');
    await refresh();
  }
}

function renderUserscriptStatus() {
  const el = $('usStatus');
  if (!el) return;
  const av = state.userscriptAvailability;
  if (!av || av.ok) { el.hidden = true; el.textContent = ''; return; }

  el.hidden = false;
  el.textContent = '';
  const title = document.createElement('strong');
  const body = document.createElement('div');

  if (av.code === 'old-chrome') {
    title.textContent = '⚠️ Chrome is too old for userscripts';
    body.textContent = 'Userscripts need Chrome 120 or newer. Please update Chrome.';
    el.append(title, body);
    return;
  }

  title.textContent = '⚠️ One-time setup needed: allow user scripts';
  const ol = document.createElement('ol');
  [
    'Open chrome://extensions and click "Details" on Corsair Unbound.',
    'Turn on "Allow User Scripts". (On Chrome 137 or older, turn on "Developer mode" at the top right instead.)',
    'Come back here and reload this page.'
  ].forEach(txt => { const li = document.createElement('li'); li.textContent = txt; ol.appendChild(li); });

  const btn = document.createElement('button');
  btn.className = 'tool-btn';
  btn.type = 'button';
  btn.textContent = 'Open extension settings';
  btn.addEventListener('click', () => {
    const id = state.extensionId || (chrome.runtime && chrome.runtime.id) || '';
    chrome.tabs.create({ url: 'chrome://extensions/?id=' + id });
  });
  el.append(title, ol, btn);
}

/** Turn @match/@include rules into short, de-duplicated domain labels. */
function usTargetDomains(patterns) {
  const out = [];
  const seen = new Set();
  const add = (label, kind) => { if (!seen.has(label)) { seen.add(label); out.push({ label, kind }); } };
  for (const raw of patterns || []) {
    const p = String(raw || '').trim();
    if (!p) continue;
    if (p === '<all_urls>' || p === '*') { add('All sites', 'all'); continue; }
    if (/^\/.+\/[a-z]*$/.test(p)) { add('Custom regex', 'regex'); continue; }
    const m = /^([a-z*]+):\/\/([^/]*)/i.exec(p.replace(/^http\*:/i, '*:'));
    if (!m) { add(p.length > 26 ? p.slice(0, 25) + '…' : p, 'other'); continue; }
    if (m[1].toLowerCase() === 'file') { add('Local files', 'other'); continue; }
    let host = m[2].toLowerCase();
    if (host === '*' || host === '') { add('All sites', 'all'); continue; }
    host = host.replace(/^\*\./, '');
    add(host, 'domain');
  }
  return out;
}

function usDomainHue(label) {
  let h = 0;
  for (let i = 0; i < label.length; i++) h = (h * 31 + label.charCodeAt(i)) >>> 0;
  return h % 360;
}

function usBuildDomainChips(item) {
  const wrap = document.createElement('div');
  wrap.className = 'script-domains';
  const domains = usTargetDomains(item.matches);
  if (!domains.length) return wrap;

  const MAX = 3;
  domains.slice(0, MAX).forEach(d => {
    const chip = document.createElement('span');
    chip.className = 'domain-chip' + (d.kind === 'domain' ? '' : ' ' + d.kind);
    if (d.kind === 'domain') chip.style.setProperty('--h', String(usDomainHue(d.label)));
    chip.title = d.label;
    const dot = document.createElement('span');
    dot.className = 'dot';
    const label = document.createElement('span');
    label.className = 'label';
    label.textContent = d.label;
    chip.append(dot, label);
    wrap.appendChild(chip);
  });
  if (domains.length > MAX) {
    const more = document.createElement('span');
    more.className = 'domain-chip more';
    more.textContent = '+' + (domains.length - MAX);
    more.title = domains.slice(MAX).map(d => d.label).join('\n');
    wrap.appendChild(more);
  }
  return wrap;
}

function renderCustomScripts() {
  const box = $('scriptList');
  if (!box) return;
  box.innerHTML = '';
  renderUserscriptStatus();

  const total = state.customScripts.length;
  const countEl = $('scriptCount');

  if (!total) {
    if (countEl) countEl.textContent = '';
    box.innerHTML = '<div class="empty">No userscripts yet. Click "New script" or import one from a URL or file.</div>';
    return;
  }

  const q = (state.scriptQuery || '').trim().toLowerCase();
  const sorted = [...state.customScripts].sort((a, b) => String(a.name).localeCompare(String(b.name), undefined, { sensitivity: 'base' }));
  const visible = sorted.filter(item => {
    if (!q) return true;
    const hay = [item.name, item.description, ...usTargetDomains(item.matches).map(d => d.label)].join(' ').toLowerCase();
    return hay.includes(q);
  });

  if (countEl) countEl.textContent = q ? `${visible.length} / ${total}` : `${total} script${total === 1 ? '' : 's'}`;

  if (!visible.length) {
    box.innerHTML = '<div class="empty">No scripts match your search.</div>';
    return;
  }

  let flashEl = null;

  for (const item of visible) {
    const enabled = item.enabled !== false;
    const row = document.createElement('div');
    row.className = 'script-item' + (enabled ? '' : ' disabled');
    row.dataset.id = item.id;
    if (state.highlightScriptId && state.highlightScriptId === item.id) flashEl = row;

    const head = document.createElement('div');
    head.className = 'script-item-head';

    const left = document.createElement('div');
    left.className = 'script-main';
    const title = document.createElement('div');
    title.className = 'script-host';
    title.textContent = item.name + (item.version ? '  v' + item.version : '');
    const meta = document.createElement('div');
    meta.className = 'script-meta';
    const world = item.world === 'MAIN' ? 'page' : 'sandbox';
    meta.textContent = [
      item.description || '',
      `${item.lines} lines`,
      item.runAt,
      world,
      item.sourceUrl ? 'from URL' : (item.migratedFrom ? 'migrated' : 'local')
    ].filter(Boolean).join(' • ');
    left.append(title, meta);

    if (item.noMatch) {
      const warn = document.createElement('div');
      warn.className = 'script-warn';
      warn.textContent = 'No @match or @include in the header: this script will not run anywhere yet.';
      left.appendChild(warn);
    }
    if (item.lastError) {
      const warn = document.createElement('div');
      warn.className = 'script-warn';
      warn.textContent = 'Registration error: ' + item.lastError;
      left.appendChild(warn);
    }

    const actions = document.createElement('div');
    actions.className = 'script-actions';

    const toggleLabel = document.createElement('label');
    toggleLabel.className = 'script-toggle';
    const toggle = document.createElement('input');
    toggle.type = 'checkbox';
    toggle.checked = enabled;
    toggle.addEventListener('change', async () => {
      const res = await send({ type: 'us-toggle', id: item.id, enabled: toggle.checked });
      if (res?.ok) {
        item.enabled = toggle.checked;
        row.classList.toggle('disabled', !toggle.checked);
        showToast(`${item.name}: ${toggle.checked ? 'enabled' : 'disabled'}`);
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
    editBtn.addEventListener('click', () => openEditor(item.id));

    const delBtn = document.createElement('button');
    delBtn.className = 'btn-script-remove';
    delBtn.textContent = t('scripts.remove', 'Remove');
    delBtn.addEventListener('click', async () => {
      if (!confirm(t('scripts.confirmRemove', 'Remove this script? This cannot be undone.'))) return;
      const res = await send({ type: 'us-remove', id: item.id });
      if (res?.ok) { showToast(`Removed ${item.name}`); await refresh(); }
      else showToast(res?.error || 'Failed', 'error');
    });

    actions.append(toggleLabel, editBtn, delBtn);

    const side = document.createElement('div');
    side.className = 'script-side';
    side.append(usBuildDomainChips(item), actions);

    head.append(left, side);
    row.appendChild(head);

    const preview = document.createElement('div');
    preview.className = 'script-preview';
    const shown = (item.matches || []).slice(0, 4);
    preview.textContent = shown.length
      ? shown.join('\n') + ((item.matches || []).length > 4 ? `\n… +${item.matches.length - 4} more` : '')
      : '(no match rules)';
    preview.addEventListener('click', () => openEditor(item.id));
    row.appendChild(preview);

    box.appendChild(row);
  }

  // Bring a just-saved script into view (the list is alphabetical and scrollable)
  if (flashEl) {
    state.highlightScriptId = '';
    flashEl.classList.add('flash');
    setTimeout(() => { try { flashEl.scrollIntoView({ block: 'nearest', behavior: 'smooth' }); } catch {} }, 30);
  }
}

function reportSaveResult(res, fallbackName) {
  if (!res?.ok) { showToast(res?.error || 'Failed to save', 'error'); return false; }
  const name = res.script?.name || fallbackName || 'script';
  if (res.script?.id) state.highlightScriptId = res.script.id;
  if (res.sync && res.sync.ok === false) {
    showToast(`Saved "${name}", but it is not active yet: allow user scripts for this extension (see the notice above).`, 'error');
  } else if (res.sync?.errors?.length) {
    showToast(`Saved "${name}" with an error: ${res.sync.errors[0].error}`, 'error');
  } else if (res.warnings?.length) {
    showToast(`Saved "${name}". ${res.warnings[0]}`, 'error');
  } else {
    showToast(`Saved "${name}"`);
  }
  return true;
}

async function importUserscriptFromUrl() {
  const input = $('scriptImportUrl');
  const url = (input?.value || '').trim();
  if (!url) { showToast('Paste a script URL first', 'error'); return; }
  const res = await send({ type: 'us-import-url', url });
  if (reportSaveResult(res)) { input.value = ''; await refresh(); }
}

async function importUserscriptFiles(files) {
  for (const file of Array.from(files || [])) {
    try {
      const code = await file.text();
      const res = await send({ type: 'us-save', code });
      reportSaveResult(res, file.name);
    } catch (e) {
      showToast(`Could not read ${file.name}`, 'error');
    }
  }
  await refresh();
}

/* ============================================================
   CODE EDITOR
   ============================================================ */
async function openEditor(id) {
  let code = USERSCRIPT_TEMPLATE;
  let name = 'New script';
  if (id) {
    const res = await send({ type: 'us-get', id });
    if (!res?.ok || !res.script) { showToast(res?.error || 'Script not found', 'error'); return; }
    code = res.script.code || '';
    name = res.script.name;
  }

  state.editingScript = { id: id || null, code, originalCode: code, isNew: !id };
  const modal = $('editorModal');
  if (!modal) return;

  const hostEl = $('editorHost');
  const fileEl = $('editorFilename');
  const ta = $('editorCode');
  const tab = $('editorTab');

  if (hostEl) hostEl.textContent = name;
  if (fileEl) fileEl.textContent = name.replace(/[^a-z0-9.-]/gi, '_') + '.user.js';
  if (ta) { ta.value = code; ta.focus(); }
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

function isEditorDirty() {
  const ta = $('editorCode');
  return !!(state.editingScript && ta && ta.value !== state.editingScript.originalCode);
}

/** User-initiated close (X button, backdrop click, Esc): never lose unsaved code silently. */
function requestCloseEditor() {
  if (isEditorDirty() && !confirm(t('scripts.discard', 'You have unsaved changes. Discard them?'))) return;
  closeEditor();
}

async function saveEditor() {
  if (!state.editingScript) return;
  const ta = $('editorCode');
  const code = ta ? ta.value : '';

  const res = await send({
    type: 'us-save',
    id: state.editingScript.id || undefined,
    code
  });

  if (reportSaveResult(res)) {
    closeEditor();
    await refresh();
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
    // insertText keeps the browser's undo history (Ctrl+Z) intact
    let done = false;
    try { done = document.execCommand('insertText', false, '  '); } catch {}
    if (!done) {
      const start = ta.selectionStart;
      const end = ta.selectionEnd;
      ta.value = ta.value.substring(0, start) + '  ' + ta.value.substring(end);
      ta.selectionStart = ta.selectionEnd = start + 2;
    }
    updateLineNumbers();
  }
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') {
    e.preventDefault();
    saveEditor();
  }
  if (e.key === 'Escape') {
    e.preventDefault();
    requestCloseEditor();
  }
});

safeOn('editorCode', 'input', () => {
  updateLineNumbers();
  const tab = $('editorTab');
  if (tab && state.editingScript) tab.classList.toggle('dirty', isEditorDirty());
});

safeOn('editorCode', 'scroll', () => {
  const ta = $('editorCode');
  const gutter = $('editorGutter');
  if (ta && gutter) gutter.scrollTop = ta.scrollTop;
});

safeOn('editorSave', 'click', saveEditor);
safeOn('editorClose', 'click', requestCloseEditor);

safeOn('editorModal', 'click', (e) => {
  if (e.target && e.target.id === 'editorModal') requestCloseEditor();
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

  const persistToggle = $('persistApiKeyToggle');
  if (persistToggle) {
    persistToggle.checked = state.settings.persistApiKey !== false;
  }

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

async function renderApiKeyWarning() {
  const warnEl = $('apiKeyMissingWarning');
  if (!warnEl) return;
  try {
    const r = await send({ type: 'get-api-key-status' });
    if (r?.ok && r.status?.shouldWarn === true) {
      warnEl.hidden = false;
    } else {
      warnEl.hidden = true;
    }
  } catch {
    warnEl.hidden = true;
  }
}

safeOn('apiKeyToggle', 'click', () => {
  const field = $('vtApiKeyField');
  if (!field) return;

  const currentValue = field.value;
  const wasMasked = /^•+$/.test(currentValue);

  state.apiKeyVisible = !state.apiKeyVisible;
  field.type = state.apiKeyVisible ? 'text' : 'password';

  if (state.apiKeyVisible && wasMasked && state.currentApiKey) {
    field.value = state.currentApiKey;
  } else if (!state.apiKeyVisible && currentValue === state.currentApiKey && state.currentApiKey) {
    field.value = '•'.repeat(Math.min(64, state.currentApiKey.length));
  }
});

safeOn('persistApiKeyToggle', 'change', async () => {
  const cb = $('persistApiKeyToggle');
  if (!cb) return;
  try {
    await send({ type: 'patch-settings', patch: { persistApiKey: cb.checked } });
    showToast(cb.checked
      ? t('api.persistOn', 'API key will be kept after browser restart.')
      : t('api.persistOff', 'API key will be cleared when the browser closes.'));
  } catch {
    cb.checked = !cb.checked;
    showToast('Failed to save preference', 'error');
  }
});

safeOn('apiKeySave', 'click', async () => {
  const field = $('vtApiKeyField');
  if (!field) return;

  const rawValue = field.value.trim();
  const isMasked = /^•+$/.test(rawValue);

  if (!rawValue) {
    try {
      await send({ type: 'set-api-key-secure', apiKey: '' });
      state.currentApiKey = '';
      state.apiKeyVisible = false;
      renderApiStatus();
      showToast(t('api.cleared', 'API key cleared.'));
    } catch (err) {
      showToast(err.message || 'Failed', 'error');
    }
    return;
  }

  if (isMasked) {
    showToast(t('api.alreadySaved', 'Key already saved and verified.'), 'success');
    return;
  }

  if (rawValue.length !== 64) {
    showToast(t('api.invalidLength',
      '⚠ VirusTotal API keys are 64 characters (yours is {n}).')
      .replace('{n}', String(rawValue.length)), 'error');
    return;
  }

  const btn = $('apiKeySave');
  const originalText = btn ? btn.textContent : 'Save & Verify';
  if (btn) { btn.disabled = true; btn.textContent = t('api.verifying', 'Verifying…'); }

  try {
    const res = await send({ type: 'set-api-key-secure', apiKey: rawValue });

    if (!res?.ok) {
      const errMap = {
        'invalid-api-key': t('api.invalidKey',
          '⚠ VirusTotal rejected this key. It may be expired, revoked, or mistyped.'),
        'invalid-key-format': t('api.invalidLength',
          '⚠ VirusTotal API keys are 64 characters.'),
        'network-error': t('api.networkError',
          '⚠ Could not reach VirusTotal. Check your internet connection.'),
        'network-timeout': t('api.networkError',
          '⚠ VirusTotal did not respond in time. Try again.'),
        'empty-key': t('api.emptyKey', '⚠ Please paste your API key first.')
      };
      showToast(errMap[res?.error] || res?.error || t('api.verifyFailed', 'Key verification failed.'), 'error');
      return;
    }

    state.currentApiKey = rawValue;
    state.apiKeyVisible = false;
    renderApiStatus();

    if (res.rateLimited) {
      showToast(t('api.savedRateLimited',
        '✓ Key verified — you are currently rate-limited by VirusTotal.'), 'success');
    } else {
      showToast(t('api.savedVerified', '✓ API key saved and verified.'), 'success');
    }
  } catch (err) {
    showToast(err.message || t('api.saveFailed', 'Failed to save API key'), 'error');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = originalText; }
  }
});

let _urlhausKeyVisible = false;
let _urlhausKeyStored = '';

async function renderUrlhausStatus() {
  try {
    const s = await send({ type: 'get-settings' });
    const settings = s?.settings || {};
    const key = typeof settings.urlhausAuthKey === 'string'
      ? settings.urlhausAuthKey.trim()
      : '';

    _urlhausKeyStored = key;

    const field = $('urlhausKeyField');
    if (field && document.activeElement !== field) {
      field.value = key
        ? (_urlhausKeyVisible ? key : '•'.repeat(Math.min(64, key.length)))
        : '';
    }

    const box = $('urlhausStatusBox');
    if (box) {
      if (key) {
        box.textContent = '✓ URLhaus is enabled — host queries will be sent to abuse.ch.';
        box.style.color = '#34d399';
      } else {
        box.textContent = 'URLhaus is disabled. Optional — leave empty for a fully local-only setup.';
        box.style.color = '';
      }
    }
  } catch {}
}

safeOn('urlhausKeyToggle', 'click', () => {
  const field = $('urlhausKeyField');
  if (!field) return;

  const currentValue = field.value;
  const wasMasked = /^•+$/.test(currentValue);

  _urlhausKeyVisible = !_urlhausKeyVisible;
  field.type = _urlhausKeyVisible ? 'text' : 'password';

  if (_urlhausKeyVisible && wasMasked && _urlhausKeyStored) {
    field.value = _urlhausKeyStored;
  } else if (!_urlhausKeyVisible && currentValue === _urlhausKeyStored && _urlhausKeyStored) {
    field.value = '•'.repeat(Math.min(64, _urlhausKeyStored.length));
  }
});

safeOn('urlhausKeySave', 'click', async () => {
  const field = $('urlhausKeyField');
  if (!field) return;

  const raw = field.value.trim();
  const isMasked = /^•+$/.test(raw);

  if (!raw) {
    try {
      await send({ type: 'set-urlhaus-key-secure', apiKey: '' });
      _urlhausKeyStored = '';
      _urlhausKeyVisible = false;
      field.type = 'password';
      await renderUrlhausStatus();
      showToast(t('urlhaus.disabled', 'URLhaus disabled.'));
    } catch (err) {
      showToast(err?.message || 'Failed', 'error');
    }
    return;
  }

  if (isMasked) {
    showToast(t('urlhaus.alreadySaved', 'Key already saved and verified.'), 'success');
    return;
  }

  if (raw.length < 10) {
    showToast(t('urlhaus.invalidLength', '⚠ Auth-Key looks too short.'), 'error');
    return;
  }

  const btn = $('urlhausKeySave');
  const originalText = btn ? btn.textContent : 'Save';
  if (btn) { btn.disabled = true; btn.textContent = t('urlhaus.verifying', 'Verifying…'); }

  try {
    const res = await send({ type: 'set-urlhaus-key-secure', apiKey: raw });

    if (!res?.ok) {
      const errMap = {
        'invalid-auth-key': t('urlhaus.invalidKey',
          '⚠ abuse.ch rejected this Auth-Key. Check that you copied the full key.'),
        'invalid-key-format': t('urlhaus.invalidLength', '⚠ Auth-Key looks too short.'),
        'network-error': t('urlhaus.networkError',
          '⚠ Could not reach abuse.ch. Check your internet connection.'),
        'network-timeout': t('urlhaus.networkError',
          '⚠ abuse.ch did not respond in time. Try again.'),
        'empty-key': t('urlhaus.emptyKey', '⚠ Please paste your Auth-Key first.')
      };
      showToast(errMap[res?.error] || res?.error || t('urlhaus.verifyFailed', 'Key verification failed.'), 'error');
      return;
    }

    _urlhausKeyStored = raw;
    _urlhausKeyVisible = false;
    field.type = 'password';
    await renderUrlhausStatus();

    if (res.rateLimited) {
      showToast(t('urlhaus.savedRateLimited',
        '✓ Key verified — you are currently rate-limited by abuse.ch.'), 'success');
    } else {
      showToast(t('urlhaus.savedVerified', '✓ URLhaus key saved and verified.'), 'success');
    }
  } catch (err) {
    showToast(err?.message || 'Failed to save URLhaus key', 'error');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = originalText; }
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

  // Same keys as before, now arranged in labelled groups.
  const GROUPS = [
    {
      icon: '\u{1F6E1}\uFE0F',
      en: 'Protection', fa: 'محافظت',
      descEn: 'How Corsair watches redirects, popups and downloads.',
      descFa: 'نحوه‌ی نظارت Corsair بر ریدایرکت‌ها، پاپ‌آپ‌ها و دانلودها.',
      keys: [
        ['enforceSuspiciousRedirects', 'setting.enforceSuspiciousRedirects'],
        ['verificationEnabled',        'setting.verificationEnabled'],
        ['observationEnabled',         'setting.observationEnabled'],
        ['resolverEnabled',            'setting.resolverEnabled'],
        ['downloadGuard',              'setting.downloadGuard']
      ],
      hops: true,
      autoArm: true
    },
    {
      icon: '\u{1F50E}',
      en: 'Threat intelligence', fa: 'اطلاعات تهدید',
      descEn: 'Look up domains against online threat databases.',
      descFa: 'بررسی دامنه‌ها در پایگاه‌های داده‌ی تهدید آنلاین.',
      keys: [
        ['threatIntelEnabled',  'setting.threatIntelEnabled'],
        ['threatIntelAutoScan', 'setting.threatIntelAutoScan']
      ]
    },
    {
      icon: '\u{1F514}',
      en: 'Alerts & banners', fa: 'اعلان‌ها و بنرها',
      descEn: 'What Corsair shows you while you browse.',
      descFa: 'چیزهایی که Corsair هنگام مرور به شما نشان می‌دهد.',
      keys: [
        ['notifications',     'setting.notifications'],
        ['notifyOnSafeSites', 'setting.notifyOnSafeSites'],
        ['siteVerdictBanner', 'setting.siteVerdictBanner']
      ]
    },
    {
      icon: '\u{1F4DD}',
      en: 'Logging', fa: 'ثبت رویدادها',
      descEn: 'Keep a local activity history.',
      descFa: 'نگه‌داشتن تاریخچه‌ی فعالیت روی همین دستگاه.',
      keys: [['logEvents', 'setting.logEvents']]
    }
  ];

  const bilingual = (el, en, fa) => { el.dataset.en = en; el.dataset.fa = fa; el.textContent = tx(en, fa); return el; };

  for (const grp of GROUPS) {
    const section = document.createElement('section');
    section.className = 'settings-group';

    const head = document.createElement('div');
    head.className = 'settings-group-head';
    const icon = document.createElement('span');
    icon.className = 'settings-group-icon';
    icon.textContent = grp.icon;
    const titles = document.createElement('div');
    const h = bilingual(document.createElement('h3'), grp.en, grp.fa);
    const d = bilingual(document.createElement('div'), grp.descEn, grp.descFa);
    d.className = 'muted';
    titles.append(h, d);
    head.append(icon, titles);
    section.appendChild(head);

    const body = document.createElement('div');
    body.className = 'settings-group-body';

    for (const [key, i18nKey] of grp.keys) {
      const l = document.createElement('label');
      l.className = 'setting';
      const input = document.createElement('input');
      input.type = 'checkbox';
      input.dataset.key = key;
      input.checked = state.settings[key] !== false;
      const span = document.createElement('span');
      span.textContent = t(i18nKey, key);
      l.append(input, span);
      body.appendChild(l);
    }

    if (grp.hops) {
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
      body.appendChild(wrap);
    }

    if (grp.autoArm) {
      const autoBlock = document.createElement('div');
      autoBlock.className = 'setting-block';

      const header = document.createElement('div');
      header.className = 'setting-block-header';

      const headerText = document.createElement('div');
      const strong = document.createElement('strong');
      strong.textContent = '\u26A1 ' + t('onboarding.step5.autoArm.title', 'Auto-Arm Fortress');
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

      autoBlock.append(
        makeSliderRow({ label: 'Arm at', key: 'autoArmFortressThreshold', value: armValue, min: 1, max: 100, step: 1 }),
        makeSliderRow({ label: 'Block at', key: 'autoBlockThreshold', value: blockValue, min: 1, max: 100, step: 1 })
      );
      body.appendChild(autoBlock);
    }

    section.appendChild(body);
    box.appendChild(section);
  }
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

  const countEl = $('activityCount');

  if (typeof CorsairEventFilter === 'undefined') {
    box.innerHTML = '<div class="empty">—</div>';
    if (countEl) countEl.textContent = '';
    return;
  }

  if (!state.events.length) {
    box.innerHTML = '<div class="empty">—</div>';
    if (countEl) countEl.textContent = '';
    return;
  }

  const filtered = CorsairEventFilter.filterEvents(state.events, {
    search: state.activityFilters.search,
    severity: state.activityFilters.severity,
    type: state.activityFilters.type,
    limit: 200
  });

  if (countEl) {
    if (filtered.length === state.events.length) {
      countEl.textContent = `${filtered.length} events`;
    } else {
      countEl.textContent = `${filtered.length} / ${state.events.length} events`;
    }
  }

  if (!filtered.length) {
    box.innerHTML = '<div class="empty">No events match the current filters.</div>';
    return;
  }

  for (const e of filtered) {
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

function refreshActivityTypeFilter() {
  const sel = $('activityTypeFilter');
  if (!sel || typeof CorsairEventFilter === 'undefined') return;

  const prevValue = state.activityFilters.type;
  const types = CorsairEventFilter.collectEventTypes(state.events);

  sel.innerHTML = '';
  const allOpt = document.createElement('option');
  allOpt.value = 'all';
  allOpt.textContent = 'All types';
  sel.appendChild(allOpt);

  for (const ty of types) {
    const opt = document.createElement('option');
    opt.value = ty;
    opt.textContent = ty;
    sel.appendChild(opt);
  }

  if (types.includes(prevValue)) {
    sel.value = prevValue;
  } else {
    sel.value = 'all';
    state.activityFilters.type = 'all';
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

/* ============================================================
   ANALYTICS
   ============================================================ */
const SEVERITY_COLORS = {
  high: 'var(--danger)',
  medium: 'var(--warn)',
  low: 'var(--primary)',
  info: 'var(--text-dim)'
};

const TYPE_ICONS = {
  auto_block: '🚫',
  auto_fortress_armed: '🛡️',
  popup_blocked: '🪟',
  navigation_contained: '🧯',
  download_blocked: '⬇️',
  domain_removed: '🗑️',
  extension_updated: '🔄'
};

function analyticsSeverityLabel(sev) {
  const key = `analytics.severity.${sev}`;
  const fb = sev.charAt(0).toUpperCase() + sev.slice(1);
  return t(key, fb);
}

function analyticsTypeLabel(type) {
  const fb = String(type || 'event').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
  return t(`activity.type.${type}`, fb);
}

function dayKey(ts) {
  const d = new Date(Number(ts) || Date.now());
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

function shortDayLabel(ts) {
  const d = new Date(Number(ts) || Date.now());
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

function buildTimelineChartSVG(points) {
  const W = 560, H = 200, padL = 8, padR = 8, padT = 16, padB = 24;
  const innerW = W - padL - padR;
  const innerH = H - padT - padB;
  const max = Math.max(1, ...points.map(p => p.count));
  const n = points.length;
  const stepX = n > 1 ? innerW / (n - 1) : 0;

  const coords = points.map((p, i) => {
    const x = padL + i * stepX;
    const y = padT + innerH - (p.count / max) * innerH;
    return { x, y, ...p };
  });

  const linePath = coords.map((c, i) => `${i === 0 ? 'M' : 'L'}${c.x.toFixed(1)},${c.y.toFixed(1)}`).join(' ');
  const areaPath = `${linePath} L${coords[coords.length - 1].x.toFixed(1)},${padT + innerH} L${coords[0].x.toFixed(1)},${padT + innerH} Z`;

  const gridLines = [0, 0.5, 1].map(f => {
    const y = padT + innerH * f;
    return `<line class="grid-line" x1="${padL}" y1="${y.toFixed(1)}" x2="${W - padR}" y2="${y.toFixed(1)}" stroke-dasharray="3,4"/>`;
  }).join('');

  const labelEvery = Math.max(1, Math.ceil(n / 6));
  const labels = coords.map((c, i) => {
    if (i % labelEvery !== 0 && i !== n - 1) return '';
    return `<text class="axis-label" x="${c.x.toFixed(1)}" y="${H - 6}" text-anchor="middle">${escapeHtml(c.label)}</text>`;
  }).join('');

  const dots = coords.map(c =>
    `<circle class="data-point" cx="${c.x.toFixed(1)}" cy="${c.y.toFixed(1)}" r="3"><title>${escapeHtml(c.label)}: ${c.count}</title></circle>`
  ).join('');

  return `
    <svg class="chart-svg" viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid meet">
      <defs>
        <linearGradient id="analyticsAreaGradient" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="var(--primary)" stop-opacity="0.45"/>
          <stop offset="100%" stop-color="var(--primary)" stop-opacity="0"/>
        </linearGradient>
      </defs>
      ${gridLines}
      <path class="area-fill" d="${areaPath}"/>
      <path class="line-path" d="${linePath}"/>
      ${dots}
      ${labels}
    </svg>`;
}

function buildDonutChartSVG(segments, centerValue, centerLabel) {
  const size = 180, cx = size / 2, cy = size / 2, r = 62, sw = 26;
  const total = Math.max(1, segments.reduce((s, x) => s + x.value, 0));
  const circumference = 2 * Math.PI * r;
  let offset = 0;

  const arcs = segments.filter(s => s.value > 0).map(s => {
    const frac = s.value / total;
    const dash = frac * circumference;
    const gap = circumference - dash;
    const rotation = (offset / total) * 360 - 90;
    offset += s.value;
    return `<circle class="donut-seg" cx="${cx}" cy="${cy}" r="${r}" fill="none"
      stroke="${s.color}" stroke-width="${sw}"
      stroke-dasharray="${dash.toFixed(1)} ${gap.toFixed(1)}"
      transform="rotate(${rotation.toFixed(1)} ${cx} ${cy})">
      <title>${escapeHtml(s.label)}: ${s.value}</title>
    </circle>`;
  }).join('');

  return `
    <svg class="chart-svg" viewBox="0 0 ${size} ${size}" style="max-width:200px;margin:0 auto;">
      <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="var(--border)" stroke-width="${sw}"/>
      ${arcs}
      <text class="donut-center-value" x="${cx}" y="${cy - 2}" text-anchor="middle">${centerValue}</text>
      <text class="donut-center-label" x="${cx}" y="${cy + 16}" text-anchor="middle">${escapeHtml(centerLabel)}</text>
    </svg>`;
}

function buildChartLegend(segments) {
  return `<div class="chart-legend">${segments.map(s =>
    `<div class="chart-legend-item"><span class="chart-legend-dot" style="background:${s.color}"></span>${escapeHtml(s.label)} · ${s.value}</div>`
  ).join('')}</div>`;
}

function buildBarList(entries, opts = {}) {
  if (!entries.length) {
    return `<div class="empty">${escapeHtml(opts.emptyText || '—')}</div>`;
  }
  const max = Math.max(1, ...entries.map(e => e.count));
  return entries.map(e => `
    <div class="bar-row">
      <div class="bar-row-label" title="${escapeHtml(e.label)}">${opts.icon ? (TYPE_ICONS[e.key] || '•') + ' ' : ''}${escapeHtml(e.label)}</div>
      <div class="bar-row-track"><div class="bar-row-fill" style="width:${Math.max(4, (e.count / max) * 100).toFixed(0)}%"></div></div>
      <div class="bar-row-count">${e.count}</div>
    </div>`).join('');
}

function renderAnalytics() {
  const rangeDays = state.analyticsRange || 14;
  const cutoff = Date.now() - rangeDays * 24 * 60 * 60 * 1000;
  const events = state.events.filter(e => Number(e.timestamp) >= cutoff);

  const shownEl = $('analyticsShown');
  if (shownEl) shownEl.textContent = t('analytics.totalShown', 'Based on the last {n} recorded events').replace('{n}', String(state.events.length));

  const dayBuckets = new Map();
  for (let i = rangeDays - 1; i >= 0; i--) {
    const ts = Date.now() - i * 24 * 60 * 60 * 1000;
    dayBuckets.set(dayKey(ts), { ts, count: 0 });
  }
  for (const e of events) {
    const k = dayKey(e.timestamp);
    if (dayBuckets.has(k)) dayBuckets.get(k).count++;
  }
  const points = [...dayBuckets.values()].map(b => ({ count: b.count, label: shortDayLabel(b.ts) }));
  const timelineEl = $('analyticsTimeline');
  if (timelineEl) {
    timelineEl.innerHTML = events.length
      ? buildTimelineChartSVG(points)
      : `<div class="empty">${escapeHtml(t('analytics.empty', 'No data yet.'))}</div>`;
  }

  const sevCounts = { high: 0, medium: 0, low: 0, info: 0 };
  for (const e of events) {
    const s = (e.severity || 'info').toLowerCase();
    if (s in sevCounts) sevCounts[s]++; else sevCounts.info++;
  }
  const sevSegments = Object.entries(sevCounts)
    .filter(([, v]) => v > 0)
    .map(([k, v]) => ({ label: analyticsSeverityLabel(k), value: v, color: SEVERITY_COLORS[k] }));
  const severityEl = $('analyticsSeverity');
  if (severityEl) {
    severityEl.innerHTML = events.length
      ? buildDonutChartSVG(sevSegments, events.length, t('stats.totalEvents', 'Events'))
        + buildChartLegend(sevSegments)
      : `<div class="empty">${escapeHtml(t('analytics.empty', 'No data yet.'))}</div>`;
  }

  const typeCounts = new Map();
  for (const e of events) {
    const k = e.type || 'event';
    typeCounts.set(k, (typeCounts.get(k) || 0) + 1);
  }
  const typeEntries = [...typeCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([k, v]) => ({ key: k, label: analyticsTypeLabel(k), count: v }));
  const typesEl = $('analyticsTypes');
  if (typesEl) typesEl.innerHTML = buildBarList(typeEntries, { icon: true, emptyText: t('analytics.empty', 'No data yet.') });

  const domainCounts = new Map();
  for (const e of events) {
    for (const host of [e.domain, e.destination]) {
      const h = String(host || '').trim();
      if (!h) continue;
      domainCounts.set(h, (domainCounts.get(h) || 0) + 1);
    }
  }
  const domainEntries = [...domainCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([k, v]) => ({ key: k, label: k, count: v }));
  const domainsEl = $('analyticsDomains');
  if (domainsEl) domainsEl.innerHTML = buildBarList(domainEntries, { emptyText: t('analytics.noDomains', 'No domain activity in this range.') });
}

function exportAnalyticsReport() {
  const rangeDays = state.analyticsRange || 14;
  const cutoff = Date.now() - rangeDays * 24 * 60 * 60 * 1000;
  const events = state.events.filter(e => Number(e.timestamp) >= cutoff);
  const sevCounts = { high: 0, medium: 0, low: 0, info: 0 };
  const typeCounts = {};
  const domainCounts = {};
  for (const e of events) {
    const s = (e.severity || 'info').toLowerCase();
    sevCounts[s in sevCounts ? s : 'info']++;
    const ty = e.type || 'event';
    typeCounts[ty] = (typeCounts[ty] || 0) + 1;
    for (const host of [e.domain, e.destination]) {
      if (!host) continue;
      domainCounts[host] = (domainCounts[host] || 0) + 1;
    }
  }
  downloadJSON(`corsair-analytics-${rangeDays}d-${Date.now()}.json`, {
    generatedAt: new Date().toISOString(),
    rangeDays,
    totalEvents: events.length,
    bySeverity: sevCounts,
    byType: typeCounts,
    byDomain: domainCounts,
    events
  });
  showToast(t('analytics.export', 'Export Report'), 'success');
}

function initAnalytics() {
  const group = $('analyticsRangeGroup');
  if (group) {
    group.querySelectorAll('.range-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        group.querySelectorAll('.range-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        state.analyticsRange = Number(btn.dataset.range) || 14;
        renderAnalytics();
      });
    });
  }
  safeOn('analyticsExportBtn', 'click', exportAnalyticsReport);
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
    send({ type: 'us-list' }),
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
  state.userscriptAvailability = cs?.availability || null;
  state.extensionId = cs?.extensionId || state.extensionId;
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
  renderAnalytics();
  refreshActivityTypeFilter();
  renderEvents();
  renderEvidence();
  renderRisk();
  renderStorageStats();
  renderApiStatus();
  renderUrlhausStatus();
  renderApiKeyWarning();

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
    const includeSecrets = $('exportIncludeSecrets')?.checked !== false;
    const r = await send({ type: 'export-config', includeSecrets });
    if (!r?.ok) throw new Error(r?.error || 'Export failed');

    const exp = r.export || {};
    const s = exp.summary || {};

    const lines = [
      `Corsair Unbound Backup`,
      ``,
      `This file will contain:`,
      `  • ${s.profileCount || 0} domain profiles`,
      `  • ${s.userscriptsCount ?? s.customScriptsCount ?? 0} userscripts (with their saved values)`,
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
      (s.apiKeysIncluded || []).length
        ? `API KEYS ARE INCLUDED IN PLAIN TEXT (${s.apiKeysIncluded.join(', ')}). Keep this file private!`
        : `API keys are NOT included in this file.`,
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
    if (r.importedUserscripts) parts.push(`${r.importedUserscripts} userscripts`);
    else if (r.importedCustomScripts) parts.push(`${r.importedCustomScripts} scripts`);
    if (r.importedApiKeys?.length) parts.push(`API keys (${r.importedApiKeys.join(', ')})`);
    if (r.importedUserTrusted) parts.push(`${r.importedUserTrusted} trusted`);
    if (r.importedUserBlocked) parts.push(`${r.importedUserBlocked} blocked`);
    if (r.importedThreatCache) parts.push(`${r.importedThreatCache} cache entries`);
    if (restoreTelemetry) parts.push('telemetry');
    showToast(`Restored: ${parts.join(', ')}`);
    if (r.userscriptsError) showToast(`Userscripts could not be fully restored: ${r.userscriptsError}`, 'error');
    if (r.apiKeyError) showToast(`API key could not be restored: ${r.apiKeyError}`, 'error');
    await refresh();
  } catch (e) {
    showToast(`Import failed: ${e.message}`, 'error');
  }
}

/* ============================================================
   UPDATE CHECK — PATH A
   ------------------------------------------------------------
   In Path A, the extension does NOT download the ZIP itself.
   The Windows launcher (launcher/updater.ps1) handles:
     • Downloading the release ZIP
     • SHA-256 verification
     • Backup / extraction / file replacement
     • Opening chrome://extensions for the Reload step
   The extension's ONLY jobs are:
     • Detect that a stable release exists (via latest.json)
     • Show version info + release notes
     • Give the user the launcher URL
     • Open GitHub releases / chrome://extensions
     • Detect the "just updated" event and toast the user
   ============================================================ */
const LAST_SEEN_VERSION_KEY = 'updaterV2DashboardSeenVersion';

async function detectExtensionUpdate() {
  if (typeof CorsairUpdater === 'undefined') return;
  try {
    const current = CorsairUpdater.getCurrentVersion();
    const stored = await chrome.storage.local.get(LAST_SEEN_VERSION_KEY);
    const previous = stored?.[LAST_SEEN_VERSION_KEY];

    // First run: record the version silently, no toast.
    if (!previous) {
      await chrome.storage.local.set({ [LAST_SEEN_VERSION_KEY]: current });
      return;
    }
    if (previous === current) return;

    // Version changed while the dashboard was closed.
    await chrome.storage.local.set({ [LAST_SEEN_VERSION_KEY]: current });
    const msg = t('update.detected', 'Corsair Unbound updated to v{version}.')
      .replace('{version}', current);
    showToast(msg, 'success');
  } catch {}
}

async function initUpdateCheck() {
  if (typeof CorsairUpdater === 'undefined') return;

  // Detect "we just got updated" BEFORE we check for new updates.
  await detectExtensionUpdate();

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

  const mandatory = result.mandatory === true;
  const banner = $('updateBanner');
  const bannerTitle = $('updateBannerTitle');
  const bannerDetail = $('updateBannerDetail');
  const bannerLink = $('updateBannerLink');
  const bannerDismiss = $('updateBannerDismiss');
  const dismissed = sessionStorage.getItem('updateBannerDismissed');

  if (bannerTitle) {
    bannerTitle.textContent = mandatory
      ? t('update.banner.titleMandatory', 'Required update available')
      : t('update.banner.title', 'New version available');
  }

  if (result.hasUpdate && banner && (mandatory || !dismissed)) {
    if (bannerDetail) {
      bannerDetail.textContent = mandatory
        ? t('update.banner.detailMandatory',
            'v{version} is required. Open the dashboard to update.').replace('{version}', result.latest || '?')
        : t('update.banner.detail',
            'v{version} is available. Your data will be preserved.').replace('{version}', result.latest || '?');
    }
    if (bannerLink) {
      bannerLink.href = '#';
      bannerLink.textContent = t('update.banner.button', 'View update');
    }
    if (bannerDismiss) bannerDismiss.hidden = mandatory;
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

/* ---------- UPDATE MODAL (Path A) ---------- */
function translateUpdateModal() {
  const latest = state.updateInfo?.latest || '?';
  const mandatory = state.updateInfo?.mandatory === true;
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

  // The button that triggers "Get the Updater" is aliased to work
  // with both the legacy updateDownloadBtn ID and the new
  // updateGetUpdaterBtn ID. Add the version span inside whichever
  // one exists so CSS/localization behaves consistently.
  const getBtn = $('updateGetUpdaterBtn') || $('updateDownloadBtn');
  if (getBtn) {
    const fullText = t('update.modal.step1.button', '⬇ Get the Updater (v{version})')
      .replace('{version}', latest);
    const prefix = fullText.endsWith(latest)
      ? fullText.slice(0, fullText.length - latest.length)
      : fullText;

    getBtn.textContent = '';
    getBtn.appendChild(document.createTextNode(prefix));

    const versionSpan = document.createElement('span');
    versionSpan.id = 'updateDownloadVersion';
    versionSpan.textContent = latest;
    getBtn.appendChild(versionSpan);
  }

  const stepNodes = document.querySelectorAll('.update-step-body strong');
  const stepDescs = document.querySelectorAll('.update-step-body > span');
  const keys = [
    ['update.modal.step1.title', 'update.modal.step1.desc'],
    ['update.modal.step2.title', 'update.modal.step2.desc'],
    ['update.modal.step3.title', 'update.modal.step3.desc'],
    ['update.modal.step4.title', 'update.modal.step4.desc']
  ];
  stepNodes.forEach((node, i) => {
    if (keys[i]) node.textContent = t(keys[i][0], node.textContent);
  });
  stepDescs.forEach((node, i) => {
    if (keys[i]) node.textContent = t(keys[i][1], node.textContent);
  });

  setText('updateOpenReleasesBtn', 'update.modal.releasesBtn', '🔗 Open GitHub Releases');
  setText('updateOpenExtensionsBtn', 'update.modal.extensionsBtn', '🔗 Copy chrome://extensions');
  setText('updateSkipVersion', 'update.modal.snooze', 'Remind me later');
  setText('updateModalDone', 'update.modal.done', 'Got it');

  const snooze = $('updateSkipVersion');
  if (snooze) snooze.hidden = mandatory;
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
  if (state.updateInfo?.mandatory === true) return;
  closeUpdateModal();
  showToast(t('update.snoozed', 'Reminder snoozed for this session.'));
});

/* ---------- PATH A ACTIONS ---------- */

function handleGetUpdater() {
  const fallbackBase = 'https://github.com/amiraction0938/Corsair-Unbound';
  const url = `${(typeof CorsairUpdater !== 'undefined' && CorsairUpdater.repoUrl) || fallbackBase}/releases`;
  
  // باز کردن صفحه ریلیزها
  try {
    if (typeof chrome !== 'undefined' && chrome.tabs?.create) {
      chrome.tabs.create({ url }).catch(() => {});
    } else {
      window.open(url, '_blank', 'noopener');
    }
    // این خط رو به کلید جدید تغییر دادیم
    showToast(t('update.openingReleases', 'Opening GitHub Releases page...'));
  } catch {
    try { window.open(url, '_blank', 'noopener'); } catch {}
  }
}

function handleOpenReleases() {
  const fallbackBase = 'https://github.com/amiraction0938/Corsair-Unbound';
  const url = `${(typeof CorsairUpdater !== 'undefined' && CorsairUpdater.repoUrl) || fallbackBase}/releases`;
  try {
    if (typeof chrome !== 'undefined' && chrome.tabs?.create) {
      chrome.tabs.create({ url }).catch(() => {});
    } else {
      window.open(url, '_blank', 'noopener');
    }
  } catch {
    try { window.open(url, '_blank', 'noopener'); } catch {}
  }
}

// Primary button inside the modal (Path A).
safeOn('updateGetUpdaterBtn', 'click', handleGetUpdater);
// Back-compat: the legacy HTML may still carry this ID.
safeOn('updateDownloadBtn', 'click', handleGetUpdater);

// Open GitHub Releases.
safeOn('updateOpenReleasesBtn', 'click', handleOpenReleases);
// Back-compat: the legacy HTML "Copy path" button now opens Releases
// (closest equivalent action in Path A).
safeOn('updateCopyPathBtn', 'click', handleOpenReleases);

// Copy chrome://extensions (unchanged behavior).
safeOn('updateOpenExtensionsBtn', 'click', async () => {
  try {
    await navigator.clipboard.writeText('chrome://extensions');
    showToast(t('update.copy.extensions', 'Copied: chrome://extensions'));
  } catch {
    showToast(t('update.copy.extensionsManual', 'Paste chrome://extensions in the URL bar.'), 'error');
  }
});

// The legacy "Reveal in folder" button has no Path A equivalent.
// Hide it if it still exists so the modal doesn't show a dead control.
const _legacyRevealBtn = $('updateRevealBtn');
if (_legacyRevealBtn) _legacyRevealBtn.hidden = true;

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
        const setRes = await send({ type: 'set-api-key-secure', apiKey: key });
        if (!setRes?.ok) {
          throw new Error(setRes?.error === 'invalid-api-key'
            ? t('onboarding.step4.errInvalid', 'Invalid API key — VirusTotal rejected it.')
            : (setRes?.error || 'Failed to save key'));
        }
        state.currentApiKey = key;

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

safeOn('activitySearch', 'input', () => {
  state.activityFilters.search = $('activitySearch')?.value || '';
  renderEvents();
});

safeOn('activitySeverityFilter', 'change', () => {
  state.activityFilters.severity = $('activitySeverityFilter')?.value || 'all';
  renderEvents();
});

safeOn('activityTypeFilter', 'change', () => {
  state.activityFilters.type = $('activityTypeFilter')?.value || 'all';
  renderEvents();
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

safeOn('scriptNewBtn', 'click', () => openEditor(null));
document.querySelectorAll('[data-guide-lang]').forEach(b => b.addEventListener('click', () => { state.guideLang = b.dataset.guideLang; renderUserscriptGuide(); }));
document.querySelectorAll('[data-guide-tab]').forEach(b => b.addEventListener('click', () => { state.guideTab = b.dataset.guideTab; renderUserscriptGuide(); }));
(() => {
  // Re-render the EN/FA bits whenever the dashboard language is (re)applied
  let lastLang = '';
  if (window.CorsairI18n && !CorsairI18n.__bilingualHook) {
    const orig = CorsairI18n.apply;
    CorsairI18n.apply = function () {
      const r = orig.apply(this, arguments);
      try {
        const cur = String(CorsairI18n.getCurrent?.() || '');
        if (cur !== lastLang) { lastLang = cur; state.guideLang = ''; }
        applyBilingual();
        renderUserscriptGuide();
        const active = document.querySelector('.view.active');
        const titleEl = $('viewTitle') || document.querySelector('.view-title, #pageTitle');
        if (active && titleEl && active.id === 'view-scripts') titleEl.textContent = getViewTitle('scripts');
      } catch {}
      return r;
    };
    CorsairI18n.__bilingualHook = true;
  }
  applyBilingual();
  renderUserscriptGuide();
})();
safeOn('scriptSearch', 'input', (e) => { state.scriptQuery = e.target.value || ''; renderCustomScripts(); });
window.addEventListener('focus', async () => {
  const av = state.userscriptAvailability;
  if (!av || av.ok) return;
  try {
    const res = await send({ type: 'us-list' });
    if (res?.availability?.ok) {
      await send({ type: 'us-sync' });
      state.userscriptAvailability = res.availability;
      state.customScripts = res.scripts || [];
      renderCustomScripts();
      showToast('User scripts are now enabled ✓');
    }
  } catch {}
});
document.querySelectorAll('[data-us-demo]').forEach(btn => btn.addEventListener('click', () => installUserscriptDemo(btn.dataset.usDemo)));
safeOn('scriptOpenExample', 'click', () => chrome.tabs.create({ url: 'https://example.com/' }));
safeOn('scriptImportBtn', 'click', importUserscriptFromUrl);
safeOn('scriptImportUrl', 'keydown', e => { if (e.key === 'Enter') importUserscriptFromUrl(); });
safeOn('scriptImportFileBtn', 'click', () => { const f = $('scriptImportFile'); if (f) f.click(); });
safeOn('scriptImportFile', 'change', (e) => { importUserscriptFiles(e.target.files); e.target.value = ''; });

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
    target: '#view-security .grid-2col',
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

  try {
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
  } catch (err) {
    // اگر تور به هر دلیلی کرش کرد، متغیرها رو ریست می‌کنیم تا دکمه دوباره کار کنه
    console.error('[Corsair Tour] Failed to start:', err);
    _tourActive = false;
    document.body.classList.remove('tour-active');
    const overlay = $('tourOverlay');
    if (overlay) overlay.hidden = true;
  }
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
  initAnalytics();
  await initLanguage();
  await initTheme();
  await refresh();

  initUpdateCheck().catch(() => {});

  const show = await shouldShowOnboarding();
  if (show) {
    setTimeout(() => openOnboarding(), 400);
  }
})();
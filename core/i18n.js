const CorsairI18n = (() => {
  'use strict';

  const LANGUAGES = [
    { code: 'en', label: 'English',  flag: '🇬🇧', dir: 'ltr' },
    { code: 'fa', label: 'فارسی',    flag: '🇮🇷', dir: 'rtl' },
    { code: 'ar', label: 'العربية',  flag: '🇸🇦', dir: 'rtl' },
    { code: 'es', label: 'Español',  flag: '🇪🇸', dir: 'ltr' },
    { code: 'de', label: 'Deutsch',  flag: '🇩🇪', dir: 'ltr' },
    { code: 'fr', label: 'Français', flag: '🇫🇷', dir: 'ltr' },
    { code: 'ru', label: 'Русский',  flag: '🇷🇺', dir: 'ltr' },
    { code: 'zh', label: '中文',     flag: '🇨🇳', dir: 'ltr' }
  ];

  const T = {
    en: {
      /* header */
      'header.title': 'Corsair Unbound',
      'header.subtitle': 'Security dashboard • deterministic isolation, intelligence & recovery',
      /* actions */
      'actions.theme': 'Toggle Theme',
      'actions.clearEvents': 'Clear events',
      'actions.clearGraph': 'Clear graph',
      /* stats */
      'stats.totalEvents': 'Total Events',
      'stats.protection': 'Protection Events',
      'stats.blacklisted': 'Blacklisted Domains',
      'stats.profiles': 'Protected Profiles',
      /* analyzer */
      'analyzer.title': '🔬 Domain Analyzer',
      'analyzer.subtitle': 'Check any domain against the whitelist + VirusTotal + heuristics',
      'analyzer.syncWhitelist': '🔄 Sync Whitelist',
      'analyzer.input': 'example.com',
      'analyzer.analyze': 'Analyze',
      'analyzer.forceScan': 'Force Scan',
      'analyzer.placeholder': 'Enter a domain above to analyze its reputation.',
      /* custom scripts */
      'scripts.title': '🎨 Custom Domain Scripts',
      'scripts.subtitle': 'Inject your own JS snippets into specific domains — executed automatically on every visit.',
      'scripts.domainPlaceholder': 'example.com',
      'scripts.addDomain': 'Add Domain',
      'scripts.empty': 'No custom scripts yet. Add a domain above to begin.',
      'scripts.enable': 'Enabled',
      'scripts.edit': 'Edit',
      'scripts.remove': 'Remove',
      'scripts.editorTitle': 'Script Editor',
      'scripts.save': 'Save',
      'scripts.cancel': 'Cancel',
      'scripts.language': 'JavaScript',
      'scripts.lines': 'lines',
      'scripts.confirmRemove': 'Remove this script? This cannot be undone.',
      /* safe */
      'safe.title': '✅ Safe Scanned Domains',
      'safe.subtitle': 'Domains scanned clean by VirusTotal. Cached locally.',
      'safe.empty': 'No safe-scanned domains yet.',
      'safe.export': '⬇ Export List',
      'safe.import': '⬆ Import List',
      'safe.clearAll': 'Clear All',
      'safe.searchPlaceholder': 'Search safe domains...',
      'safe.selectAll': 'Select all',
      'safe.removeSelected': 'Remove selected',
      'safe.selected': 'selected',
      /* trusted */
      'trusted.title': '🛡️ User Trusted Domains',
      'trusted.subtitle': 'Domains you explicitly trusted. Never sent to VirusTotal.',
      'trusted.empty': 'No trusted domains yet.',
      /* guide */
      'guide.title': '📖 How Corsair Unbound Works',
      'guide.subtitle': 'Quick operating guide & setup instructions',
      'guide.card1.title': '⚡ 1. Arming Fortress',
      'guide.card1.body': 'Open the extension popup on any site and click <b>Add &amp; Arm Fortress</b>. All third-party popups and script-driven redirects on that site are terminated at the browser kernel via DNR session rules.',
      'guide.card2.title': '🌐 2. Smart Whitelist',
      'guide.card2.body': '500+ trusted domains built-in and synced from Cisco OpenDNS weekly. Whitelisted sites are <b>never</b> sent to VirusTotal — saving your API quota.',
      'guide.card3.title': '🔍 3. Auto Threat Scan',
      'guide.card3.body': 'When you open a non-whitelisted site, Corsair queries VirusTotal and shows a banner in the top-right corner of the page.',
      'guide.card4.title': '🛡️ 4. DNR Catch-All',
      'guide.card4.body': 'Every Fortress-armed profile installs a <code>domainType: thirdParty</code> session rule that blocks any main_frame navigation leaving the origin.',
      'guide.card5.title': '🧠 5. Heuristic Analysis',
      'guide.card5.body': 'Corsair analyzes domains for typosquatting, suspicious TLDs, homograph attacks, and recently registered domains.',
      'guide.card6.title': '🎨 6. Custom Scripts',
      'guide.card6.body': 'Add your own JS snippets per domain. They inject automatically every time you visit — perfect for removing annoying page overlays or tweaking styles.',
      /* backup */
      'backup.title': 'Backup & Restore',
      'backup.subtitle': 'Exports settings, profiles, regression suites and telemetry as one JSON file.',
      'backup.restoreTelemetry': 'Restore telemetry on import',
      'backup.download': 'Download Corsair Backup',
      'backup.choose': 'Choose Backup File',
      /* privacy */
      'privacy.title': '🔐 Privacy & Data',
      'privacy.subtitle': 'Everything is stored locally. Nothing is uploaded to our servers.',
      'privacy.refresh': 'Refresh',
      'privacy.wipe': '🗑 Wipe ALL Local Data',
      'privacy.wipeNote': 'This removes everything. Cannot be undone.',
      'privacy.totalStorage': 'Total local storage',
      'privacy.profiles': 'Protected profiles',
      'privacy.userTrusted': 'User-trusted domains',
      'privacy.safeScanned': 'Safe-scanned domains',
      'privacy.cacheCount': 'Threat cache entries',
      /* settings */
      'settings.title': 'Global Settings',
      'settings.save': 'Save settings',
      'setting.resolverEnabled': 'Safe Redirect Resolver',
      'setting.notifications': 'Desktop Notifications',
      'setting.siteVerdictBanner': 'In-Page Verdict Banner',
      'setting.notifyOnSafeSites': 'Show Verdict Banner on Safe Sites',
      'setting.logEvents': 'Event Telemetry Logging',
      'setting.observationEnabled': 'Page Observation Engine',
      'setting.verificationEnabled': 'Chain Verification',
      'setting.enforceSuspiciousRedirects': 'Enforce Suspicious Redirect Containment',
      'setting.threatIntelEnabled': 'Enable VirusTotal Threat Intelligence',
      'setting.threatIntelAutoScan': 'Auto-Scan Visited Domains',
      'setting.downloadGuard': 'Block Downloads from Malicious Sources',
      'setting.maxRedirectHops': 'Global max redirect hops',
      /* VT */
      'vt.title': 'VirusTotal API Key (BYOK)',
      'vt.getKey': '🔑 Get Free API Key ↗',
      'vt.placeholder': 'Paste your 64-char VirusTotal API Key',
      'vt.freeKeys': 'Free keys: 4 requests/min, 500 requests/day. All queries cached locally.',
      'vt.hintTitle': '🔑 VirusTotal API Key:',
      'vt.step1': 'Free account:',
      'vt.step2': 'API Key:',
      'vt.step3': 'Paste the 64-char key above, enable Threat Intelligence + Auto-Scan',
      'vt.refreshWhitelist': '🔄 Refresh Whitelist',
      /* risk/evidence */
      'risk.title': '🧠 Behavior Intelligence',
      'risk.subtitle': 'Correlates recent redirects, popups, and navigation signals.',
      'evidence.title': '📁 Evidence Store',
      'evidence.clear': 'Clear evidence',
      /* profiles */
      'profiles.title': 'Domain Profiles',
      'profiles.searchPlaceholder': 'Search domains...',
      'activity.title': 'Activity Log',
      'activity.refresh': 'Refresh',
      'agent.title': 'Agent Context',
      'agent.copy': 'Copy JSON',
      /* regression */
      'regression.title': 'Deterministic Replay / Regression',
      'regression.subtitle': 'Run local regression test fixtures.',
      'regression.runAll': 'Run all',
      /* network */
      'network.title': '🌐 Network Observation',
      'network.subtitle': 'External resources captured for the active tab.',
      'network.tabId': 'Tab ID',
      'network.refresh': 'Refresh',
      'network.clear': 'Clear',
      /* language */
      'lang.label': 'Language'
    },

    fa: {
      /* header */
      'header.title': '🏴‍☠️ کورسِر آنباند',
      'header.subtitle': 'داشبورد امنیتی • ایزوله‌سازی قطعی، هوش تهدید و بازیابی',
      /* actions */
      'actions.theme': 'تغییر تم',
      'actions.clearEvents': 'پاک کردن رویدادها',
      'actions.clearGraph': 'پاک کردن گراف',
      /* stats */
      'stats.totalEvents': 'کل رویدادها',
      'stats.protection': 'رویدادهای محافظت',
      'stats.blacklisted': 'دامنه‌های بلاک‌شده',
      'stats.profiles': 'پروفایل‌های محافظت‌شده',
      /* analyzer */
      'analyzer.title': '🔬 آنالایزر دامنه',
      'analyzer.subtitle': 'هر دامنه را با وایت‌لیست + VirusTotal + heuristics بررسی کن',
      'analyzer.syncWhitelist': '🔄 سینک وایت‌لیست',
      'analyzer.input': 'example.com',
      'analyzer.analyze': 'تحلیل',
      'analyzer.forceScan': 'اسکن اجباری',
      'analyzer.placeholder': 'دامنه‌ای وارد کن تا اعتبارش بررسی بشه.',
      /* custom scripts */
      'scripts.title': '🎨 اسکریپت‌های اختصاصی دامنه',
      'scripts.subtitle': 'کدهای JS خودت رو به دامنه‌های مشخص تزریق کن — خودکار هنگام بازدید اجرا میشن.',
      'scripts.domainPlaceholder': 'example.com',
      'scripts.addDomain': 'افزودن دامنه',
      'scripts.empty': 'هنوز اسکریپتی نداری. یه دامنه بالای صفحه اضافه کن.',
      'scripts.enable': 'فعال',
      'scripts.edit': 'ویرایش',
      'scripts.remove': 'حذف',
      'scripts.editorTitle': 'ویرایشگر اسکریپت',
      'scripts.save': 'ذخیره',
      'scripts.cancel': 'لغو',
      'scripts.language': 'جاوااسکریپت',
      'scripts.lines': 'خط',
      'scripts.confirmRemove': 'این اسکریپت حذف بشه؟ قابل برگشت نیست.',
      /* safe */
      'safe.title': '✅ دامنه‌های اسکن‌شده و امن',
      'safe.subtitle': 'دامنه‌هایی که توسط VirusTotal پاک شناسایی شدن. لوکال کش می‌شن.',
      'safe.empty': 'هنوز دامنه امنی اسکن نشده.',
      'safe.export': '⬇ خروجی لیست',
      'safe.import': '⬆ ورود لیست',
      'safe.clearAll': 'پاک کردن همه',
      'safe.searchPlaceholder': 'جستجو در دامنه‌های امن...',
      'safe.selectAll': 'انتخاب همه',
      'safe.removeSelected': 'حذف انتخاب‌شده‌ها',
      'safe.selected': 'انتخاب‌شده',
      /* trusted */
      'trusted.title': '🛡️ دامنه‌های مورد اعتماد کاربر',
      'trusted.subtitle': 'دامنه‌هایی که خودت به‌عنوان قابل‌اعتماد ثبت کردی. هرگز به VirusTotal فرستاده نمی‌شن.',
      'trusted.empty': 'هیچ دامنه‌ای ثبت نشده. روی «Trust permanently» توی بنر سایت بزن.',
      /* guide */
      'guide.title': '📖 کورسِر آنباند چطور کار می‌کنه',
      'guide.subtitle': 'راهنمای سریع و دستورالعمل راه‌اندازی',
      'guide.card1.title': '⚡ ۱. فعال‌سازی Fortress',
      'guide.card1.body': 'روی هر سایتی افزونه رو باز کن و <b>Add &amp; Arm Fortress</b> رو بزن. از اون لحظه، همه پاپ‌آپ‌های شخص سوم و ریدایرکت‌های اسکریپتی از طریق قوانین DNR در سطح مرورگر خنثی می‌شن.',
      'guide.card2.title': '🌐 ۲. وایت‌لیست هوشمند',
      'guide.card2.body': 'بیش از ۵۰۰ دامنه مورد اعتماد به‌صورت داخلی و هفتگی از Cisco OpenDNS سینک می‌شن. سایت‌های وایت‌لیست <b>هرگز</b> به VirusTotal فرستاده نمی‌شن — صرفه‌جویی در API quota.',
      'guide.card3.title': '🔍 ۳. اسکن خودکار تهدید',
      'guide.card3.body': 'وقتی وارد یه سایت غیر وایت‌لیست می‌شی، کورسِر از VirusTotal استعلام می‌کنه و یه بنر گوشه بالا-راست صفحه نشون می‌ده.',
      'guide.card4.title': '🛡️ ۴. DNR Catch-All',
      'guide.card4.body': 'هر پروفایل Fortress یه قانون سشن <code>domainType: thirdParty</code> نصب می‌کنه که هر ناوبری main_frame از مبدأ رو بلاک می‌کنه.',
      'guide.card5.title': '🧠 ۵. تحلیل Heuristic',
      'guide.card5.body': 'کورسِر دامنه‌ها رو از نظر typosquatting، TLD های مشکوک، حملات homograph و دامنه‌های تازه‌ثبت‌شده تحلیل می‌کنه.',
      'guide.card6.title': '🎨 ۶. اسکریپت‌های اختصاصی',
      'guide.card6.body': 'کدهای JS خودت رو برای هر دامنه اضافه کن. خودکار هنگام بازدید تزریق می‌شن — عالی برای حذف overlay های مزاحم یا تغییر استایل.',
      /* backup */
      'backup.title': 'پشتیبان‌گیری و بازیابی',
      'backup.subtitle': 'تنظیمات، پروفایل‌ها، تست‌های رگرسیون و تلمتری رو در یک فایل JSON ذخیره می‌کنه.',
      'backup.restoreTelemetry': 'بازیابی تلمتری هنگام ورود',
      'backup.download': 'دانلود پشتیبان کورسِر',
      'backup.choose': 'انتخاب فایل پشتیبان',
      /* privacy */
      'privacy.title': '🔐 حریم خصوصی و داده‌ها',
      'privacy.subtitle': 'همه‌چیز فقط در مرورگر خودت ذخیره میشه. چیزی به سرور ما فرستاده نمی‌شه.',
      'privacy.refresh': 'بروزرسانی',
      'privacy.wipe': '🗑 پاک کردن کامل داده‌های لوکال',
      'privacy.wipeNote': 'این کار همه‌چیز رو حذف می‌کنه. قابل بازگشت نیست.',
      'privacy.totalStorage': 'کل فضای مصرفی',
      'privacy.profiles': 'پروفایل‌های محافظت‌شده',
      'privacy.userTrusted': 'دامنه‌های مورد اعتماد',
      'privacy.safeScanned': 'دامنه‌های اسکن‌شده امن',
      'privacy.cacheCount': 'تعداد کش تهدیدها',
      /* settings */
      'settings.title': 'تنظیمات کلی',
      'settings.save': 'ذخیره تنظیمات',
      'setting.resolverEnabled': 'حل‌کنندهٔ ایمن ریدایرکت',
      'setting.notifications': 'نوتیفیکیشن دسکتاپ',
      'setting.siteVerdictBanner': 'بنر نتیجه در بالای سایت',
      'setting.notifyOnSafeSites': 'نمایش بنر برای سایت‌های امن',
      'setting.logEvents': 'ثبت رویدادها',
      'setting.observationEnabled': 'موتور مشاهدهٔ صفحه',
      'setting.verificationEnabled': 'تأیید زنجیرهٔ ریدایرکت',
      'setting.enforceSuspiciousRedirects': 'اجبار مهار ریدایرکت‌های مشکوک',
      'setting.threatIntelEnabled': 'فعال‌سازی هوش تهدید VirusTotal',
      'setting.threatIntelAutoScan': 'اسکن خودکار دامنه‌های بازدیدشده',
      'setting.downloadGuard': 'مسدودسازی دانلود از منابع مخرب',
      'setting.maxRedirectHops': 'حداکثر پرش ریدایرکت (کلی)',
      /* VT */
      'vt.title': 'کلید API ویروس‌توتال (BYOK)',
      'vt.getKey': '🔑 دریافت کلید رایگان ↗',
      'vt.placeholder': 'کلید ۶۴ کاراکتری VirusTotal رو اینجا بچسبون',
      'vt.freeKeys': 'کلیدهای رایگان: ۴ درخواست در دقیقه، ۵۰۰ درخواست در روز. همه استعلام‌ها لوکال کش می‌شن.',
      'vt.hintTitle': '🔑 راهنمای کلید API ویروس‌توتال:',
      'vt.step1': 'حساب رایگان بساز:',
      'vt.step2': 'کلید API:',
      'vt.step3': 'کلید ۶۴ کاراکتری رو بالا بچسبون و Threat Intelligence + Auto-Scan رو فعال کن',
      'vt.refreshWhitelist': '🔄 بروزرسانی وایت‌لیست',
      /* risk/evidence */
      'risk.title': '🧠 هوش رفتاری',
      'risk.subtitle': 'ریدایرکت‌ها، پاپ‌آپ‌ها و سیگنال‌های ناوبری اخیر رو تحلیل می‌کنه.',
      'evidence.title': '📁 مخزن شواهد',
      'evidence.clear': 'پاک کردن شواهد',
      /* profiles */
      'profiles.title': 'پروفایل‌های دامنه',
      'profiles.searchPlaceholder': 'جستجوی دامنه‌ها...',
      'activity.title': 'گزارش فعالیت',
      'activity.refresh': 'بروزرسانی',
      'agent.title': 'کانتکست ایجنت',
      'agent.copy': 'کپی JSON',
      /* regression */
      'regression.title': 'بازپخش قطعی / رگرسیون',
      'regression.subtitle': 'فیکسچرهای تست رگرسیون محلی رو اجرا کن.',
      'regression.runAll': 'اجرای همه',
      /* network */
      'network.title': '🌐 مشاهدهٔ شبکه',
      'network.subtitle': 'منابع خارجی ثبت‌شده برای تب فعال.',
      'network.tabId': 'شناسه تب',
      'network.refresh': 'بروزرسانی',
      'network.clear': 'پاک',
      /* language */
      'lang.label': 'زبان'
    }

    /* سایر زبان‌ها به صورت خودکار از انگلیسی fallback می‌کنن */
  };

  let _current = 'en';

  function getLanguages() { return LANGUAGES.slice(); }

  function getLanguage(code) {
    return LANGUAGES.find(l => l.code === code) || LANGUAGES[0];
  }

  function t(key, fallback = '') {
    const dict = T[_current] || T.en;
    return dict[key] || (T.en[key]) || fallback || key;
  }

  function getCurrent() { return _current; }
  function getDir() { return getLanguage(_current).dir; }

  async function load() {
    try {
      const stored = await chrome.storage.local.get('language');
      const wanted = stored?.language || '';
      if (LANGUAGES.some(l => l.code === wanted)) {
        _current = wanted;
      } else {
        const nav = String(navigator.language || 'en').slice(0, 2).toLowerCase();
        _current = LANGUAGES.some(l => l.code === nav) ? nav : 'en';
      }
    } catch { _current = 'en'; }
    applyDirection();
    return _current;
  }

  async function set(code) {
    if (!LANGUAGES.some(l => l.code === code)) return;
    _current = code;
    try { await chrome.storage.local.set({ language: code }); } catch {}
    applyDirection();
  }

  function applyDirection() {
    try {
      const lang = getLanguage(_current);
      const html = document.documentElement;
      html.setAttribute('lang', _current);
      html.setAttribute('dir', lang.dir);
      if (lang.dir === 'rtl') document.body?.classList.add('rtl');
      else document.body?.classList.remove('rtl');
      if (_current === 'fa') document.body?.classList.add('lang-fa');
      else document.body?.classList.remove('lang-fa');
    } catch {}
  }

  function apply(root = document) {
    try {
      root.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        const attr = el.getAttribute('data-i18n-attr');
        const txt = t(key, el.textContent);
        if (attr) el.setAttribute(attr, txt);
        else el.textContent = txt;
      });
      root.querySelectorAll('[data-i18n-html]').forEach(el => {
        const key = el.getAttribute('data-i18n-html');
        el.innerHTML = t(key, el.innerHTML);
      });
      root.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
        el.setAttribute('placeholder', t(el.getAttribute('data-i18n-placeholder'), el.placeholder));
      });
      root.querySelectorAll('[data-i18n-title]').forEach(el => {
        el.setAttribute('title', t(el.getAttribute('data-i18n-title'), el.title));
      });
    } catch {}
  }

  return {
    getLanguages,
    getLanguage,
    getCurrent,
    getDir,
    t,
    load,
    set,
    apply,
    applyDirection
  };
})();

globalThis.CorsairI18n = CorsairI18n;
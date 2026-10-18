<div dir="rtl" align="center">

# 🏴☠️ Corsair Unbound

<strong>سپر مرورگر Local برای Chrome (Manifest V3)</strong>

<p>
  <a href="README.md">🇬🇧 English</a> ·
  <a href="SECURITY.md">🔒 Security</a> ·
  <a href="docs/SECURITY-AUDIT.md">🧪 Security Audit</a> ·
  <a href="docs/UPDATE-POLICY.md">🔄 Update Policy</a>
</p>

<img src="assets/corsair-unbound-hero.png" alt="Corsair Unbound" width="100%">

<strong>نسخه فعلی: v1.9.1</strong>

</div>

Corsair Unbound یک سپر مرورگر **Local-first** برای Chrome Manifest V3 است که روی حفاظت قطعی ناوبری، اجرای Fortress، مهار redirect، تحلیل heuristic، هوش تهدید اختیاری و یک داشبورد کامل محلی تمرکز دارد.

هسته افزونه طوری طراحی شده که منطق حفاظتی و داده‌های کاربر تا حد ممکن روی خود دستگاه باقی بمانند. اتصال اختیاری VirusTotal به‌صورت **BYOK** است؛ یعنی کلید را خود کاربر وارد می‌کند و درخواست‌های مربوط به reputation و analysis مستقیماً به VirusTotal ارسال می‌شوند.

---

## ✨ قابلیت‌ها

### 🛡️ حفاظت

- **Fortress Mode** — قفل‌گذاری روی هر دامنه با قوانین DNR session
- **گارد ناوبری در سطح فریم** — اجرا در همه فریم‌های منطبق، حتی iframeهای شخص ثالث
- **مهار Popup** — تشخیص burst و اعمال cooldown
- **مهار طوفان Redirect** — containment بر پایه سیگنال‌های هوش تهدید
- **محافظ دانلود** — مهار دانلودهای مرتبط با منابع مخرب
- **حذف External Meta Refresh** — جلوگیری از ناوبری خارجی با meta-refresh
- **Content Security Guard** — پوشش سیگنال‌های clipboard، CSP و form-jacking

### 🧠 هوش تهدید

- **VirusTotal BYOK** — اتصال اختیاری با صف و محدودیت نرخ
- **Heuristic Engine** — تشخیص typosquatting، homograph، TLD مشکوک، دامنه‌های تازه‌ثبت‌شده و برند در subdomain
- **Smart Allowlist** — دامنه‌های مورداعتماد داخلی + همگام‌سازی allowlist از راه دور
- **دامنه‌های مورد اعتماد کاربر** — اعتماد با یک کلیک از بنر داخل صفحه
- **Behavior Intelligence** — طبقه‌بندی سیگنال‌ها و تجمیع ریسک در زمان اجرا
- **هوش چندمنبعی** — ترکیب heuristic محلی با providerهای پشتیبانی‌شده

### 🎨 تجربه کاربری

- **رابط چندزبانه** — English، فارسی، العربية، Español، Deutsch، Français، Русский، 中文
- **پشتیبانی کامل RTL** — چینش راست‌به‌چپ برای فارسی و عربی
- **بنر نتیجه درون صفحه** — نمایش verdict محلی‌سازی‌شده
- **Badge افزونه** — نمایش وضعیت امنیتی هر تب
- **کلیدهای میانبر** — Ctrl+Shift+F برای Fortress و Ctrl+Shift+E برای Dashboard
- **داشبورد کامل** — analyzer، Safe List، حریم خصوصی، تنظیمات، API & Intelligence و انتخاب زبان
- **تم روشن/تاریک**
- **بررسی‌کننده داخلی آپدیت** — بررسی امن نسخه در گیت‌هاب، اعلان، و لانچر اختصاصی ویندوز برای آپدیت یک‌کلیکی با تایید هش SHA-256.

### 💾 داده و پایداری

- **Safe Scanned Domains** — کش محلی با جست‌وجو و عملیات گروهی
- **Backup & Restore** — JSON نسخه‌بندی‌شده با حذف فیلدهای حساس
- **Safe List Export/Import** — فایل جداگانه برای جابه‌جایی
- **Privacy Controls** — آمار storage و پاک‌سازی کامل
- **Regression Suite** — تست‌های deterministic replay
- **Security Audit** — بررسی credentialهای واضح و تنظیمات پرریسک manifest

---

## 📦 نصب

### Load unpacked

۱. <code>chrome://extensions</code> را باز کنید  
۲. **Developer mode** را فعال کنید  
۳. روی **Load unpacked** بزنید  
۴. ریشه repository را انتخاب کنید؛ همان پوشه‌ای که <code>manifest.json</code> داخل آن است  
۵. Popup افزونه را باز کنید و وارد Dashboard شوید  
۶. *(اختیاری)* از https://www.virustotal.com/gui/my-apikey یک VirusTotal API Key رایگان بگیرید  
۷. کلید را در **Dashboard → API & Intelligence** وارد کنید  
۸. در صورت نیاز **VirusTotal Threat Intelligence** و **Auto-Scan** را فعال کنید  
۹. زبان موردنظر را انتخاب کنید

> **بعد از آپدیت:** فایل‌های نسخه جدید را جایگزین کنید و سپس در <code>chrome://extensions</code> روی **Reload** بزنید. storage داخلی افزونه حفظ می‌شود.

---

## 🔑 API Key و حریم خصوصی

Corsair Unbound هیچ VirusTotal API Key واقعی را به‌صورت hard-code داخل سورس منتشر نمی‌کند.

### مدل BYOK

- کلید را خود کاربر به‌صورت محلی وارد می‌کند
- هیچ سرور Corsair Unbound کلید را دریافت نمی‌کند
- درخواست‌های VirusTotal در صورت فعال بودن قابلیت مستقیماً به VirusTotal ارسال می‌شوند
- دامنه‌های allowlisted عمداً برای lookup به VirusTotal فرستاده نمی‌شوند
- backup/export فیلدهای قدیمی plaintext API key را حذف می‌کند
- سیاست امنیتی پروژه commit کردن API key، token، password، cookie و private key را ممنوع می‌کند

### نکته مهم درباره storage

کلید فعال خارج از payload معمول settings و با مکانیزم application-level encrypted/obfuscated ذخیره می‌شود.

این کار برای جلوگیری از باقی‌ماندن کلید به شکل plaintext معمولی مفید است، اما **password vault نیست** و در برابر compromise خود افزونه یا مهاجم بسیار قدرتمند روی browser profile مرز امنیتی مطلق ایجاد نمی‌کند؛ چون افزونه باید بتواند کلید را در زمان اجرا بازیابی کند.

برای پاک‌سازی کامل: **Dashboard → Privacy & Data → Wipe ALL Local Data**

جزئیات بیشتر در [SECURITY.md](SECURITY.md) و [Security Audit](docs/SECURITY-AUDIT.md) قرار دارد.

---

## 🔄 سیستم آپدیت

Corsair Unbound دارای یک سیستم آپدیت امن و دو مرحله‌ای است که مخصوص نصب‌های unpacked (بدون نیاز به Chrome Web Store) طراحی شده است.

### نحوه کار
۱. **افزونه** به صورت دوره‌ای یک فایل امن به نام `latest.json` را در صفحه Releases گیت‌هاب بررسی می‌کند.
۲. وقتی نسخه جدیدی پیدا شود، داشبورد به شما اطلاع می‌دهد و لینک صفحه آپدیت را نمایش می‌دهد.
۳. **آپدیتر ویندوز (`updater.ps1`)** کارهای اصلی را انجام می‌دهد. شما آن را یک بار دانلود می‌کنید و این اسکریپت:
   - جدیدترین فایل ZIP افزونه را مستقیماً از گیت‌هاب دانلود می‌کند.
   - هش **SHA-256** فایل را با اطلاعات رسمی مقایسه می‌کند تا از دستکاری نشدن آن مطمئن شود.
   - به طور خودکار یک نسخه پشتیبان (Backup) از افزونه فعلی شما می‌گیرد.
   - فایل‌های افزونه را با امنیت کامل جایگزین می‌کند و به داده‌های شما کاری ندارد.
   - کروم را باز می‌کند تا شما فقط دکمه "Reload" را بزنید.

### امنیت آپدیت
از آنجایی که این یک افزونه امنیتی است، فرآیند آپدیت حول محور یکپارچگی فایل‌ها بنا شده است. آپدیتر از نصب هر فایلی که دقیقاً با هش SHA-256 منتشر شده در ریلیز رسمی مطابقت نداشته باشد خودداری می‌کند. خود افزونه هرگز فایل ZIP را دانلود نمی‌کند تا از هرگونه خطر اجرای کدهای ناخواسته (Remote Code Execution) جلوگیری شود.

---

## ⌨️ کلیدهای میانبر

| میانبر | عملکرد |
|---|---|
| Ctrl+Shift+F | فعال/غیرفعال کردن Fortress روی تب فعلی |
| Ctrl+Shift+E | باز کردن Dashboard |

---

## 🏗️ معماری پروژه

    .
    ├── assets/
    │   └── corsair-unbound-hero.png
    ├── core/
    │   ├── security.js            پاک‌سازی، normalize و validation
    │   ├── storage.js             storage تراکنشی + مدیریت API Key
    │   ├── alarms.js              wrapper برای chrome.alarms
    │   ├── bloom.js               جستجوی سریع در allowlist
    │   ├── dnr.js                 اجرای declarativeNetRequest
    │   ├── redirects.js           ردیابی redirect chain
    │   ├── risk-aggregator.js     محاسبه ریسک چندمنبعی
    │   ├── providers/
    │   │   └── urlhaus.js         سرویس‌دهنده abuse.ch URLhaus (اختیاری)
    │   ├── threat-intel.js        VirusTotal + allowlist intelligence
    │   ├── heuristics.js          heuristicهای typosquat/homograph
    │   ├── intelligence.js        طبقه‌بندی سیگنال
    │   ├── verifier.js            منطق containment
    │   ├── observation.js         مشاهده شبکه
    │   ├── evidence.js            ذخیره شواهد
    │   ├── migration.js           backup/restore نسخه‌بندی‌شده
    │   ├── tool-router.js         API داخلی محدود
    │   ├── replay.js              regression fixtureها
    │   ├── event-filter.js        فیلترهای لاگ فعالیت
    │   ├── i18n.js                ترجمه ۸ زبان + RTL
    │   └── updater.js             بررسی‌کننده آپدیت بر پایه latest.json
    ├── icons/
    ├── launcher/
    │   └── updater.ps1            لانچر امن آپدیت برای ویندوز
    ├── background.js              service worker
    ├── content-frame-guard.js     گارد popup در سطح فریم
    ├── content-main-world.js      محافظ window.open در MAIN world
    ├── content-security-guard.js  گارد clipboard/CSP/form-jacking
    ├── content.js                 بنر و مشاهده در top frame
    ├── popup.html / popup.css / popup.js
    ├── dashboard.html / dashboard.css / dashboard.js
    ├── blocked.html / blocked.js
    ├── manifest.json
    ├── scripts/
    │   ├── build.mjs
    │   └── security-audit.mjs
    ├── tests/
    ├── CHANGELOG.md
    ├── INSTALL.md
    ├── LICENSE
    ├── SECURITY.md
    └── README.md / README.fa.md

---

## 🧪 تست و بررسی

اجرای تست‌های موجود:

    npm ci
    npm test

اجرای security audit:

    node scripts/security-audit.mjs

بررسی blobهای قابل‌دسترسی در تاریخچه Git:

    node scripts/security-audit.mjs --history

اسکریپت audit مقدار secret را چاپ نمی‌کند و فقط نام فایل و نوع finding را گزارش می‌دهد.

---

## 📚 مستندات

- [English README](README.md)
- [README فارسی](README.fa.md)
- [Security Policy](SECURITY.md)
- [Security Audit](docs/SECURITY-AUDIT.md)
- [Update Policy](docs/UPDATE-POLICY.md)
- [Install Guide](INSTALL.md)
- [Changelog](CHANGELOG.md)

---

## 📜 مجوز

MIT — [LICENSE](LICENSE)

</div>
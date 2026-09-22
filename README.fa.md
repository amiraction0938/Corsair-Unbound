# کورسِیر آنباند — Corsair Unbound 1.6.5

<p align="center">
  <strong>نسخه فعلی: 1.6.5</strong>
</p>

<p align="center">
  <img src="assets/corsair-unbound-hero.png" alt="Corsair Unbound" width="100%">
</p>

<h2 align="center">امنیت • آزادی • حق همه است</h2>
<p align="center"><strong>هیچ چیزی ما را محدود نمی‌کند.</strong></p>

<p align="center">
  <a href="README.md"><strong>🇬🇧 English Documentation</strong></a>
</p>

## معرفی

Corsair Unbound یک افزونه امنیتی محلی برای Chrome و Manifest V3 است که روی حفاظت قطعی از ناوبری، Fortress، مهار زنجیره‌های redirect، تحلیل رفتاری و heuristic، اطلاعات تهدید اختیاری و یک داشبورد کامل محلی تمرکز دارد.

## نسخه فعلی

نسخه نهایی پروژه در این مسیر قرار دارد:

`new/Corsair-Unbound-1.6.5/`

فایل‌های مهم:

- `manifest.json` — مشخصات و مجوزهای افزونه
- `background.js` — Service Worker
- `popup.*` — کنترل‌های سریع
- `dashboard.*` — داشبورد کامل
- `core/` — موتورهای امنیت، DNR، ذخیره‌سازی، intelligence و threat intelligence
- `CHANGELOG.md` — تاریخچه تغییرات
- `LICENSE` — مجوز MIT

## قابلیت‌ها

### محافظت

- Fortress Mode برای قفل‌کردن دامنه‌ها با DNR
- مهار popup و new-tab های مشکوک
- مهار redirect storm و زنجیره‌های redirect
- Download Guard
- مسدودسازی قطعی مقصدهای ممنوع
- پشتیبانی از بازیابی وضعیت و TTL مبتنی بر alarm

### هوش و تحلیل

- تشخیص typosquatting
- تشخیص homograph و Punycode/IDN
- تحلیل TLDهای مشکوک
- تحلیل رفتاری و correlation سیگنال‌ها
- Smart Whitelist
- Trusted Domains
- VirusTotal BYOK به‌صورت اختیاری

### رابط کاربری

- Verdict Banner داخل صفحه
- Extension Badge برای وضعیت هر tab
- Keyboard Shortcuts
- Dashboard کامل
- حالت روشن و تاریک
- پشتیبانی چندزبانه

### داده و بازیابی

- ذخیره‌سازی محلی تنظیمات، پروفایل‌ها، evidence و telemetry
- Backup / Restore
- Safe List Export / Import
- Storage statistics و Wipe All
- Replay / Regression
- Incognito Split Mode

## نصب

1. وارد `chrome://extensions` شوید.
2. **Developer mode** را روشن کنید.
3. **Load unpacked** را بزنید.
4. پوشه `new/Corsair-Unbound-1.6.5/` را انتخاب کنید.
5. افزونه را باز کنید و وارد Dashboard شوید.

## حریم خصوصی و API Key

این پروژه با مدل **Local-first** طراحی شده است.

در سورس نسخه 1.6.5 یک VirusTotal API Key یا credential شخصی hard-code نشده است.

پشتیبانی VirusTotal به‌صورت **BYOK (Bring Your Own Key)** است؛ یعنی کلید را خود کاربر در تنظیمات محلی وارد می‌کند و افزونه queryهای پشتیبانی‌شده را مستقیماً برای VirusTotal ارسال می‌کند.

پروفایل‌ها، تنظیمات، observation، evidence و telemetry به‌صورت محلی در extension storage نگهداری می‌شوند؛ مگر اینکه کاربر خودش آنها را export کند.

برای سیاست امنیتی پروژه، [SECURITY.md](SECURITY.md) را ببینید.

## وضعیت سورس

پوشه نسخه فعلی:

`new/Corsair-Unbound-1.6.5/`

سورس‌های قدیمی در root و در `Corsair-Unbound-v8-fixed/` صرفاً برای مرجع تاریخی نگه‌داری شده‌اند.

## مجوز

MIT — فایل [LICENSE](new/Corsair-Unbound-1.6.5/LICENSE).

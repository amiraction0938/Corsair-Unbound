# Corsair Unbound 1.6.5

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

## وضعیت فعلی

نسخه نهایی **1.6.5** مستقیماً در ریشه همین repository قرار دارد.

برای نصب افزونه فقط خودِ repository root را در `chrome://extensions` با گزینه **Load unpacked** انتخاب کنید.

## قابلیت‌ها

- Fortress Mode و اجرای سیاست‌ها با DNR
- مهار popup و redirect
- Download Guard
- تحلیل heuristic و رفتاری
- VirusTotal به‌صورت اختیاری و BYOK
- Smart Whitelist و Trusted Domains
- Dashboard کامل
- Backup / Restore
- Replay / Regression
- مدیریت TTL با alarms
- Incognito Split Mode
- پشتیبانی چندزبانه

## حریم خصوصی و API Key

پروژه Local-first است.

در نسخه 1.6.5 هیچ VirusTotal API Key یا credential شخصی به‌صورت hard-code داخل سورس قرار نگرفته است. کلید VirusTotal توسط خود کاربر در تنظیمات محلی وارد می‌شود و queryهای پشتیبانی‌شده مستقیماً به VirusTotal ارسال می‌شوند.

پروفایل‌ها، تنظیمات، observation، evidence و telemetry در extension storage باقی می‌مانند؛ مگر اینکه کاربر خودش export کند.

راهنمای امنیتی در [SECURITY.md](SECURITY.md) قرار دارد.

## ساختار

```text
.
├── core/
├── icons/
├── assets/
├── background.js
├── content.js
├── popup.*
├── dashboard.*
├── blocked.html
├── manifest.json
├── CHANGELOG.md
├── LICENSE
├── SECURITY.md
├── README.md
└── README.fa.md
```

نسخه‌های قدیمی در Git history باقی می‌مانند و با سورس فعال پروژه قاطی نمی‌شوند.

## مجوز

MIT — [LICENSE](LICENSE)

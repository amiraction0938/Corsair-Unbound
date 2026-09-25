# Corsair Unbound 1.7.0

<p align="center">
  <strong>نسخه فعلی: 1.7.0</strong>
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

نسخه‌ی فعال release line پروژه **1.7.0** است.

در این نسخه Dashboard از یک صفحه‌ی طولانی تنظیمات به یک **Security Command Center** حرفه‌ای تبدیل شده است؛ با ناوبری دسته‌بندی‌شده، وضعیت امنیت، Activity، تحلیل Domain، کنترل‌های امنیتی، Privacy، API و تنظیمات.

## قابلیت‌های مهم

### امنیت
- Fortress Mode و اجرای سیاست‌ها با DNR
- مهار popup، new tab، download و redirect
- محافظت از navigation در frameها
- تحلیل heuristic و رفتاری
- اجرای enforcement پس از verification

### Intelligence
- VirusTotal به‌صورت اختیاری و BYOK
- Domain Intelligence و تحلیل دامنه
- Safe Scanned Domains و Trusted Domains
- دسترسی به تحلیل از Context Menu

### تجربه کاربری
- Dashboard مدرن با Sidebar و Viewهای جدا
- صفحه‌ی Overview و وضعیت فعلی امنیت
- Activity و Evidence جداگانه
- API & Intelligence مستقل
- Onboarding مرحله‌به‌مرحله برای کاربر جدید
- Product Tour تعاملی
- Theme روشن/تیره
- انیمیشن‌های نرم و وضعیت‌های واضح برای loading، success و error

## نصب

1. به `chrome://extensions` بروید.
2. **Developer mode** را فعال کنید.
3. روی **Load unpacked** بزنید.
4. ریشه‌ی repository را انتخاب کنید.
5. از Popup وارد Dashboard شوید.

برای فعال کردن VirusTotal:

1. وارد حساب VirusTotal شوید.
2. API Key خودتان را دریافت کنید.
3. در Dashboard به **API & Intelligence** بروید.
4. کلید را فقط در فرم محلی افزونه وارد کنید.
5. ذخیره و Verify را انجام دهید.

## حریم خصوصی

Corsair Unbound یک پروژه Local-first و BYOK است.

- هیچ API Key شخصی داخل source code قرار ندارد.
- API Key توسط خود کاربر وارد و در storage محلی نگهداری می‌شود.
- queryهای پشتیبانی‌شده مستقیماً به VirusTotal ارسال می‌شوند.
- داده‌ها و telemetry در extension storage باقی می‌مانند، مگر اینکه کاربر خودش export کند.

راهنمای امنیت در [SECURITY.md](SECURITY.md) قرار دارد.

## ساختار

```text
.
├── .github/workflows/
├── assets/
├── core/
├── icons/
├── background.js
├── blocked.html
├── blocked.js
├── content.js
├── content-frame-guard.js
├── popup.*
├── dashboard.*
├── manifest.json
├── CHANGELOG.md
├── SECURITY.md
├── README.md
└── README.fa.md
```

نسخه‌های قدیمی در Git history باقی می‌مانند و با سورس فعال release قاطی نمی‌شوند.

## مجوز

MIT — [LICENSE](LICENSE)

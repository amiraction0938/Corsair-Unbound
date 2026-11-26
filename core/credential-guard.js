/* ============================================================
   CORSAIR UNBOUND — CREDENTIAL & PHISHING FORM GUARD
   ------------------------------------------------------------
   Detects sensitive login, banking, and payment forms using
   structural DOM metadata ONLY.

   PRIVACY INVARIANT:
   NEVER reads input `.value`, NEVER stores credentials or card
   numbers, and NEVER transmits form contents to any external
   service (VirusTotal, URLhaus, or otherwise).
   ============================================================ */
const CorsairCredentialGuard = (() => {
  'use strict';

  const LEGITIMATE_AUTH_PAYMENT_DOMAINS = new Set([
    'accounts.google.com', 'login.microsoftonline.com', 'login.live.com',
    'appleid.apple.com', 'idmsa.apple.com', 'github.com', 'auth0.com',
    'okta.com', 'www.paypal.com', 'paypal.com', 'checkout.stripe.com',
    'js.stripe.com', 'api.stripe.com', 'checkout.shopify.com',
    // Official Iranian payment network (Shaparak) & major PSPs
    'shaparak.ir', 'bpm.shaparak.ir', 'sep.shaparak.ir', 'sadad.shaparak.ir',
    'pep.shaparak.ir', 'asan.shaparak.ir', 'pec.shaparak.ir', 'ikc.shaparak.ir',
    'pna.shaparak.ir', 'fcp.shaparak.ir', 'sepehr.shaparak.ir'
  ]);

  const PROTECTED_BRANDS = [
    // Iranian financial, payment & major services
    { brand: 'shaparak', official: ['shaparak.ir'], category: 'banking' },
    { brand: 'shetab', official: ['shaparak.ir', 'cbi.ir'], category: 'banking' },
    { brand: 'mellat', official: ['bankmellat.ir', 'bpm.shaparak.ir'], category: 'banking' },
    { brand: 'melli', official: ['bmi.ir', 'sadad.shaparak.ir'], category: 'banking' },
    { brand: 'saderat', official: ['bsi.ir'], category: 'banking' },
    { brand: 'tejarat', official: ['tejaratbank.ir'], category: 'banking' },
    { brand: 'saman', official: ['sb24.ir', 'sep.shaparak.ir'], category: 'banking' },
    { brand: 'pasargad', official: ['bpi.ir', 'pep.shaparak.ir'], category: 'banking' },
    { brand: 'digikala', official: ['digikala.com'], category: 'commerce' },
    { brand: 'snapp', official: ['snapp.ir', 'snappfood.ir', 'snapp.market'], category: 'commerce' },
    { brand: 'shad', official: ['shad.ir', 'web.shad.ir'], category: 'public' },
    { brand: 'divar', official: ['divar.ir'], category: 'commerce' },
    // Global high-value brands
    { brand: 'paypal', official: ['paypal.com'], category: 'banking' },
    { brand: 'google', official: ['google.com', 'accounts.google.com'], category: 'auth' },
    { brand: 'microsoft', official: ['microsoft.com', 'live.com', 'microsoftonline.com'], category: 'auth' },
    { brand: 'apple', official: ['apple.com', 'icloud.com'], category: 'auth' },
    { brand: 'amazon', official: ['amazon.com', 'amazon.co.uk', 'amazon.de'], category: 'commerce' }
  ];

  const CARD_ATTR_RE = /\b(cc-number|cc-exp|cc-csc|cardnumber|card-number|card_number|cvv|cvv2|cvc|pan|shomare.?kart|شماره\s*کارت|رمز\s*دوم|رمز\s*پویا|انقضا|شاپرک)\b/i;
  const PASS_ATTR_RE = /\b(current-password|new-password|password|passwd|passcode|pin|رمز\s*عبور|گذرواژه|کلمه\s*عبور)\b/i;
  const AUTH_ATTR_RE = /\b(email|e-mail|username|user_name|login|userid|ایمیل|نام\s*کاربری)\b/i;

  function normalizeHost(raw) {
    return String(raw || '').trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  }

  function isLoopback(host) {
    const h = normalizeHost(host);
    return h === 'localhost' || h.endsWith('.localhost') || h === '127.0.0.1' || h === '::1';
  }

  function hostMatchesDomain(host, domain) {
    const h = normalizeHost(host);
    const d = normalizeHost(domain);
    return h === d || h.endsWith('.' + d);
  }

  function registrableDomain(host) {
    const parts = normalizeHost(host).split('.').filter(Boolean);
    if (parts.length <= 2) return parts.join('.');
    const sld = parts[parts.length - 2];
    if (['co', 'com', 'org', 'net', 'gov', 'edu', 'ac'].includes(sld) && parts.length >= 3) {
      return parts.slice(-3).join('.');
    }
    return parts.slice(-2).join('.');
  }

  function isLegitimateDestination(host) {
    const h = normalizeHost(host);
    for (const allowed of LEGITIMATE_AUTH_PAYMENT_DOMAINS) {
      if (hostMatchesDomain(h, allowed)) return true;
    }
    return false;
  }

  /**
   * Inspect a descriptor of form fields (or a DOM Form element) WITHOUT ever reading `.value`.
   * Returns { sensitive, categories: ['password'|'payment'|'credential'], fieldCount }.
   */
  function analyzeFormFields(fieldsOrForm) {
    const categories = new Set();
    let fieldCount = 0;
    let fields = [];

    if (Array.isArray(fieldsOrForm)) {
      fields = fieldsOrForm;
    } else if (fieldsOrForm && typeof fieldsOrForm.querySelectorAll === 'function') {
      const inputs = Array.from(fieldsOrForm.querySelectorAll('input, textarea'));
      fields = inputs.map((el) => {
        let labelText = '';
        try {
          if (el.id && fieldsOrForm.ownerDocument) {
            const lbl = fieldsOrForm.ownerDocument.querySelector(`label[for="${CSS.escape ? CSS.escape(el.id) : el.id}"]`);
            if (lbl) labelText = String(lbl.textContent || '');
          }
          if (!labelText && typeof el.closest === 'function') {
            const parentLbl = el.closest('label');
            if (parentLbl) labelText = String(parentLbl.textContent || '');
          }
        } catch {}
        return {
          type: String(el.getAttribute ? (el.getAttribute('type') || '') : (el.type || '')).toLowerCase(),
          autocomplete: String(el.getAttribute ? (el.getAttribute('autocomplete') || '') : (el.autocomplete || '')).toLowerCase(),
          name: String(el.getAttribute ? (el.getAttribute('name') || '') : (el.name || '')),
          id: String(el.getAttribute ? (el.getAttribute('id') || '') : (el.id || '')),
          placeholder: String(el.getAttribute ? (el.getAttribute('placeholder') || '') : (el.placeholder || '')),
          ariaLabel: String(el.getAttribute ? (el.getAttribute('aria-label') || '') : (el.ariaLabel || '')),
          label: labelText
        };
      });
    }

    for (const f of fields) {
      if (!f || typeof f !== 'object') continue;
      const type = String(f.type || '').toLowerCase();
      if (type === 'hidden' || type === 'submit' || type === 'button' || type === 'checkbox' || type === 'radio') continue;
      fieldCount++;
      const ac = String(f.autocomplete || '').toLowerCase();
      const metaBlob = [ac, f.name, f.id, f.placeholder, f.ariaLabel, f.label].filter(Boolean).join(' ');

      if (type === 'password' || ac === 'current-password' || ac === 'new-password' || PASS_ATTR_RE.test(metaBlob)) {
        categories.add('password');
      }
      if (ac === 'cc-number' || ac === 'cc-exp' || ac === 'cc-csc' || CARD_ATTR_RE.test(metaBlob)) {
        categories.add('payment');
      }
      if (type === 'email' || ac === 'username' || ac === 'email' || AUTH_ATTR_RE.test(metaBlob)) {
        categories.add('credential');
      }
    }

    const cats = Array.from(categories);
    // Email/username alone is only sensitive when paired with password/payment or explicit login context
    const sensitive = categories.has('password') || categories.has('payment');
    return { sensitive, categories: cats, fieldCount };
  }

  function detectBrandImpersonation(host) {
    const h = normalizeHost(host);
    if (!h) return null;
    for (const entry of PROTECTED_BRANDS) {
      if (entry.official.some((dom) => hostMatchesDomain(h, dom))) return null;
      if (h.includes(entry.brand)) {
        return { brand: entry.brand, category: entry.category, official: entry.official[0] };
      }
    }
    // Punycode homograph signal
    if (h.includes('xn--')) {
      return { brand: 'punycode-idn', category: 'homograph', official: '' };
    }
    return null;
  }

  /**
   * Evaluate risk of submitting a sensitive form from `pageUrl` to `actionUrl`.
   * Pure function — zero side effects, zero credential value access.
   */
  function evaluateSubmission({
    pageUrl,
    actionUrl,
    fields,
    trustedHosts = [],
    offlineThreatHit = false,
    reputationRisk = 0
  }) {
    const fieldInfo = analyzeFormFields(fields);
    if (!fieldInfo.sensitive) {
      return { risk: 0, severity: 'none', shouldWarn: false, reasons: [], categories: fieldInfo.categories };
    }

    let pageParsed, destParsed;
    try { pageParsed = new URL(String(pageUrl || '')); } catch { return { risk: 0, severity: 'none', shouldWarn: false, reasons: [], categories: fieldInfo.categories }; }
    try { destParsed = new URL(String(actionUrl || pageUrl || ''), pageParsed.href); } catch { destParsed = pageParsed; }

    const pageHost = normalizeHost(pageParsed.hostname);
    const destHost = normalizeHost(destParsed.hostname);
    const trusted = Array.isArray(trustedHosts) && trustedHosts.some((t) => hostMatchesDomain(pageHost, t));
    if (trusted || isLoopback(pageHost)) {
      return { risk: 0, severity: 'none', shouldWarn: false, reasons: ['trusted-or-local'], categories: fieldInfo.categories, pageHost, destHost };
    }

    const reasons = [];
    let score = 0;

    // 1. Insecure HTTP page or HTTP submission destination
    if (pageParsed.protocol === 'http:') {
      score += fieldInfo.categories.includes('payment') ? 55 : 40;
      reasons.push('insecure-http-page');
    }
    if (destParsed.protocol === 'http:') {
      score += fieldInfo.categories.includes('payment') ? 60 : 45;
      reasons.push('insecure-http-action');
    }

    // 2. Cross-origin submission to an unrecognized host
    const crossDomain = registrableDomain(pageHost) !== registrableDomain(destHost);
    if (crossDomain && !isLegitimateDestination(destHost)) {
      score += 45;
      reasons.push('cross-origin-destination');
    }

    // 3. Brand impersonation / Iranian banking & payment gateway spoofing / IDN homograph
    const pageBrand = detectBrandImpersonation(pageHost);
    const destBrand = detectBrandImpersonation(destHost);
    const impersonation = pageBrand || destBrand;
    if (impersonation) {
      score += impersonation.category === 'banking' ? 70 : 50;
      reasons.push(`brand-impersonation:${impersonation.brand}`);
    }

    // 4. Offline threat intelligence or reputation score
    if (offlineThreatHit) {
      score += 60;
      reasons.push('offline-threat-match');
    }
    if (Number(reputationRisk) >= 40) {
      score += Math.min(50, Math.round(Number(reputationRisk) * 0.6));
      reasons.push('elevated-domain-risk');
    }

    const risk = Math.min(100, score);
    const severity = risk >= 70 ? 'critical' : risk >= 40 ? 'high' : risk >= 25 ? 'medium' : 'none';

    return {
      risk,
      severity,
      shouldWarn: risk >= 40,
      reasons,
      categories: fieldInfo.categories,
      pageHost,
      destHost,
      destinationUrl: destParsed.origin + destParsed.pathname,
      impersonation
    };
  }

  return {
    analyzeFormFields,
    detectBrandImpersonation,
    isLegitimateDestination,
    evaluateSubmission,
    LEGITIMATE_AUTH_PAYMENT_DOMAINS
  };
})();

globalThis.CorsairCredentialGuard = CorsairCredentialGuard;

const CorsairHeuristics = (() => {
  'use strict';

  const POPULAR_BRANDS = [
    'google','facebook','instagram','whatsapp','telegram','youtube',
    'apple','microsoft','amazon','paypal','netflix','twitter','linkedin',
    'github','dropbox','spotify','discord','tiktok','reddit','wikipedia',
    'digikala','aparat','divar','torob','bama','snapp','cafebazaar','shad'
  ];

  const SUSPICIOUS_TLDS = new Set([
    'tk','ml','ga','cf','gq',
    'top','xyz','work','click','loan','review','country','stream',
    'download','racing','win','bid','party','trade','science','gdn',
    'date','faith','cricket','accountant','men','link','zip','mov',
    'cfd','sbs','rest','quest','monster','cyou','beauty','hair','skin'
  ]);

  const HIGH_RISK_TLDS = new Set(['tk','ml','ga','cf','gq','top','xyz','zip','mov']);

  const DIGIT_MAP = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
    '6': 'g', '7': 't', '8': 'b', '9': 'g'
  };

  function levenshtein(a, b) {
    if (a === b) return 0;
    if (!a.length) return b.length;
    if (!b.length) return a.length;
    if (a.length > 60 || b.length > 60) return 999;
    const m = a.length, n = b.length;
    const prev = new Array(n + 1);
    const curr = new Array(n + 1);
    for (let j = 0; j <= n; j++) prev[j] = j;
    for (let i = 1; i <= m; i++) {
      curr[0] = i;
      for (let j = 1; j <= n; j++) {
        const cost = a.charCodeAt(i - 1) === b.charCodeAt(j - 1) ? 0 : 1;
        curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
      }
      for (let j = 0; j <= n; j++) prev[j] = curr[j];
    }
    return prev[n];
  }

  const KNOWN_SECOND_LEVEL = new Set(['co','com','org','net','gov','edu','ac','sch']);

  function getTld(host) {
    const parts = String(host || '').toLowerCase().split('.').filter(Boolean);
    return parts.length ? parts[parts.length - 1] : '';
  }

  function getSecondLevelLabel(host) {
    const parts = String(host || '').toLowerCase().split('.').filter(Boolean);
    if (parts.length < 2) return '';
    if (parts.length >= 3 && KNOWN_SECOND_LEVEL.has(parts[parts.length - 2])) {
      return parts[parts.length - 3] || '';
    }
    return parts[parts.length - 2] || '';
  }

  function isPunycode(host) {
    return /(^|\.)xn--/i.test(String(host || ''));
  }

  function hasMixedScripts(host) {
    const h = String(host || '');
    if (!h) return false;
    const hasLatin = /[a-z]/i.test(h);
    const hasCyrillic = /[\u0400-\u04FF]/.test(h);
    const hasGreek = /[\u0370-\u03FF]/.test(h);
    const hasArabic = /[\u0600-\u06FF\u0750-\u077F]/.test(h);
    const hasHebrew = /[\u0590-\u05FF]/.test(h);
    const hasOther = hasCyrillic || hasGreek || hasArabic || hasHebrew;
    return hasLatin && hasOther;
  }

  function stripDigits(label) {
    let out = '';
    for (const ch of String(label || '')) out += DIGIT_MAP[ch] || ch;
    return out;
  }

  function stripHyphens(label) {
    return String(label || '').replace(/-/g, '');
  }

  /* ------------------------------------------------------------------
     BEST-MATCH BRAND DETECTION
     ------------------------------------------------------------------
     The previous code iterated POPULAR_BRANDS and `break`-ed at the
     first hit. So "amaz0n-paypal" would report only whichever brand
     happened to be earlier in the array, not the CLOSEST match. This
     version scores every candidate brand and returns the best one
     using:
       1. Lowest edit distance (after normalization for digit/hyphen)
       2. Tiebreak: highest points (most specific signal wins)
     Exact matches score 0 points and are excluded.
     ------------------------------------------------------------------ */

  function findBestBrandMatch(label) {
    if (!label || label.length < 3) return null;

    const noDigits = stripDigits(label);
    const noHyphens = stripHyphens(label);
    const noBoth = stripHyphens(noDigits);

    let best = null;

    for (const brand of POPULAR_BRANDS) {
      if (label === brand) return null; // exact real domain — no signal

      let candidate = null;

      // Substitution patterns are treated as "distance 1" — they are
      // deliberate, targeted obfuscation, more severe than a generic
      // edit-distance match.
      if (noDigits === brand) {
        candidate = {
          kind: 'typosquatting-digits',
          brand,
          points: 40,
          editDistance: 1,
          message: `Looks like "${brand}" using digit substitution`
        };
      } else if (noHyphens === brand) {
        candidate = {
          kind: 'typosquatting-hyphens',
          brand,
          points: 35,
          editDistance: 1,
          message: `Looks like "${brand}" with hyphens`
        };
      } else if (noBoth === brand) {
        candidate = {
          kind: 'typosquatting-mixed',
          brand,
          points: 40,
          editDistance: 1,
          message: `Resembles "${brand}" after normalizing`
        };
      } else {
        const d = levenshtein(label, brand);
        if (d > 0 && d <= 2 && Math.abs(label.length - brand.length) <= 2) {
          candidate = {
            kind: 'typosquatting-levenshtein',
            brand,
            distance: d,
            points: d === 1 ? 35 : 25,
            editDistance: d + 1, // de-prioritize generic edits vs. substitutions
            message: `Very similar to "${brand}" (edit distance ${d})`
          };
        }
      }

      if (!candidate) continue;

      if (
        !best ||
        candidate.editDistance < best.editDistance ||
        (candidate.editDistance === best.editDistance && candidate.points > best.points)
      ) {
        best = candidate;
      }
    }

    return best;
  }

  function analyze(rawHost, options = {}) {
    const host = String(rawHost || '').toLowerCase();
    if (!host) return { risk: 0, signals: [], label: '', tld: '' };

    const signals = [];
    const label = getSecondLevelLabel(host);
    const tld = getTld(host);

    if (SUSPICIOUS_TLDS.has(tld)) {
      signals.push({
        kind: 'suspicious-tld',
        tld,
        points: HIGH_RISK_TLDS.has(tld) ? 30 : 15,
        message: `Uses high-risk TLD ".${tld}"`
      });
    }

    if (isPunycode(host)) {
      signals.push({
        kind: 'punycode',
        points: 25,
        message: 'Internationalized domain (xn-- encoding)'
      });
    }

    if (hasMixedScripts(host)) {
      signals.push({
        kind: 'homograph',
        points: 45,
        message: 'Domain mixes Latin with non-Latin characters'
      });
    }

    // Best-match typosquatting (not first-match)
    const brandMatch = findBestBrandMatch(label);
    if (brandMatch) signals.push(brandMatch);

    const hyphens = (label.match(/-/g) || []).length;
    if (hyphens >= 3) {
      signals.push({
        kind: 'excessive-hyphens',
        points: 15,
        message: `${hyphens} hyphens in domain label`
      });
    }

    if (label.length > 25) {
      signals.push({
        kind: 'very-long-label',
        points: 10,
        message: 'Unusually long domain label'
      });
    }

    const creationDate = Number(options.creationDate) || 0;
    if (creationDate > 0) {
      const ageDays = Math.floor((Date.now() - creationDate * 1000) / 86400000);
      if (ageDays >= 0 && ageDays < 30) {
        signals.push({
          kind: 'recently-registered',
          ageDays,
          points: 30,
          message: `Domain registered only ${ageDays} day(s) ago`
        });
      } else if (ageDays >= 30 && ageDays < 90) {
        signals.push({
          kind: 'new-domain',
          ageDays,
          points: 15,
          message: `Domain registered ${ageDays} days ago`
        });
      }
    }

    const dotCount = (host.match(/\./g) || []).length;
    if (dotCount >= 4) {
      signals.push({
        kind: 'deep-subdomains',
        points: 15,
        message: `Deeply nested subdomains (${dotCount} levels)`
      });
    }

    const parts = host.split('.');
    if (parts.length >= 3) {
      const subparts = parts.slice(0, -2);
      let brandInSub = null;
      for (const brand of POPULAR_BRANDS) {
        if (subparts.some(p => p.includes(brand)) && !label.includes(brand)) {
          brandInSub = brand;
          break;
        }
      }
      if (brandInSub) {
        signals.push({
          kind: 'brand-in-subdomain',
          brand: brandInSub,
          points: 30,
          message: `"${brandInSub}" appears in subdomain but not main domain`
        });
      }
    }

    const risk = Math.min(100, signals.reduce((s, x) => s + (x.points || 0), 0));
    return { risk, signals, label, tld };
  }

  return {
    analyze,
    isSuspiciousTld: (tld) => SUSPICIOUS_TLDS.has(String(tld || '').toLowerCase()),
    getSecondLevelLabel,
    getTld,
    levenshtein,
    findBestBrandMatch
  };
})();

globalThis.CorsairHeuristics = CorsairHeuristics;
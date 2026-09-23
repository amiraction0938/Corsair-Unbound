const CorsairThreatIntel = (() => {
  'use strict';

  // ============================================================
  // BUILT-IN WHITELIST — popular + trusted + Iranian
  // ============================================================
  const BUILTIN_ALLOWLIST = new Set([
    // Google
    'google.com','www.google.com','google.ir','www.google.ir','accounts.google.com','apis.google.com',
    'gstatic.com','googleapis.com','googlevideo.com','youtube.com','www.youtube.com','youtu.be',
    'i.ytimg.com','ytimg.com','ggpht.com','googleusercontent.com','blogger.com','blogspot.com',
    'gmail.com','mail.google.com','drive.google.com','docs.google.com','maps.google.com',
    'play.google.com','photos.google.com','meet.google.com','chrome.google.com',
    // Microsoft
    'microsoft.com','www.microsoft.com','live.com','outlook.com','office.com','office365.com',
    'azure.com','msn.com','bing.com','windows.com','windowsupdate.com','microsoftonline.com',
    'sharepoint.com','onedrive.com','skype.com','visualstudio.com','xbox.com','msftconnecttest.com',
    // Apple
    'apple.com','www.apple.com','icloud.com','itunes.com','me.com','mzstatic.com',
    // Mozilla
    'mozilla.org','addons.mozilla.org','firefox.com',
    // GitHub / Dev
    'github.com','www.github.com','github.io','raw.githubusercontent.com','githubusercontent.com',
    'gitlab.com','bitbucket.org','stackoverflow.com','stackexchange.com','npmjs.com','npmjs.org',
    'python.org','nodejs.org','rust-lang.org','golang.org','java.com','oracle.com',
    'docker.com','dockerhub.com','kubernetes.io','vercel.com','netlify.com','heroku.com',
    'cloudflare.com','one.one.one.one','cdnjs.cloudflare.com','jsdelivr.net','unpkg.com',
    // Social
    'facebook.com','www.facebook.com','fb.com','fbcdn.net','instagram.com','www.instagram.com',
    'twitter.com','x.com','t.co','twimg.com','linkedin.com','www.linkedin.com','licdn.com',
    'reddit.com','www.reddit.com','redd.it','redditmedia.com','pinterest.com','tumblr.com',
    'tiktok.com','snapchat.com','discord.com','discord.gg','telegram.org','t.me',
    'web.telegram.org','whatsapp.com','web.whatsapp.com','signal.org',
    // Streaming / Media
    'netflix.com','spotify.com','twitch.tv','vimeo.com','dailymotion.com','soundcloud.com',
    'hulu.com','disneyplus.com','primevideo.com','hbomax.com',
    // Shopping
    'amazon.com','www.amazon.com','amazon.co.uk','amazon.de','amazon.in','ebay.com','etsy.com',
    'aliexpress.com','alibaba.com','walmart.com','target.com','bestbuy.com',
    // Wikipedia / Knowledge
    'wikipedia.org','en.wikipedia.org','fa.wikipedia.org','wikimedia.org','wiktionary.org',
    'wikidata.org','mediawiki.org',
    // News
    'bbc.com','bbc.co.uk','cnn.com','nytimes.com','washingtonpost.com','theguardian.com',
    'reuters.com','apnews.com','aljazeera.com','bloomberg.com','wsj.com','forbes.com',
    // Iranian popular
    'digikala.com','www.digikala.com','aparat.com','www.aparat.com','varzesh3.com',
    'divar.ir','www.divar.ir','torob.com','bama.ir','filimo.com','namava.ir','snapp.ir',
    'snappfood.ir','tapsi.ir','alibaba.ir','yektaa.com','shad.ir','irancell.ir','mci.ir',
    'bmi.ir','bankmellat.ir','bsi.ir','banksepah.ir','tejaratbank.ir','parsian-bank.ir',
    'sadad.ir','shaparak.ir','cbi.ir','bourse.ir','tsetmc.com','karnameh.com',
    'arvancloud.com','arvancloud.ir','parspack.com','iranserver.com','mizbanfa.net',
    'khabaronline.ir','isna.ir','irna.ir','mehrnews.com','tabnak.ir','entekhab.ir',
    'zoomit.ir','donya-e-eqtesad.com','hamshahrionline.ir','yjc.ir','farsnews.ir',
    'cafebazaar.ir','myket.ir','sibapp.com','sibirani.com','divar.ir',
    'blog.ir','mihanblog.com','persianblog.ir','bayan.ir','porsline.ir',
    // Email / Productivity
    'yahoo.com','yandex.com','proton.me','protonmail.com','zoho.com','slack.com',
    'notion.so','trello.com','asana.com','monday.com','figma.com','canva.com',
    'zoom.us','webex.com','miro.com','airtable.com',
    // Payments
    'paypal.com','stripe.com','visa.com','mastercard.com','americanexpress.com',
    // CDN / Infrastructure
    'akamaihd.net','akamaized.net','fastly.net','cloudfront.net','amazonaws.com',
    'azureedge.net','fbcdn.net','edgecastcdn.net',
    // OS / Browsers
    'ubuntu.com','debian.org','redhat.com','centos.org','fedoraproject.org',
    'linux.org','kernel.org','archlinux.org','chromium.org','opera.com','brave.com',
    'vivaldi.com','edge.microsoft.com',
    // Education
    'coursera.org','edx.org','udemy.com','khanacademy.org','duolingo.com','w3schools.com',
    // File storage
    'dropbox.com','mega.nz','box.com','mediafire.com','wetransfer.com',
    // Misc trusted
    'archive.org','imdb.com','booking.com','airbnb.com','tripadvisor.com',
    'wordpress.com','medium.com','substack.com','ghost.org','squarespace.com',
    'wix.com','shopify.com','duckduckgo.com','ecosia.org','startpage.com'
  ]);

  // ============================================================
  // REMOTE WHITELIST — Cisco OpenDNS top domains
  // ============================================================
  const REMOTE_WHITELIST_URL =
    'https://raw.githubusercontent.com/opendns/public-domain-lists/master/opendns-top-domains.txt';

  const REMOTE_SYNC_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 1 week
  const REMOTE_MAX_DOMAINS = 20000;

  let _remoteAllowlist = null;
  let _remoteLoaded = false;

  // ============================================================
  // USER-TRUSTED DOMAINS (from "Trust permanently" button on banner)
  // ============================================================
  let _userTrustedCache = new Set();

  async function refreshUserTrusted() {
    try {
      const list = await CorsairStorage.get('userTrustedDomains', []);
      _userTrustedCache = new Set(Array.isArray(list) ? list : []);
    } catch {
      _userTrustedCache = new Set();
    }
    return _userTrustedCache;
  }

  async function loadRemoteAllowlist() {
    if (_remoteLoaded) return _remoteAllowlist;
    try {
      const cached = await CorsairStorage.get('remoteWhitelist', null);
      if (cached && Array.isArray(cached.domains) && cached.domains.length) {
        _remoteAllowlist = new Set(cached.domains);
        _remoteLoaded = true;
        if (!cached.syncedAt || Date.now() - cached.syncedAt > REMOTE_SYNC_TTL_MS) {
          refreshRemoteAllowlist().catch(() => {});
        }
        return _remoteAllowlist;
      }
    } catch {}
    try {
      await refreshRemoteAllowlist();
    } catch {}
    _remoteLoaded = true;
    return _remoteAllowlist || new Set();
  }

  async function refreshRemoteAllowlist() {
    try {
      const res = await fetch(REMOTE_WHITELIST_URL, { cache: 'no-store' });
      if (!res.ok) throw new Error(`fetch-failed-${res.status}`);
      const text = await res.text();
      const domains = text
        .split(/\r?\n/)
        .map(s => s.trim().toLowerCase())
        .filter(s => s && !s.startsWith('#') && s.length < 253)
        .filter(s => /^[a-z0-9.-]+$/.test(s))
        .slice(0, REMOTE_MAX_DOMAINS);
      _remoteAllowlist = new Set(domains);
      _remoteLoaded = true;
      await CorsairStorage.withPartitionLock('globalSettings', async () => {
        await CorsairStorage.set('remoteWhitelist', {
          domains,
          syncedAt: Date.now(),
          source: 'opendns-top-domains'
        });
      });
      return { ok: true, count: domains.length };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  }

  function isAllowlisted(rawHost) {
    const host = CorsairSecurity.normalizeHostname(rawHost);
    if (!host) return false;

    // 1) User-trusted domains (from banner "Trust permanently")
    if (_userTrustedCache.size) {
      if (_userTrustedCache.has(host)) return true;
      for (const base of _userTrustedCache) {
        if (CorsairSecurity.sameOrSubdomain(host, base)) return true;
      }
    }

    // 2) Localhost / private ranges
    if (host === 'localhost' || host === '127.0.0.1' || host === '0.0.0.0') return true;
    if (/^10\./.test(host) || /^192\.168\./.test(host) || /^172\.(1[6-9]|2\d|3[01])\./.test(host)) return true;
    if (host.endsWith('.local') || host.endsWith('.lan') || host.endsWith('.internal')) return true;

    // 3) Built-in allowlist
    if (BUILTIN_ALLOWLIST.has(host)) return true;
    for (const base of BUILTIN_ALLOWLIST) {
      if (CorsairSecurity.sameOrSubdomain(host, base)) return true;
    }

    // 4) Remote allowlist (OpenDNS)
    if (_remoteAllowlist) {
      if (_remoteAllowlist.has(host)) return true;
      const parts = host.split('.');
      if (parts.length > 2) {
        const parent = parts.slice(-2).join('.');
        if (_remoteAllowlist.has(parent)) return true;
      }
    }
    return false;
  }

  // ============================================================
  // API KEY
  // ============================================================
  async function getApiKey() {
    const settings = await CorsairStorage.getSettings();
    return (settings?.vtApiKey || '').trim();
  }

  // ============================================================
  // CACHE
  // ============================================================
  const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24h

  async function getCachedReport(rawHost) {
    const host = CorsairSecurity.normalizeHostname(rawHost);
    if (!host) return null;
    if (isAllowlisted(host)) {
      return {
        host,
        status: 'allowlisted',
        verdict: 'clean',
        riskPercentage: 0,
        flaggedEngines: [],
        stats: { harmless: 85, malicious: 0, suspicious: 0, undetected: 0 },
        lastChecked: Date.now(),
        cached: true
      };
    }
    const cache = await CorsairStorage.get('threatCache', {});
    const entry = cache[host];
    if (!entry) return null;
    if (entry.lastChecked && Date.now() - entry.lastChecked > CACHE_TTL_MS) {
      return { ...entry, stale: true };
    }
    return entry;
  }

  async function saveReport(host, report) {
    return CorsairStorage.withTransactionGateShared(async () => {
      return CorsairStorage.withPartitionLock('threatCache', async () => {
        const cache = await CorsairStorage.get('threatCache', {});
        cache[host] = { ...report, lastChecked: Date.now() };
        await CorsairStorage.set('threatCache', cache);
      });
    });
  }

  async function clearCache() {
    await CorsairStorage.set('threatCache', {});
  }

  // ============================================================
  // VT QUERY
  // ============================================================
  async function executeVtQuery(host, apiKey) {
    const url = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(host)}`;
    const res = await fetch(url, {
      headers: { 'x-apikey': apiKey, 'Accept': 'application/json' }
    });

    if (res.status === 401 || res.status === 403) throw new Error('invalid-api-key');
    if (res.status === 429) throw new Error('rate-limit-exceeded');
    if (res.status === 404) {
      // 404 = not indexed by VT. Run heuristics only.
      let heuristicSignals = [];
      let heuristicRisk = 0;
      try {
        if (typeof CorsairHeuristics !== 'undefined') {
          const h = CorsairHeuristics.analyze(host, {});
          heuristicSignals = h.signals || [];
          heuristicRisk = h.risk || 0;
        }
      } catch {}

      let verdict = 'clean';
      if (heuristicRisk >= 80) verdict = 'malicious';
      else if (heuristicRisk >= 45) verdict = 'suspicious';

      return {
        host, status: 'analyzed', verdict,
        riskPercentage: heuristicRisk,
        flaggedEngines: [],
        stats: { harmless: 0, malicious: 0, suspicious: 0, undetected: 0 },
        heuristicSignals,
        heuristicRisk,
        vtNotIndexed: true
      };
    }
    if (!res.ok) throw new Error(`vt-status-${res.status}`);

    const data = await res.json();
    const attrs = data?.data?.attributes || {};
    const stats = attrs.last_analysis_stats || { harmless: 0, malicious: 0, suspicious: 0, undetected: 0 };
    const results = attrs.last_analysis_results || {};

    const flaggedEngines = [];
    for (const [engineName, resObj] of Object.entries(results)) {
      if (resObj.category === 'malicious' || resObj.category === 'phishing' || resObj.category === 'suspicious') {
        flaggedEngines.push(engineName);
      }
    }

    const totalEngines = Object.values(stats).reduce((a, b) => a + b, 0) || 1;
    const maliciousCount = stats.malicious || 0;
    const suspiciousCount = stats.suspicious || 0;

    let riskPercentage = Math.round(((maliciousCount * 2 + suspiciousCount) / totalEngines) * 100);
    if (maliciousCount >= 2) riskPercentage = Math.max(riskPercentage, 75);
    if (maliciousCount >= 4) riskPercentage = Math.max(riskPercentage, 95);

    let verdict = 'clean';
    if (maliciousCount >= 2) verdict = 'malicious';
    else if (maliciousCount > 0 || suspiciousCount >= 2) verdict = 'suspicious';

    // ---- Heuristics analysis ----
    let heuristicSignals = [];
    let heuristicRisk = 0;
    try {
      if (typeof CorsairHeuristics !== 'undefined') {
        const h = CorsairHeuristics.analyze(host, { creationDate: attrs.creation_date });
        heuristicSignals = h.signals || [];
        heuristicRisk = h.risk || 0;
      }
    } catch {}

    // Merge heuristic risk into verdict
    const combinedRisk = Math.min(100, Math.max(riskPercentage, heuristicRisk));
    if (heuristicRisk >= 80 && verdict !== 'malicious') verdict = 'malicious';
    else if (heuristicRisk >= 45 && verdict === 'clean') verdict = 'suspicious';

    return {
      host, status: 'analyzed', verdict,
      riskPercentage: combinedRisk,
      flaggedEngines: flaggedEngines.slice(0, 12),
      stats,
      reputation: attrs.reputation || 0,
      categories: attrs.categories || {},
      lastAnalysisDate: attrs.last_analysis_date || null,
      whois: attrs.whois || '',
      creationDate: attrs.creation_date || null,
      heuristicSignals,
      heuristicRisk
    };
  }

  // ============================================================
  // QUEUE / RATE LIMIT
  // ============================================================
  const RATE_LIMIT_WINDOW_MS = 60 * 1000;
  const MAX_REQUESTS_PER_WINDOW = 4;
  const MIN_REQUEST_INTERVAL_MS = 15000;

  let _requestTimestamps = [];
  let _lastRequestTime = 0;
  let _queue = [];
  let _isProcessingQueue = false;

  async function processQueue() {
    if (_isProcessingQueue || _queue.length === 0) return;
    _isProcessingQueue = true;
    while (_queue.length > 0) {
      const now = Date.now();
      _requestTimestamps = _requestTimestamps.filter(t => now - t < RATE_LIMIT_WINDOW_MS);

      if (_requestTimestamps.length >= MAX_REQUESTS_PER_WINDOW) {
        const oldest = _requestTimestamps[0];
        const waitMs = (RATE_LIMIT_WINDOW_MS - (now - oldest)) + 500;
        await new Promise(r => setTimeout(r, waitMs));
        continue;
      }
      const elapsed = now - _lastRequestTime;
      if (elapsed < MIN_REQUEST_INTERVAL_MS) {
        await new Promise(r => setTimeout(r, MIN_REQUEST_INTERVAL_MS - elapsed));
        continue;
      }
      const item = _queue.shift();
      if (!item) break;
      try {
        _requestTimestamps.push(Date.now());
        _lastRequestTime = Date.now();
        const rep = await executeVtQuery(item.host, item.apiKey);
        await saveReport(item.host, rep);
        item.resolve(rep);
      } catch (err) {
        item.reject(err);
      }
    }
    _isProcessingQueue = false;
  }

  function queryDomain(rawHost, { force = false } = {}) {
    const host = CorsairSecurity.normalizeHostname(rawHost);
    if (!host) return Promise.reject(new Error('invalid-hostname'));

    if (!force && isAllowlisted(host)) {
      return Promise.resolve({
        host, status: 'allowlisted', verdict: 'clean',
        riskPercentage: 0, flaggedEngines: [],
        stats: { harmless: 85, malicious: 0, suspicious: 0, undetected: 0 }
      });
    }

    return new Promise(async (resolve, reject) => {
      if (!force) {
        const cached = await getCachedReport(host);
        if (cached && !cached.stale) return resolve(cached);
      }
      const apiKey = await getApiKey();
      if (!apiKey) return reject(new Error('no-api-key'));
      _queue.push({ host, apiKey, resolve, reject });
      processQueue().catch(() => {});
    });
  }

  /**
   * Auto-scan helper: enqueue a non-blocking query for background scan.
   * Resolves with report or null. Never throws.
   */
  async function autoScan(rawHost) {
    const host = CorsairSecurity.normalizeHostname(rawHost);
    if (!host) return null;
    if (isAllowlisted(host)) {
      return {
        host, status: 'allowlisted', verdict: 'clean',
        riskPercentage: 0, flaggedEngines: [],
        stats: { harmless: 85, malicious: 0, suspicious: 0, undetected: 0 },
        auto: true
      };
    }
    try {
      const report = await queryDomain(host, { force: false });
      return { ...report, auto: true };
    } catch (err) {
      return { host, status: 'error', error: err.message, auto: true };
    }
  }

  return {
    isAllowlisted,
    getCachedReport,
    queryDomain,
    autoScan,
    clearCache,
    refreshRemoteAllowlist,
    loadRemoteAllowlist,
    refreshUserTrusted,
    getAllowlistSize: () => ({
      builtin: BUILTIN_ALLOWLIST.size,
      remote: _remoteAllowlist ? _remoteAllowlist.size : 0,
      userTrusted: _userTrustedCache.size
    })
  };
})();

globalThis.CorsairThreatIntel = CorsairThreatIntel;
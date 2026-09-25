const CorsairThreatIntel = (() => {
  'use strict';

  /* ============================================================
     BUILT-IN WHITELIST
     ============================================================ */
  const BUILTIN_ALLOWLIST = new Set([
    'google.com','www.google.com','google.ir','www.google.ir','accounts.google.com','apis.google.com',
    'gstatic.com','googleapis.com','googlevideo.com','youtube.com','www.youtube.com','youtu.be',
    'i.ytimg.com','ytimg.com','ggpht.com','googleusercontent.com','blogger.com','blogspot.com',
    'gmail.com','mail.google.com','drive.google.com','docs.google.com','maps.google.com',
    'play.google.com','photos.google.com','meet.google.com','chrome.google.com',
    'microsoft.com','www.microsoft.com','live.com','outlook.com','office.com','office365.com',
    'azure.com','msn.com','bing.com','windows.com','windowsupdate.com','microsoftonline.com',
    'sharepoint.com','onedrive.com','skype.com','visualstudio.com','xbox.com','msftconnecttest.com',
    'apple.com','www.apple.com','icloud.com','itunes.com','me.com','mzstatic.com',
    'mozilla.org','addons.mozilla.org','firefox.com',
    'github.com','www.github.com','github.io','raw.githubusercontent.com','githubusercontent.com',
    'gitlab.com','bitbucket.org','stackoverflow.com','stackexchange.com','npmjs.com','npmjs.org',
    'python.org','nodejs.org','rust-lang.org','golang.org','java.com','oracle.com',
    'docker.com','dockerhub.com','kubernetes.io','vercel.com','netlify.com','heroku.com',
    'cloudflare.com','one.one.one.one','cdnjs.cloudflare.com','jsdelivr.net','unpkg.com',
    'facebook.com','www.facebook.com','fb.com','fbcdn.net','instagram.com','www.instagram.com',
    'twitter.com','x.com','t.co','twimg.com','linkedin.com','www.linkedin.com','licdn.com',
    'reddit.com','www.reddit.com','redd.it','redditmedia.com','pinterest.com','tumblr.com',
    'tiktok.com','snapchat.com','discord.com','discord.gg','telegram.org','t.me',
    'web.telegram.org','whatsapp.com','web.whatsapp.com','signal.org',
    'netflix.com','spotify.com','twitch.tv','vimeo.com','dailymotion.com','soundcloud.com',
    'hulu.com','disneyplus.com','primevideo.com','hbomax.com',
    'amazon.com','www.amazon.com','amazon.co.uk','amazon.de','amazon.in','ebay.com','etsy.com',
    'aliexpress.com','alibaba.com','walmart.com','target.com','bestbuy.com',
    'wikipedia.org','en.wikipedia.org','fa.wikipedia.org','wikimedia.org','wiktionary.org',
    'wikidata.org','mediawiki.org',
    'bbc.com','bbc.co.uk','cnn.com','nytimes.com','washingtonpost.com','theguardian.com',
    'reuters.com','apnews.com','aljazeera.com','bloomberg.com','wsj.com','forbes.com',
    'digikala.com','www.digikala.com','aparat.com','www.aparat.com','varzesh3.com',
    'divar.ir','www.divar.ir','torob.com','bama.ir','filimo.com','namava.ir','snapp.ir',
    'snappfood.ir','tapsi.ir','alibaba.ir','yektaa.com','shad.ir','irancell.ir','mci.ir',
    'bmi.ir','bankmellat.ir','bsi.ir','banksepah.ir','tejaratbank.ir','parsian-bank.ir',
    'sadad.ir','shaparak.ir','cbi.ir','bourse.ir','tsetmc.com','karnameh.com',
    'arvancloud.com','arvancloud.ir','parspack.com','iranserver.com','mizbanfa.net',
    'khabaronline.ir','isna.ir','irna.ir','mehrnews.com','tabnak.ir','entekhab.ir',
    'zoomit.ir','donya-e-eqtesad.com','hamshahrionline.ir','yjc.ir','farsnews.ir',
    'cafebazaar.ir','myket.ir','sibapp.com','sibirani.com',
    'blog.ir','mihanblog.com','persianblog.ir','bayan.ir','porsline.ir',
    'yahoo.com','yandex.com','proton.me','protonmail.com','zoho.com','slack.com',
    'notion.so','trello.com','asana.com','monday.com','figma.com','canva.com',
    'zoom.us','webex.com','miro.com','airtable.com',
    'paypal.com','stripe.com','visa.com','mastercard.com','americanexpress.com',
    'akamaihd.net','akamaized.net','fastly.net','cloudfront.net','amazonaws.com',
    'azureedge.net','edgecastcdn.net',
    'ubuntu.com','debian.org','redhat.com','centos.org','fedoraproject.org',
    'linux.org','kernel.org','archlinux.org','chromium.org','opera.com','brave.com',
    'vivaldi.com','edge.microsoft.com',
    'coursera.org','edx.org','udemy.com','khanacademy.org','duolingo.com','w3schools.com',
    'dropbox.com','mega.nz','box.com','mediafire.com','wetransfer.com',
    'archive.org','imdb.com','booking.com','airbnb.com','tripadvisor.com',
    'wordpress.com','medium.com','substack.com','ghost.org','squarespace.com',
    'wix.com','shopify.com','duckduckgo.com','ecosia.org','startpage.com'
  ]);

  const REMOTE_WHITELIST_URL =
    'https://raw.githubusercontent.com/opendns/public-domain-lists/master/opendns-top-domains.txt';

  const REMOTE_SYNC_TTL_MS = 7 * 24 * 60 * 60 * 1000;
  const REMOTE_MAX_DOMAINS = 20000;

  let _remoteAllowlist = null;
  let _remoteLoaded = false;

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

    if (_userTrustedCache.size) {
      if (_userTrustedCache.has(host)) return true;
      for (const base of _userTrustedCache) {
        if (CorsairSecurity.sameOrSubdomain(host, base)) return true;
      }
    }

    if (host === 'localhost' || host === '127.0.0.1' || host === '0.0.0.0') return true;
    if (/^10\./.test(host) || /^192\.168\./.test(host) || /^172\.(1[6-9]|2\d|3[01])\./.test(host)) return true;
    if (host.endsWith('.local') || host.endsWith('.lan') || host.endsWith('.internal')) return true;

    if (BUILTIN_ALLOWLIST.has(host)) return true;
    for (const base of BUILTIN_ALLOWLIST) {
      if (CorsairSecurity.sameOrSubdomain(host, base)) return true;
    }

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

  async function getApiKey() {
    return CorsairStorage.getApiKeySecure();
  }

  const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

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

  /* ============================================================
     RATE LIMIT — shared across all VT calls
     ============================================================ */
  const RATE_LIMIT_WINDOW_MS = 60 * 1000;
  const MAX_REQUESTS_PER_WINDOW = 4;
  const MIN_REQUEST_INTERVAL_MS = 15000;

  let _requestTimestamps = [];
  let _lastRequestTime = 0;
  let _queue = [];
  let _isProcessingQueue = false;

  async function reserveRateLimitSlot() {
    for (;;) {
      const now = Date.now();
      _requestTimestamps = _requestTimestamps.filter(t => now - t < RATE_LIMIT_WINDOW_MS);
      if (_requestTimestamps.length >= MAX_REQUESTS_PER_WINDOW) {
        const oldest = _requestTimestamps[0];
        await new Promise(r => setTimeout(r, (RATE_LIMIT_WINDOW_MS - (now - oldest)) + 500));
        continue;
      }
      const elapsed = now - _lastRequestTime;
      if (elapsed < MIN_REQUEST_INTERVAL_MS) {
        await new Promise(r => setTimeout(r, MIN_REQUEST_INTERVAL_MS - elapsed));
        continue;
      }
      _requestTimestamps.push(Date.now());
      _lastRequestTime = Date.now();
      return;
    }
  }

  /* ============================================================
     VIRUSTOTAL REQUEST WRAPPER
     ============================================================ */
  async function vtGetJson(path, apiKey) {
    await reserveRateLimitSlot();
    const url = 'https://www.virustotal.com/api/v3/' + path;
    const res = await fetch(url, {
      headers: { 'x-apikey': apiKey, 'Accept': 'application/json' }
    });
    if (res.status === 401 || res.status === 403) throw new Error('invalid-api-key');
    if (res.status === 429) throw new Error('rate-limit-exceeded');
    if (res.status === 404) return null;   // not indexed — treat as empty
    if (!res.ok) throw new Error(`vt-status-${res.status}`);
    return res.json();
  }

  /* ============================================================
     BASE DOMAIN QUERY (single VT request)
     ============================================================ */
  async function executeVtQuery(host, apiKey) {
    const data = await vtGetJson(`domains/${encodeURIComponent(host)}`, apiKey);

    if (!data || !data.data) {
      // Not indexed by VT. Fall back to heuristics only.
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

    const attrs = data.data.attributes || {};
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

    const popularityRanks = attrs.popularity_ranks || {};
    const bestPopularityRank = Object.values(popularityRanks)
      .map(p => Number(p?.rank))
      .filter(n => Number.isFinite(n) && n > 0)
      .sort((a, b) => a - b)[0] || null;

    const totalVotes = attrs.total_votes || { harmless: 0, malicious: 0 };
    const tags = Array.isArray(attrs.tags) ? attrs.tags : [];
    const cert = attrs.last_https_certificate || null;
    const certIssuer = cert?.issuer?.O || cert?.issuer?.CN || null;
    const certValidTo = cert?.validity?.not_after || null;

    const dnsRecords = Array.isArray(attrs.last_dns_records)
      ? attrs.last_dns_records
          .filter(r => ['A', 'AAAA', 'MX', 'NS'].includes(r.type))
          .slice(0, 8)
          .map(r => ({ type: r.type, value: r.value }))
      : [];

    let heuristicSignals = [];
    let heuristicRisk = 0;
    try {
      if (typeof CorsairHeuristics !== 'undefined') {
        const h = CorsairHeuristics.analyze(host, { creationDate: attrs.creation_date });
        heuristicSignals = h.signals || [];
        heuristicRisk = h.risk || 0;
      }
    } catch {}

    if (bestPopularityRank && bestPopularityRank <= 500000) {
      heuristicRisk = Math.max(0, heuristicRisk - 25);
    }

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
      popularityRanks,
      bestPopularityRank,
      totalVotes,
      tags,
      certIssuer,
      certValidTo,
      dnsRecords,
      heuristicSignals,
      heuristicRisk
    };
  }

  /* ============================================================
     DEEP SCAN — Relationships
     ============================================================ */

  const DEEP_SUBDOMAIN_LIMIT = 40;
  const DEEP_FILE_LIMIT = 15;

  /**
   * Turn a VT file/object entry into a compact summary suitable for
   * storage and UI rendering. Avoids carrying the full JSON:API blob
   * (which is easily 10x the size) into local storage.
   */
  function summarizeFileEntry(file) {
    if (!file || typeof file !== 'object') return null;
    const attrs = file.attributes || {};
    const stats = attrs.last_analysis_stats || {};
    const names = Array.isArray(attrs.names) ? attrs.names : [];
    const name = attrs.meaningful_name || names[0] || 'unknown';
    return {
      sha256: String(file.id || '').slice(0, 64),
      name: String(name).slice(0, 200),
      type: String(attrs.type_description || attrs.type_tag || 'unknown').slice(0, 60),
      size: Number(attrs.size) || 0,
      malicious: Number(stats.malicious) || 0,
      suspicious: Number(stats.suspicious) || 0,
      harmless: Number(stats.harmless) || 0,
      undetected: Number(stats.undetected) || 0
    };
  }

  async function fetchSubdomains(host, apiKey) {
    const data = await vtGetJson(
      `domains/${encodeURIComponent(host)}/subdomains?limit=${DEEP_SUBDOMAIN_LIMIT}`,
      apiKey
    );
    if (!data || !Array.isArray(data.data)) return [];
    return data.data
      .map(item => String(item.id || '').trim().toLowerCase())
      .filter(s => s && s.length < 253 && /^[a-z0-9.-]+$/.test(s))
      .slice(0, DEEP_SUBDOMAIN_LIMIT);
  }

  async function fetchCommunicatingFiles(host, apiKey) {
    const data = await vtGetJson(
      `domains/${encodeURIComponent(host)}/communicating_files?limit=${DEEP_FILE_LIMIT}`,
      apiKey
    );
    if (!data || !Array.isArray(data.data)) return [];
    return data.data
      .map(summarizeFileEntry)
      .filter(Boolean)
      .slice(0, DEEP_FILE_LIMIT);
  }

  async function fetchDownloadedFiles(host, apiKey) {
    const data = await vtGetJson(
      `domains/${encodeURIComponent(host)}/downloaded_files?limit=${DEEP_FILE_LIMIT}`,
      apiKey
    );
    if (!data || !Array.isArray(data.data)) return [];
    return data.data
      .map(summarizeFileEntry)
      .filter(Boolean)
      .slice(0, DEEP_FILE_LIMIT);
  }

  /**
   * Deep-scan a domain: base VT report + 3 relationship endpoints.
   * Total VT budget cost: 4 requests (~1 full minute of the free tier).
   *
   * The base report is cached; the relationships are NOT (they change
   * frequently and VT does not expose cheap ETags for them). If a
   * relationship fetch fails (404 or rate-limit), the section is
   * returned empty rather than aborting the whole scan.
   */
  async function deepScan(rawHost) {
    const host = CorsairSecurity.normalizeHostname(rawHost);
    if (!host) throw new Error('invalid-hostname');

    const apiKey = await getApiKey();
    if (!apiKey) throw new Error('no-api-key');

    // 1) Base report (uses cache if fresh; forces VT call otherwise)
    const base = await queryDomain(host, { force: false });

    // 2) Relationships — 3 extra VT requests, capped by the shared
    //    rate limiter. Failures degrade to empty arrays.
    const [subdomains, communicatingFiles, downloadedFiles] = await Promise.all([
      fetchSubdomains(host, apiKey).catch(() => []),
      fetchCommunicatingFiles(host, apiKey).catch(() => []),
      fetchDownloadedFiles(host, apiKey).catch(() => [])
    ]);

    const enriched = {
      ...base,
      relationships: {
        subdomains,
        communicatingFiles,
        downloadedFiles,
        scannedAt: Date.now()
      },
      deepScannedAt: Date.now()
    };

    await saveReport(host, enriched);
    return enriched;
  }

  /* ============================================================
     QUEUE / RATE LIMIT FOR BASE QUERIES
     ============================================================ */
  async function processQueue() {
    if (_isProcessingQueue || _queue.length === 0) return;
    _isProcessingQueue = true;
    while (_queue.length > 0) {
      const item = _queue.shift();
      if (!item) break;
      // Rate-limit is enforced inside vtGetJson() — reserving here too
      // would double-charge every request and add a spurious 15s wait.
      try {
        const rep = await executeVtQuery(item.host, item.apiKey);
        await saveReport(item.host, rep);
        item.resolve(rep);
      } catch (err) {
        item.reject(err);
      }
    }
    _isProcessingQueue = false;
  }

  /* ============================================================
     URL SCAN
     ============================================================ */
  const URL_POLL_ATTEMPTS = 8;
  const URL_POLL_INTERVAL_MS = 3000;

  async function scanUrl(rawUrl) {
    if (!rawUrl || typeof rawUrl !== 'string') throw new Error('invalid-url');
    let parsed;
    try { parsed = new URL(rawUrl); } catch { throw new Error('invalid-url'); }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') throw new Error('invalid-url');

    const apiKey = await getApiKey();
    if (!apiKey) throw new Error('no-api-key');

    await reserveRateLimitSlot();
    const submitRes = await fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: { 'x-apikey': apiKey, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `url=${encodeURIComponent(parsed.href)}`
    });
    if (submitRes.status === 401 || submitRes.status === 403) throw new Error('invalid-api-key');
    if (submitRes.status === 429) throw new Error('rate-limit-exceeded');
    if (!submitRes.ok) throw new Error(`vt-url-submit-${submitRes.status}`);
    const submitData = await submitRes.json();
    const analysisId = submitData?.data?.id;
    if (!analysisId) throw new Error('vt-url-no-analysis-id');

    for (let i = 0; i < URL_POLL_ATTEMPTS; i++) {
      await new Promise(r => setTimeout(r, i === 0 ? 2000 : URL_POLL_INTERVAL_MS));
      await reserveRateLimitSlot();
      const res = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
        headers: { 'x-apikey': apiKey, 'Accept': 'application/json' }
      });
      if (!res.ok) continue;
      const data = await res.json();
      const attrs = data?.data?.attributes || {};
      if (attrs.status !== 'completed') continue;

      const stats = attrs.stats || { harmless: 0, malicious: 0, suspicious: 0, undetected: 0 };
      const results = attrs.results || {};
      const flaggedEngines = [];
      for (const [engineName, resObj] of Object.entries(results)) {
        if (resObj.category === 'malicious' || resObj.category === 'phishing' || resObj.category === 'suspicious') {
          flaggedEngines.push(engineName);
        }
      }
      const maliciousCount = stats.malicious || 0;
      const suspiciousCount = stats.suspicious || 0;
      let verdict = 'clean';
      if (maliciousCount >= 2) verdict = 'malicious';
      else if (maliciousCount > 0 || suspiciousCount >= 2) verdict = 'suspicious';

      return {
        url: parsed.href, host: parsed.hostname, status: 'analyzed', verdict,
        stats, flaggedEngines: flaggedEngines.slice(0, 12), analysisId
      };
    }
    return { url: parsed.href, host: parsed.hostname, status: 'pending', analysisId };
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
    scanUrl,
    deepScan,
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
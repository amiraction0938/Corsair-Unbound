/* ============================================================
   CORSAIR BLOCK-PAGE ACTIONS
   ------------------------------------------------------------
   What the "site blocked" page can do for the user:

   - explain():             WHY the site was blocked
   - proceedWithFortress(): unblock it, but keep strict protection on
   - markFalsePositive():   it is safe: trust it and undo everything
                            Corsair did automatically to it
   - blockAndIsolate():     it is dangerous: keep it blocked, put it in
                            Fortress, and delete the data it stored

   Everything is injected through `deps`, so the sequences are tested
   without a browser. Every step reports success or the exact error
   (nothing is swallowed), and a required step that fails stops the
   action so the page never claims something that did not happen.
   ============================================================ */
const CorsairBlockActions = (() => {
  'use strict';

  const SNOOZE_MS = 24 * 60 * 60 * 1000;

  // Origin-scoped data types supported by chrome.browsingData.remove({ origins })
  const SITE_DATA_TYPES = Object.freeze({
    cacheStorage: true,
    cookies: true,
    fileSystems: true,
    indexedDB: true,
    localStorage: true,
    serviceWorkers: true,
    webSQL: true
  });

  /** http(s) origins of the host and of its www. twin. */
  function originsFor(host) {
    const h = String(host || '').trim().toLowerCase();
    if (!h || !/^[a-z0-9.-]+$/.test(h)) return [];
    const bare = h.startsWith('www.') ? h.slice(4) : h;
    const names = new Set([h, bare, 'www.' + bare]);
    const out = [];
    for (const n of names) out.push(`https://${n}`, `http://${n}`);
    return out;
  }

  function newRun() {
    const steps = [];
    return {
      steps,
      async step(name, fn, required = false) {
        try {
          const r = await fn();
          if (r && r.ok === false) throw new Error(r.error || 'failed');
          steps.push({ name, ok: true });
          return true;
        } catch (err) {
          steps.push({ name, ok: false, error: (err && err.message) || String(err), required });
          return false;
        }
      },
      failedRequired() { return steps.find(s => !s.ok && s.required) || null; }
    };
  }

  function result(run, extra = {}) {
    const failed = run.failedRequired();
    return {
      ok: !failed,
      error: failed ? `${failed.name}: ${failed.error}` : '',
      steps: run.steps,
      ...extra
    };
  }

  async function safe(fn, fallback) {
    try { return await fn(); } catch { return fallback; }
  }

  /* ---------- why was it blocked? ---------- */
  async function explain(host, deps) {
    const [blocked, report, profile, settings, events] = await Promise.all([
      safe(() => deps.getBlocked(), []),
      safe(() => deps.getReport(host), null),
      safe(() => deps.getProfile(host), null),
      safe(() => deps.getSettings(), {}),
      safe(() => deps.findAutoBlockEvent(host), null)
    ]);

    const risk = report && Number.isFinite(Number(report.riskPercentage)) ? Number(report.riskPercentage) : null;
    const stats = (report && report.stats) || {};
    const flagged = Array.isArray(report && report.flaggedEngines) ? report.flaggedEngines.length : (Number(stats.malicious) || 0);

    return {
      host,
      trusted: Boolean(await safe(() => deps.isTrusted(host), false)),
      inBlocklist: Array.isArray(blocked) && blocked.includes(host),
      auto: events ? {
        at: events.timestamp || events.ts || null,
        reason: String(events.reason || '')
      } : null,
      report: report ? {
        risk,
        verdict: report.verdict || report.status || 'unknown',
        flagged,
        malicious: Number(stats.malicious) || 0,
        suspicious: Number(stats.suspicious) || 0,
        categories: Array.isArray(report.categories) ? report.categories.slice(0, 4) : [],
        scannedAt: report.lastChecked || null
      } : null,
      thresholds: {
        autoBlock: Number(settings && settings.autoBlockThreshold) || 75
      },
      profile: profile ? {
        protected: profile.protected === true,
        autoArmed: profile.autoArmed === true
      } : null
    };
  }

  const fortressPatch = (now, extra = {}) => (current) => {
    const next = {
      ...(current || {}),
      protected: true,
      mode: 'fortress',
      autoContainRedirects: true,
      clickbaitGuard: true,
      ...extra
    };
    return next;
  };

  /* ---------- back to the site, Fortress ON ---------- */
  async function proceedWithFortress(host, deps) {
    const run = newRun();
    const now = deps.now ? deps.now() : Date.now();

    if (!await run.step('unblock', () => deps.unblockDomain(host), true)) return result(run);

    await run.step('fortress-on', () => deps.patchProfile(host, (current) => {
      const next = fortressPatch(now, { autoBlockSnoozeUntil: now + SNOOZE_MS, userProceededAt: now })(current);
      delete next.autoArmed;               // a manual choice, not an automatic one
      return next;
    }), true);

    await run.step('log', () => deps.logEvent({
      type: 'user_proceed_fortress', domain: host, severity: 'info',
      reason: 'user reopened a blocked site with Fortress on'
    }));

    return result(run, { redirectUrl: `https://${host}/` });
  }

  /* ---------- false positive: trust it and undo our automatic actions ---------- */
  async function markFalsePositive(host, deps) {
    const run = newRun();
    const now = deps.now ? deps.now() : Date.now();

    const before = await safe(() => deps.getReport(host), null);
    const profile = await safe(() => deps.getProfile(host), null);

    // trustDomain also removes the host from the blocklist and refreshes the in-memory allowlist
    if (!await run.step('trust', () => deps.trustDomain(host), true)) return result(run);

    // an auto-armed Fortress profile would keep containing the site even though it is trusted
    if (profile && profile.autoArmed === true) {
      await run.step('disarm-auto-fortress', () => deps.patchProfile(host, (current) => ({
        ...(current || {}), protected: false, mode: 'standard', autoArmed: false,
        autoBlockSnoozeUntil: undefined
      })));
    }

    // the stored "malicious" verdict must not come back as a banner or an auto-block decision
    await run.step('forget-verdict', () => deps.dropThreatCache(host));
    await run.step('forget-autoarm', () => deps.forgetAutoArm(host));

    await run.step('log', () => deps.logEvent({
      type: 'false_positive', domain: host, severity: 'info',
      reason: before
        ? `user marked as safe (was risk ${Number(before.riskPercentage) || 0}%, verdict ${before.verdict || before.status || 'unknown'})`
        : 'user marked as safe'
    }));

    return result(run, { redirectUrl: `https://${host}/`, markedAt: now });
  }

  /* ---------- dangerous: keep blocked, isolate, delete its data ---------- */
  async function blockAndIsolate(host, deps) {
    const run = newRun();
    const now = deps.now ? deps.now() : Date.now();

    // blockDomain also removes the host from the trusted list
    if (!await run.step('block', () => deps.blockDomain(host), true)) return result(run);

    await run.step('fortress-on', () => deps.patchProfile(host, (current) => {
      const next = fortressPatch(now)(current);
      delete next.autoBlockSnoozeUntil;
      delete next.autoArmed;
      return next;
    }));

    const origins = originsFor(host);
    await run.step('wipe-site-data', () => deps.clearSiteData(origins));

    await run.step('forget-verdict', () => deps.dropThreatCache(host));
    await run.step('forget-autoarm', () => deps.forgetAutoArm(host));

    await run.step('log', () => deps.logEvent({
      type: 'user_block_isolated', domain: host, severity: 'medium',
      reason: 'user blocked the site, isolated it and deleted its stored data'
    }));

    return result(run, { newTab: true, wiped: origins });
  }

  /**
   * Only the TOP-LEVEL frame of our own block page, showing exactly this host, may trigger the
   * actions. blocked.html is web-accessible, so another site can frame it; a framed copy (or any
   * other extension page / frame) is refused.
   */
  function isBlockPageSender(sender, host, { baseUrl, normalizeHostname }) {
    try {
      if (!sender || sender.frameId !== 0 || !sender.tab || !Number.isInteger(sender.tab.id)) return false;
      if (typeof sender.url !== 'string' || !baseUrl || !sender.url.startsWith(baseUrl)) return false;
      const rest = sender.url.slice(baseUrl.length);
      if (rest && !/^[?#]/.test(rest)) return false;                 // blocked.html.evil/ etc.
      const shown = new URL(sender.url).searchParams.get('host') || '';
      const a = normalizeHostname(shown);
      return Boolean(a) && a === normalizeHostname(host || '');
    } catch { return false; }
  }

  return { SNOOZE_MS, SITE_DATA_TYPES, originsFor, explain, proceedWithFortress, markFalsePositive, blockAndIsolate, isBlockPageSender };
})();

globalThis.CorsairBlockActions = CorsairBlockActions;

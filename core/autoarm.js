/* ============================================================
   CORSAIR AUTO-ARM / AUTO-BLOCK
   ------------------------------------------------------------
   Decides, from a threat report and the user's settings, whether
   a site should automatically get Fortress protection or be added
   to the global blocklist, and applies that decision.

   Design rules (security first):
   - The decision is a PURE function (`decide`) so it can be tested
     exhaustively. Every outcome carries a machine-readable `reason`.
   - The decision never depends on display-only settings such as the
     verdict banner.
   - Nothing fails silently: apply errors are retried once and then
     logged as an `auto_arm_failed` event.
   - The user's explicit opt-out (`profile.autoArmed === false`) is
     always respected for Fortress, but never prevents blocking a
     site that is at or above the auto-block threshold.
   ============================================================ */
const CorsairAutoArm = (() => {
  'use strict';

  const DEFAULT_ARM = 10;
  const DEFAULT_BLOCK = 75;
  const MAX_BLOCKLIST = 500;

  const REASON = Object.freeze({
    DISABLED: 'disabled',
    NO_REPORT: 'no-report',
    REPORT_ERROR: 'report-error',
    ALLOWLISTED: 'allowlisted',
    BELOW_THRESHOLD: 'below-threshold',
    USER_OPT_OUT: 'user-opt-out',
    ALREADY_PROTECTED: 'already-protected',
    ARM: 'arm',
    BLOCK: 'block'
  });

  // IMPORTANT: Number(null), Number('') and Number(false) are all 0, which would
  // clamp to 1% and make EVERY site with 1% risk get blocked. Only real numbers
  // and non-empty numeric strings are accepted; anything else uses the default.
  function clampPct(value, fallback) {
    let n = NaN;
    if (typeof value === 'number') n = value;
    else if (typeof value === 'string' && value.trim() !== '') n = Number(value);
    if (!Number.isFinite(n)) return fallback;
    return Math.min(100, Math.max(1, n));
  }

  function resolveThresholds(settings) {
    const s = settings || {};
    return {
      armMin: clampPct(s.autoArmFortressThreshold, DEFAULT_ARM),
      blockMin: clampPct(s.autoBlockThreshold, DEFAULT_BLOCK)
    };
  }

  function reportRisk(report) {
    const n = Number(report && report.riskPercentage);
    return Number.isFinite(n) ? n : 0;
  }

  /**
   * @returns {{action:'none'|'arm'|'block', reason:string, risk:number,
   *            armMin:number, blockMin:number, armProfile:boolean, addToBlocklist:boolean}}
   */
  function decide({ settings, report, profile, isAllowlisted, isBlocked, now }) {
    const { armMin, blockMin } = resolveThresholds(settings);
    const risk = reportRisk(report);
    const base = { action: 'none', risk, armMin, blockMin, armProfile: false, addToBlocklist: false };

    if (!settings || settings.autoArmFortress === false) return { ...base, reason: REASON.DISABLED };
    if (!report) return { ...base, reason: REASON.NO_REPORT };
    if (report.status === 'error') return { ...base, reason: REASON.REPORT_ERROR };
    if (report.status === 'allowlisted' || isAllowlisted) return { ...base, reason: REASON.ALLOWLISTED };
    if (risk < armMin) return { ...base, reason: REASON.BELOW_THRESHOLD };

    const optedOut = Boolean(profile) && profile.autoArmed === false;
    const protectedNow = Boolean(profile) && profile.protected === true;

    // The user explicitly chose "back to the site (Fortress on)" on the block page: do not
    // auto-block again for a while (otherwise the same scan would block it on the next page).
    const t0 = Number.isFinite(now) ? now : Date.now();
    const snoozed = Boolean(profile) && Number(profile.autoBlockSnoozeUntil) > t0;

    if (risk >= blockMin && !snoozed) {
      return {
        ...base,
        action: 'block',
        reason: REASON.BLOCK,
        addToBlocklist: !isBlocked,
        armProfile: !optedOut && !protectedNow
      };
    }

    if (optedOut) return { ...base, reason: REASON.USER_OPT_OUT };
    if (protectedNow) return { ...base, reason: REASON.ALREADY_PROTECTED };
    return { ...base, action: 'arm', reason: REASON.ARM, armProfile: true };
  }

  const defaultSleep = (ms) => new Promise(r => setTimeout(r, ms));

  async function patchWithRetry(deps, host, mutator) {
    const sleep = deps.sleep || defaultSleep;
    let last = null;
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        last = await deps.patchProfile(host, mutator);
        if (last && last.ok) return last;
      } catch (err) {
        last = { ok: false, error: (err && err.message) || String(err) };
      }
      if (attempt === 0) await sleep(deps.retryDelayMs ?? 400);
    }
    return last || { ok: false, error: 'no-result' };
  }

  /**
   * Evaluate and apply. `deps` is injected so this can be tested without a browser:
   *   getSettings, isAllowlisted(host), getProfile(host), getUserBlocked(),
   *   addBlocked(host), patchProfile(host, mutator), logEvent(evt),
   *   addEvidence(evt), remember(host, diagnostic), now(), sleep(ms)
   */
  async function evaluate(host, report, deps, opts = {}) {
    const source = opts.source || 'scan';
    const now = deps.now ? deps.now() : Date.now();
    const settings = await deps.getSettings();

    let isAllowlisted = false;
    try { isAllowlisted = Boolean(await deps.isAllowlisted(host)); } catch {}

    const [profile, blockedList] = await Promise.all([
      deps.getProfile(host),
      deps.getUserBlocked()
    ]);
    const isBlocked = Array.isArray(blockedList) && blockedList.includes(host);

    const d = decide({ settings, report, profile, isAllowlisted, isBlocked, now });
    const diag = { host, at: now, source, ...d, applied: false, error: '' };

    if (d.action === 'none') {
      try { await deps.remember(host, diag); } catch {}
      return diag;
    }

    const verdict = (report && report.verdict) || 'unknown';

    // ---------- block ----------
    if (d.action === 'block' && d.addToBlocklist) {
      try {
        await deps.addBlocked(host);
        await deps.logEvent({
          type: 'auto_block', domain: host, severity: 'high',
          reason: `auto-blocked at risk ${d.risk}% (threshold ${d.blockMin}%)`
        });
        try { await deps.addEvidence({ kind: 'auto_block', origin: host, tabId: null, data: { risk: d.risk, threshold: d.blockMin, verdict } }); } catch {}
        diag.applied = true;
      } catch (err) {
        diag.error = (err && err.message) || 'block-failed';
        try { await deps.logEvent({ type: 'auto_arm_failed', domain: host, severity: 'medium', reason: `auto-block failed: ${diag.error}` }); } catch {}
      }
    }

    // ---------- arm (also part of the block path) ----------
    if (d.armProfile) {
      const reasonText = d.action === 'block'
        ? `auto-blocked at risk ${d.risk}% (threshold ${d.blockMin}%)`
        : `risk ${d.risk}% ≥ ${d.armMin}%`;
      const res = await patchWithRetry(deps, host, (current) => ({
        ...(current || {}),
        protected: true,
        mode: 'fortress',
        autoContainRedirects: true,
        clickbaitGuard: true,
        autoArmed: true,
        autoArmedAt: now,
        autoArmReason: reasonText
      }));

      if (res && res.ok) {
        diag.applied = true;
        if (d.action === 'arm') {
          try {
            await deps.logEvent({
              type: 'auto_fortress_armed', domain: host,
              severity: d.risk >= 60 ? 'high' : 'medium',
              reason: `auto-armed at risk ${d.risk}% (threshold ${d.armMin}%)`
            });
          } catch {}
          try { await deps.addEvidence({ kind: 'auto_fortress_armed', origin: host, tabId: null, data: { risk: d.risk, threshold: d.armMin, verdict } }); } catch {}
        }
      } else {
        diag.error = (res && res.error) || 'arm-failed';
        try {
          await deps.logEvent({
            type: 'auto_arm_failed', domain: host, severity: 'medium',
            reason: `could not arm Fortress at risk ${d.risk}%: ${diag.error}`
          });
        } catch {}
      }
    }

    try { await deps.remember(host, diag); } catch {}
    return diag;
  }

  /**
   * The verdict banner is shown once per tab + host (a "visit"), not on every in-page route
   * change (Instagram "next post", YouTube video links, ...), and not again on reloads.
   */
  function createBannerGate() {
    const shown = new Map();
    return {
      shouldShow(tabId, host) {
        if (!Number.isInteger(tabId) || !host) return false;
        if (shown.get(tabId) === host) return false;
        shown.set(tabId, host);
        return true;
      },
      reset(tabId) { shown.delete(tabId); },
      peek(tabId) { return shown.get(tabId) || null; }
    };
  }

  return { REASON, DEFAULT_ARM, DEFAULT_BLOCK, MAX_BLOCKLIST, clampPct, resolveThresholds, decide, evaluate, createBannerGate };
})();

globalThis.CorsairAutoArm = CorsairAutoArm;

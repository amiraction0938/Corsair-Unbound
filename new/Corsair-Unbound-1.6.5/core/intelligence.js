const CorsairIntelligence = (() => {
  'use strict';

  const WINDOW_MS = 15000;
  const MAX_SIGNALS = 40;

  function scoreEvent(e) {
    const t = String(e?.type || '');
    if (t === 'threat_intel_flagged') return 70;
    if (t === 'download_blocked') return 45;
    if (t === 'popup_blocked') return 25;
    if (t === 'new_tab_blocked') return 25;
    if (t === 'navigation_blocked') return 20;
    if (t === 'navigation_contained') return 40;
    if (t === 'dnr_rule_added') return 40;
    return 0;
  }

  function classifySignals({ events = [], chain = null, destination = '', source = '', tabId = null, now = null, profile = {} } = {}) {
    const currentTime = Number.isFinite(now) ? Number(now) : Date.now();
    const destHost = CorsairSecurity.normalizeHostname(destination);
    const srcHost = CorsairSecurity.normalizeHostname(source);

    const scopedEvents = (Array.isArray(events) ? events : []).filter(e => {
      if (!e || typeof e !== 'object') return false;
      if (tabId !== null && Number.isInteger(e.tabId) && e.tabId !== tabId) return false;
      const dom = CorsairSecurity.normalizeHostname(e.domain || '');
      const dst = CorsairSecurity.normalizeHostname(e.destination || '');
      if (!srcHost && !destHost) return true;
      return (srcHost && (dom === srcHost || dst === srcHost)) ||
             (destHost && (dom === destHost || dst === destHost));
    });

    const recent = scopedEvents.filter(e => {
      const ts = Number(e?.timestamp || 0);
      const age = currentTime - ts;
      return Number.isFinite(ts) && age >= 0 && age <= WINDOW_MS;
    }).slice(0, MAX_SIGNALS);

    const signals = [];
    for (const e of recent) {
      const points = scoreEvent(e);
      if (points) signals.push({ kind: e.type, points, timestamp: e.timestamp, reason: e.reason || '' });
    }

    const hops = Array.isArray(chain?.hops) ? chain.hops : [];
    const externalHops = hops.filter(h => h.external || (srcHost && h.host && !CorsairSecurity.sameOrSubdomain(h.host, srcHost))).length;
    const distinctHosts = new Set(hops.map(h => h.host).filter(Boolean)).size;
    const autoHops = hops.filter(h => h.auto || h.server_redirect || h.client_redirect).length;
    const userGestureHops = hops.filter(h => h.userGesture === true).length;

    if (externalHops >= 1) signals.push({ kind: 'external-hop', points: 15 });
    if (externalHops >= 2) signals.push({ kind: 'multiple-external-hops', points: 15 });
    if (externalHops >= 3) signals.push({ kind: 'triple-external-hops', points: 20 });
    if (distinctHosts >= 3) signals.push({ kind: 'many-hosts', points: 12 });
    if (distinctHosts >= 4) signals.push({ kind: 'very-many-hosts', points: 15 });
    if (autoHops >= 1) signals.push({ kind: 'automatic-navigation', points: 10 });
    if (autoHops >= 2) signals.push({ kind: 'automatic-navigation-storm', points: 20 });
    if (autoHops >= 3) signals.push({ kind: 'automatic-navigation-flood', points: 25 });
    if (hops.length > (Number(profile.maxRedirectHops) || 8)) signals.push({ kind: 'hop-limit-exceeded', points: 25 });

    // Rapid redirect storm (hops in <3s)
    if (hops.length >= 3) {
      const first = Number(hops[0]?.timestamp) || 0;
      const last = Number(hops[hops.length - 1]?.timestamp) || 0;
      const elapsed = last - first;
      if (first > 0 && elapsed > 0 && elapsed < 3000) {
        signals.push({ kind: 'rapid-redirect-burst', points: 25 });
      }
    }

    const sameSite = Boolean(srcHost && destHost && CorsairSecurity.sameOrSubdomain(destHost, srcHost));
    if (sameSite) signals.push({ kind: 'same-site-destination', points: -20 });
    if (profile.clickbaitGuard === true && profile.mode === 'fortress') signals.push({ kind: 'fortress-context', points: 5 });

    if (chain?.cycleDetected) signals.push({ kind: 'redirect-cycle', points: 50 });

    // VirusTotal signals
    const ti = profile?.threatIntel || chain?.threatIntel;
    if (ti && ti.stats) {
      if (ti.stats.malicious >= 3) {
        signals.push({ kind: 'threat-intel-malicious', points: 70, reason: `VT: ${ti.stats.malicious} engines flagged` });
      } else if (ti.stats.malicious > 0 || ti.stats.suspicious >= 2) {
        signals.push({ kind: 'threat-intel-suspicious', points: 40, reason: `VT: ${ti.stats.malicious} mal / ${ti.stats.suspicious} susp` });
      } else if (ti.stats.harmless >= 10 && ti.stats.malicious === 0) {
        signals.push({ kind: 'threat-intel-reputable', points: -20 });
      }
    }

    // Clickbait title
    if (chain?.clickbaitScore && chain.clickbaitScore >= 50) {
      signals.push({
        kind: 'clickbait-content-detected',
        points: 25,
        reason: (chain.clickbaitTriggers || []).join(', ')
      });
    }

    const raw = signals.reduce((n, x) => n + Number(x.points || 0), 0);
    const risk = Math.max(0, Math.min(100, raw));
    const reasons = signals
      .filter(x => Number(x.points) > 0)
      .sort((a, b) => Number(b.points) - Number(a.points))
      .map(x => x.kind);

    let verdict = 'low-risk';
    if (risk >= 75) verdict = 'high-risk';
    else if (risk >= 45) verdict = 'suspicious';
    else if (risk >= 25) verdict = 'review';

    const confidence = Math.min(0.99, 0.5 + Math.min(0.45, signals.length * 0.07));

    return {
      risk,
      verdict,
      confidence,
      reasons: [...new Set(reasons)],
      signals,
      destination: destHost,
      sourceHost: srcHost,
      metrics: { recentEvents: recent.length, hops: hops.length, externalHops, distinctHosts, autoHops, userGestureHops, sameSite }
    };
  }

  function shouldContain({ assessment, profile = {}, destination = '', source = '', userInitiated = false } = {}) {
    if (!assessment || userInitiated) return false;
    if (source && destination && CorsairSecurity.sameOrSubdomain(destination, source)) return false;
    if (profile.autoContainRedirects !== true) return false;
    return assessment.risk >= 60;
  }

  function fingerprint({ source, destination, reasons = [] } = {}) {
    return [
      CorsairSecurity.normalizeHostname(source),
      CorsairSecurity.normalizeHostname(destination),
      [...reasons].sort().join(',')
    ].join('|');
  }

  return { WINDOW_MS, MAX_SIGNALS, classifySignals, shouldContain, fingerprint };
})();

globalThis.CorsairIntelligence = CorsairIntelligence;
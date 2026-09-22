const CorsairIntelligence = (() => {
  const WINDOW_MS = 15000;
  const MAX_SIGNALS = 40;

  function scoreEvent(e) {
    const t = String(e?.type || '');
    if (t === 'download_blocked') return 45;
    if (t === 'popup_blocked') return 25;
    if (t === 'new_tab_blocked') return 25;
    if (t === 'redirect_contained') return 40;
    if (t === 'dnr_rule_added') return 40;
    if (t === 'navigation_observed' && Number(e?.risk) >= 60) return 20;
    return 0;
  }

  function classifySignals({ events = [], chain = null, destination = '', source = '', profile = {} } = {}) {
    const now = Date.now();
    const recent = events.filter(e => now - Number(e?.timestamp || 0) <= WINDOW_MS).slice(0, MAX_SIGNALS);
    const signals = [];
    for (const e of recent) {
      const points = scoreEvent(e);
      if (points) signals.push({ kind: e.type, points, timestamp: e.timestamp, reason: e.reason || '' });
    }
    const hops = Array.isArray(chain?.hops) ? chain.hops : [];
    const externalHops = hops.filter(h => h.external).length;
    const distinctHosts = new Set(hops.map(h => h.host).filter(Boolean)).size;
    const autoHops = hops.filter(h => h.auto).length;
    if (externalHops >= 1) signals.push({ kind:'external-hop', points:15 });
    if (externalHops >= 3) signals.push({ kind:'multiple-external-hops', points:15 });
    if (distinctHosts >= 4) signals.push({ kind:'many-hosts', points:15 });
    if (autoHops >= 1) signals.push({ kind:'automatic-navigation', points:10 });
    if (hops.length > (Number(profile.maxRedirectHops) || 8)) signals.push({ kind:'hop-limit-exceeded', points:25 });
    const sameSite = source && destination && CorsairSecurity.sameOrSubdomain(destination, source);
    if (sameSite) signals.push({ kind:'same-site-destination', points:-20 });
    const blockedByPolicy = profile.clickbaitGuard === true && profile.mode === 'fortress';
    const raw = signals.reduce((n, x) => n + Number(x.points || 0), 0);
    const risk = Math.max(0, Math.min(100, raw + (blockedByPolicy ? 5 : 0)));
    const reasons = signals.filter(x => x.points > 0).sort((a,b) => b.points - a.points).map(x => x.kind);
    const verdict = risk >= 75 ? 'high-risk' : risk >= 45 ? 'suspicious' : risk >= 25 ? 'review' : 'low-risk';
    const confidence = Math.min(0.99, 0.5 + Math.min(0.45, signals.length * 0.07));
    return { risk, verdict, confidence, reasons, signals, metrics: { recentEvents: recent.length, hops: hops.length, externalHops, distinctHosts, autoHops, sameSite } };
  }

  function shouldContain({ assessment, profile = {}, destination = '', source = '', userInitiated = false } = {}) {
    if (!assessment) return false;
    if (userInitiated) return false;
    if (source && destination && CorsairSecurity.sameOrSubdomain(destination, source)) return false;
    if (profile.autoContainRedirects !== true) return false;
    return assessment.risk >= 60;
  }

  function fingerprint({ source, destination, reasons = [] } = {}) {
    return [CorsairSecurity.normalizeHostname(source), CorsairSecurity.normalizeHostname(destination), [...reasons].sort().join(',')].join('|');
  }

  return { classifySignals, shouldContain, fingerprint, WINDOW_MS };
})();
globalThis.CorsairIntelligence = CorsairIntelligence;

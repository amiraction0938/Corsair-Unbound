const CorsairIntelligence = (() => {
'use strict';

const WINDOW_MS = 15000;
const MAX_SIGNALS = 20;

function classifySignals({ events = [], chain = null, destination = '', source = '', tabId = null, now = null } = {}) {
const currentTime = Number.isFinite(now) ? Number(now) : Date.now();
const destHost = CorsairSecurity.normalizeHostname(destination);
const srcHost = CorsairSecurity.normalizeHostname(source);
const scopedEvents = (Array.isArray(events) ? events : []).filter(e => {
  if (!e || typeof e !== 'object') return false;
  if (tabId !== null && Number.isInteger(e.tabId) && e.tabId !== tabId) return false;
  const dom = CorsairSecurity.normalizeHostname(e.domain || '');
  const dst = CorsairSecurity.normalizeHostname(e.destination || '');
  if (srcHost && (dom === srcHost || dst === srcHost)) return true;
  if (destHost && (dom === destHost || dst === destHost)) return true;
  return false;
});

const recent = scopedEvents.filter(e => {
  const ts = Number(e?.timestamp || 0);
  if (!Number.isFinite(ts)) return false;
  const age = currentTime - ts;
  return age >= 0 && age <= WINDOW_MS;
}).slice(0, MAX_SIGNALS);

let risk = 0;
const signals = [];
const reasons = [];

for (const ev of recent) {
  if (ev.type === 'download_blocked') {
    risk += 45;
    signals.push({ kind: 'download_blocked', weight: 45, ref: ev });
    reasons.push('download_blocked');
  } else if (ev.type === 'popup_blocked') {
    risk += 25;
    signals.push({ kind: 'popup_blocked', weight: 25, ref: ev });
    reasons.push('popup_blocked');
  } else if (ev.type === 'new_tab_blocked') {
    risk += 25;
    signals.push({ kind: 'new_tab_blocked', weight: 25, ref: ev });
    reasons.push('new_tab_blocked');
  } else if (ev.type === 'navigation_blocked') {
    risk += 20;
    signals.push({ kind: 'navigation_blocked', weight: 20, ref: ev });
    reasons.push('navigation_blocked');
  }
}

if (chain && Array.isArray(chain.hops) && chain.hops.length > 1) {
  if (chain.cycleDetected) {
    risk += 50;
    signals.push({ kind: 'redirect_cycle', weight: 50 });
    reasons.push('redirect_cycle');
  }

  const hops = chain.hops;
  let rapidCount = 0;
  for (let i = 1; i < hops.length; i++) {
    const delta = (hops[i].timestamp || 0) - (hops[i - 1].timestamp || 0);
    if (delta >= 0 && delta < 500) {
      rapidCount++;
    }
  }
  if (rapidCount >= 2) {
    risk += 30;
    signals.push({ kind: 'rapid_redirects', weight: 30, count: rapidCount });
    reasons.push('rapid_redirects');
  }

  const externalDomains = new Set(
    hops
      .map(h => h.host)
      .filter(h => h && srcHost && !CorsairSecurity.sameOrSubdomain(h, srcHost))
  );
  if (externalDomains.size >= 3) {
    risk += 35;
    signals.push({ kind: 'external_hop_burst', weight: 35, domains: [...externalDomains] });
    reasons.push('external_hop_burst');
  }
}

let verdict = 'low-risk';
if (risk >= 60) {
  verdict = 'dangerous';
} else if (risk >= 35) {
  verdict = 'suspicious';
}

return {
  risk,
  verdict,
  signals,
  reasons: [...new Set(reasons)],
  destination: destHost,
  sourceHost: srcHost
};
}

return {
WINDOW_MS,
MAX_SIGNALS,
classifySignals
};
})();

globalThis.CorsairIntelligence = CorsairIntelligence;
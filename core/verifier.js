const CorsairVerifier = (() => {
'use strict';

function evaluateRedirectChain({ profile, chain, intelligence, destination, source }) {
if (!profile || profile.protected !== true || profile.mode !== 'fortress') {
return { shouldContain: false, reason: 'unprotected-profile', action: 'allow' };
}
const destHost = CorsairSecurity.normalizeHostname(destination);
const srcHost = CorsairSecurity.normalizeHostname(source || profile.domain || chain?.sourceHost);

if (destHost && srcHost && (destHost === srcHost || CorsairSecurity.sameOrSubdomain(destHost, srcHost))) {
  return { shouldContain: false, reason: 'same-origin-permitted', action: 'allow' };
}

if (Array.isArray(profile.blockedDestinationDomains) && destHost) {
  const isDestBlocked = profile.blockedDestinationDomains.some(
    d => destHost === d || CorsairSecurity.sameOrSubdomain(destHost, d)
  );
  if (isDestBlocked) {
    return {
      shouldContain: true,
      reason: 'profile-destination-blocked',
      action: 'block',
      fallbackUrl: `https://${srcHost}/`
    };
  }
}

if (profile.autoContainRedirects) {
  if (intelligence?.verdict === 'dangerous' || intelligence?.verdict === 'suspicious') {
    return {
      shouldContain: true,
      reason: `threat-intelligence-${intelligence.verdict}`,
      action: 'block',
      fallbackUrl: `https://${srcHost}/`
    };
  }
  if (chain?.cycleDetected) {
    return {
      shouldContain: true,
      reason: 'redirect-cycle-contained',
      action: 'block',
      fallbackUrl: `https://${srcHost}/`
    };
  }
}

if (profile.clickbaitGuard && chain && Array.isArray(chain.hops)) {
  const autoHops = chain.hops.filter(h => h.auto || h.server_redirect);
  if (autoHops.length >= 3) {
    return {
      shouldContain: true,
      reason: 'clickbait-redirect-storm',
      action: 'block',
      fallbackUrl: `https://${srcHost}/`
    };
  }
}

return { shouldContain: false, reason: 'policy-clear', action: 'allow' };
}

return {
evaluateRedirectChain
};
})();

globalThis.CorsairVerifier = CorsairVerifier;
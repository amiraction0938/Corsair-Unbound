const CorsairVerifier = (() => {
  'use strict';

  /**
   * Determine if a hop was initiated by the user (address bar, bookmark, etc).
   * Used to skip containment for legitimate user-driven navigations.
   */
  function isUserInitiated(hop) {
    if (!hop || typeof hop !== 'object') return false;
    if (hop.userGesture === true) return true;
    if (hop.fromAddressBar === true) return true;
    const t = String(hop.transitionType || '');
    if (t === 'typed' || t === 'auto_bookmark') return true;
    const q = Array.isArray(hop.qualifiers) ? hop.qualifiers : [];
    if (q.includes('from_address_bar')) return true;
    if (q.includes('forward_back')) return true;
    return false;
  }

  function evaluateRedirectChain({ profile, chain, intelligence, destination, source }) {
    if (!profile || profile.protected !== true || profile.mode !== 'fortress') {
      return { shouldContain: false, reason: 'unprotected-profile', action: 'allow' };
    }

    const destHost = CorsairSecurity.normalizeHostname(destination);
    const srcHost = CorsairSecurity.normalizeHostname(source || profile.domain || chain?.sourceHost);

    // ---- User-initiated escape hatch ----
    // If the most recent hop is directly user-typed/bookmarked and destination
    // is not in the explicit blocklist, we allow it. (Prevents false positives
    // when the user intentionally navigates.)
    const hops = Array.isArray(chain?.hops) ? chain.hops : [];
    const lastHop = hops.length ? hops[hops.length - 1] : null;
    const lastHopIsUser = isUserInitiated(lastHop);

    // Same-origin always allowed (regardless of user gesture)
    if (destHost && srcHost && (destHost === srcHost || CorsairSecurity.sameOrSubdomain(destHost, srcHost))) {
      return { shouldContain: false, reason: 'same-origin-permitted', action: 'allow' };
    }

    // Explicit destination blocklist — highest priority (even over user gesture)
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

    // If user explicitly typed/bookmarked → allow (unless blocked above)
    if (lastHopIsUser) {
      return { shouldContain: false, reason: 'user-initiated-navigation', action: 'allow' };
    }

    // ============ AUTO-CONTAINMENT ============
    if (profile.autoContainRedirects) {

      // (A) Threat intel high-risk
      if (intelligence?.verdict === 'high-risk' || intelligence?.verdict === 'dangerous') {
        return {
          shouldContain: true,
          reason: `threat-intelligence-${intelligence.verdict}`,
          action: 'block',
          fallbackUrl: `https://${srcHost}/`
        };
      }

      // (B) Explicit cycle
      if (chain?.cycleDetected) {
        return {
          shouldContain: true,
          reason: 'redirect-cycle-contained',
          action: 'block',
          fallbackUrl: `https://${srcHost}/`
        };
      }

      // (C) Hop-limit exceeded
      const maxHops = Math.max(2, Number(profile.maxRedirectHops) || 8);
      if (hops.length > maxHops) {
        return {
          shouldContain: true,
          reason: 'hop-limit-exceeded',
          action: 'block',
          fallbackUrl: `https://${srcHost}/`
        };
      }

      // (D) Automatic external hops — 2+ auto + external = contain
      const autoExternalHops = hops.filter(h => {
        if (!h || typeof h !== 'object') return false;
        const isAuto = h.auto === true || h.redirect === true || h.server_redirect === true || h.client_redirect === true;
        const isExternal = h.external === true || (srcHost && h.host && !CorsairSecurity.sameOrSubdomain(h.host, srcHost));
        return isAuto && isExternal;
      });
      if (autoExternalHops.length >= 2) {
        return {
          shouldContain: true,
          reason: 'redirect-storm-contained',
          action: 'block',
          fallbackUrl: `https://${srcHost}/`
        };
      }

      // (E) Rapid redirect storm (<3s, 3+ hops, 2+ external)
      if (hops.length >= 3) {
        const firstTs = Number(hops[0]?.timestamp) || 0;
        const lastTs = Number(hops[hops.length - 1]?.timestamp) || 0;
        const elapsed = lastTs - firstTs;
        if (firstTs > 0 && elapsed > 0 && elapsed < 3000) {
          const externalCount = hops.filter(h => h.host && !CorsairSecurity.sameOrSubdomain(h.host, srcHost)).length;
          if (externalCount >= 2) {
            return {
              shouldContain: true,
              reason: 'rapid-external-redirect-storm',
              action: 'block',
              fallbackUrl: `https://${srcHost}/`
            };
          }
        }
      }
    }

    // ============ CLICKBAIT GUARD ============
    if (profile.clickbaitGuard && Array.isArray(chain?.hops)) {
      const autoHops = chain.hops.filter(h => h.auto || h.server_redirect || h.client_redirect);
      if (autoHops.length >= 2 && destHost && srcHost && !CorsairSecurity.sameOrSubdomain(destHost, srcHost)) {
        return {
          shouldContain: true,
          reason: 'clickbait-redirect-storm',
          action: 'block',
          fallbackUrl: `https://${srcHost}/`
        };
      }

      if (chain.clickbaitScore >= 50 && destHost && srcHost && !CorsairSecurity.sameOrSubdomain(destHost, srcHost)) {
        return {
          shouldContain: true,
          reason: 'clickbait-content-flagged',
          action: 'block',
          fallbackUrl: `https://${srcHost}/`
        };
      }
    }

    return { shouldContain: false, reason: 'policy-clear', action: 'allow' };
  }

  return { evaluateRedirectChain, isUserInitiated };
})();

globalThis.CorsairVerifier = CorsairVerifier;
const CorsairRedirects = (() => {
  'use strict';

  const _tabLocks = new Map();

  async function withTabLock(tabId, fn) {
    while (_tabLocks.get(tabId)) {
      await _tabLocks.get(tabId);
    }
    let resolveLock;
    const p = new Promise(resolve => { resolveLock = resolve; });
    _tabLocks.set(tabId, p);
    try { return await fn(); }
    finally {
      _tabLocks.delete(tabId);
      resolveLock();
    }
  }

  async function getTabChain(tabId) {
    if (typeof chrome === 'undefined' || !chrome.storage?.session) return null;
    const key = `redirectTab:${tabId}`;
    const res = await chrome.storage.session.get(key);
    return res[key] || null;
  }

  async function setTabChain(tabId, chain) {
    if (typeof chrome === 'undefined' || !chrome.storage?.session) return;
    const key = `redirectTab:${tabId}`;
    await chrome.storage.session.set({ [key]: chain });
  }

  async function getGenerationToken(tabId) {
    const chain = await getTabChain(tabId);
    return chain?.generationId || null;
  }

  async function clearChain(tabId) {
    if (typeof chrome === 'undefined' || !chrome.storage?.session) return;
    return withTabLock(tabId, async () => {
      await chrome.storage.session.remove(`redirectTab:${tabId}`);
    });
  }

  async function clearChainIfTabClosed(tabId, token) {
    if (typeof chrome === 'undefined' || !chrome.storage?.session) return;
    return withTabLock(tabId, async () => {
      const current = await getTabChain(tabId);
      if (!current) return;
      if (!token || current.generationId === token) {
        await chrome.storage.session.remove(`redirectTab:${tabId}`);
      }
    });
  }

  function detectCycle(hops) {
    if (!Array.isArray(hops) || hops.length < 3) return null;
    const seen = new Map();
    for (let i = 0; i < hops.length; i++) {
      const h = hops[i]?.host;
      if (!h) continue;
      if (seen.has(h)) {
        const prevIndex = seen.get(h);
        if (i - prevIndex >= 2) {
          return { host: h, firstIndex: prevIndex, cycleIndex: i };
        }
      } else {
        seen.set(h, i);
      }
    }
    return null;
  }

  /* ------------------------------------------------------------------
     HOP AUTO-CLASSIFICATION
     auto=true if:
       - transitionType is client_redirect / auto_subframe / auto_toplevel
       - qualifiers include server_redirect / client_redirect
     ------------------------------------------------------------------ */
  function isAutoHop({ transitionType = '', qualifiers = [] }) {
    const t = String(transitionType);
    if (t === 'client_redirect') return true;
    if (t === 'auto_subframe') return true;
    if (t === 'auto_toplevel') return true;
    if (t === 'reload') return false;
    if (Array.isArray(qualifiers)) {
      if (qualifiers.includes('server_redirect')) return true;
      if (qualifiers.includes('client_redirect')) return true;
    }
    return false;
  }

  /* ------------------------------------------------------------------
     USER-DRIVEN classification
     Includes 'link' (normal user click) so ordinary clicks are not
     misclassified as auto-redirects.
     ------------------------------------------------------------------ */
  function isUserDriven({ transitionType = '', qualifiers = [] }) {
    const t = String(transitionType);
    if (t === 'typed' || t === 'auto_bookmark' || t === 'link' || t === 'generated') return true;
    if (Array.isArray(qualifiers)) {
      if (qualifiers.includes('from_address_bar')) return true;
      if (qualifiers.includes('forward_back')) return true;
    }
    return false;
  }

  async function beginNavigation({ tabId, frameId = 0, url, initiator = null, transitionType = '', qualifiers = [] }) {
    if (!Number.isInteger(tabId) || frameId !== 0 || !url) return null;
    return withTabLock(tabId, async () => {
      const target = CorsairSecurity.normalizeUrl(url);
      if (!target) return null;
      const targetHost = CorsairSecurity.extractHostname(target);

      let current = await getTabChain(tabId);
      const isExplicit = isUserDriven({ transitionType, qualifiers }) || !current;

      if (isExplicit) {
        const generationId = crypto.randomUUID();
        const initialHop = {
          url: target,
          host: targetHost,
          timestamp: Date.now(),
          external: false,
          auto: false,
          redirect: false,
          committed: false,
          userGesture: true,
          transitionType,
          qualifiers: Array.isArray(qualifiers) ? [...qualifiers] : []
        };
        current = {
          tabId,
          generationId,
          sourceHost: targetHost,
          initiator: initiator ? CorsairSecurity.normalizeUrl(initiator) : null,
          startedAt: Date.now(),
          updatedAt: Date.now(),
          hops: [initialHop],
          cycleDetected: false
        };
        await setTabChain(tabId, current);
        return current;
      }

      const isExternal = Boolean(current.sourceHost && targetHost && !CorsairSecurity.sameOrSubdomain(targetHost, current.sourceHost));
      const autoHop = isAutoHop({ transitionType, qualifiers });
      const userGest = isUserDriven({ transitionType, qualifiers });

      const hop = {
        url: target,
        host: targetHost,
        timestamp: Date.now(),
        external: isExternal,
        auto: autoHop,
        redirect: autoHop || (Array.isArray(qualifiers) && qualifiers.some(q => q.includes('redirect'))),
        server_redirect: Array.isArray(qualifiers) && qualifiers.includes('server_redirect'),
        client_redirect: Array.isArray(qualifiers) && qualifiers.includes('client_redirect'),
        userGesture: userGest,
        committed: false,
        transitionType,
        qualifiers: Array.isArray(qualifiers) ? [...qualifiers] : []
      };

      current.hops = [...current.hops, hop].slice(-32);
      current.cycleDetected = Boolean(detectCycle(current.hops));
      current.updatedAt = Date.now();

      await setTabChain(tabId, current);
      return current;
    });
  }

  async function reconcileCommittedHop({ tabId, frameId = 0, url, qualifiers = [], transitionType = '' }) {
    if (!Number.isInteger(tabId) || frameId !== 0 || !url) return null;
    return withTabLock(tabId, async () => {
      const current = await getTabChain(tabId);
      if (!current || !Array.isArray(current.hops) || current.hops.length === 0) return current;

      const target = CorsairSecurity.normalizeUrl(url);
      if (!target) return current;

      const lastHop = current.hops[current.hops.length - 1];

      if (lastHop && CorsairSecurity.normalizeUrl(lastHop.url) === target) {
        lastHop.committed = true;
        if (Array.isArray(qualifiers) && qualifiers.length) {
          lastHop.qualifiers = [...qualifiers];
        }
        if (transitionType) lastHop.transitionType = transitionType;
        await setTabChain(tabId, current);
        return current;
      }

      const existingHop = [...current.hops].reverse().find(h => CorsairSecurity.normalizeUrl(h.url) === target);
      if (existingHop) {
        existingHop.committed = true;
        if (Array.isArray(qualifiers) && qualifiers.length) existingHop.qualifiers = [...qualifiers];
        if (transitionType) existingHop.transitionType = transitionType;
        await setTabChain(tabId, current);
        return current;
      }

      const targetHost = CorsairSecurity.extractHostname(target);
      const isExternal = Boolean(current.sourceHost && targetHost && !CorsairSecurity.sameOrSubdomain(targetHost, current.sourceHost));
      const autoHop = isAutoHop({ transitionType, qualifiers });

      const committedHop = {
        url: target,
        host: targetHost,
        timestamp: Date.now(),
        external: isExternal,
        auto: autoHop,
        redirect: true,
        server_redirect: Array.isArray(qualifiers) && qualifiers.includes('server_redirect'),
        client_redirect: Array.isArray(qualifiers) && qualifiers.includes('client_redirect'),
        userGesture: false,
        committed: true,
        transitionType,
        qualifiers: Array.isArray(qualifiers) ? [...qualifiers] : []
      };

      current.hops = [...current.hops, committedHop].slice(-32);
      current.cycleDetected = Boolean(detectCycle(current.hops));
      current.updatedAt = Date.now();

      await setTabChain(tabId, current);
      return current;
    });
  }

  async function discardFailedNavigation({ tabId, frameId = 0, url = '', generationId = null } = {}) {
    if (!Number.isInteger(tabId) || frameId !== 0 || !url) return null;
    return withTabLock(tabId, async () => {
      const current = await getTabChain(tabId);
      if (!current || !Array.isArray(current.hops) || current.hops.length === 0) return null;

      if (generationId && current.generationId && current.generationId !== generationId) return null;

      const target = CorsairSecurity.normalizeUrl(url);
      if (!target) return null;

      const lastIndex = current.hops.length - 1;
      const lastHop = current.hops[lastIndex];

      if (lastHop && CorsairSecurity.normalizeUrl(lastHop.url) === target) {
        if (lastHop.committed === true) return current;
        current.hops.splice(lastIndex, 1);
        current.cycleDetected = Boolean(detectCycle(current.hops));
        current.updatedAt = Date.now();
        await setTabChain(tabId, current);
        return current;
      }

      for (let i = current.hops.length - 1; i >= 0; i--) {
        const h = current.hops[i];
        if (CorsairSecurity.normalizeUrl(h.url) === target && !h.committed) {
          current.hops.splice(i, 1);
          current.cycleDetected = Boolean(detectCycle(current.hops));
          current.updatedAt = Date.now();
          await setTabChain(tabId, current);
          return current;
        }
      }

      return current;
    });
  }

  return {
    withTabLock,
    getTabChain,
    setTabChain,
    getGenerationToken,
    clearChain,
    clearChainIfTabClosed,
    detectCycle,
    isAutoHop,
    isUserDriven,
    beginNavigation,
    reconcileCommittedHop,
    discardFailedNavigation
  };
})();

globalThis.CorsairRedirects = CorsairRedirects;
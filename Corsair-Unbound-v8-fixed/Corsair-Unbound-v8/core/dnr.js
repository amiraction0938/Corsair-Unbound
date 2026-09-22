const CorsairDNR = (() => {
  const BLOCK_BASE = 100000;
  const MAX_DYNAMIC = 30000;

  function hashId(text) {
    let h = 2166136261;
    for (let i = 0; i < text.length; i++) {
      h ^= text.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
    return BLOCK_BASE + (h >>> 0) % MAX_DYNAMIC;
  }

  function domainFilter(domain) {
    return `||${domain}^`;
  }

  function makeBlockRule({ source, destination, reason }) {
    const src = CorsairSecurity.normalizeHostname(source);
    const dst = CorsairSecurity.normalizeHostname(destination);
    if (!CorsairSecurity.isValidHostname(src) || !CorsairSecurity.isValidHostname(dst)) return null;
    return {
      id: hashId(`${src}>${dst}`),
      priority: 100,
      action: { type: 'block' },
      condition: {
        initiatorDomains: [src],
        requestDomains: [dst],
        resourceTypes: ['main_frame'],
        domainType: 'thirdParty'
      }
    };
  }

  async function getDynamicRules() {
    return chrome.declarativeNetRequest.getDynamicRules();
  }

  async function listCorsairRules() {
    return (await getDynamicRules()).filter(r => Number(r.id) >= BLOCK_BASE && Number(r.id) < BLOCK_BASE + MAX_DYNAMIC);
  }

  async function ensureNavigationBlock(source, destination, reason) {
    const rule = makeBlockRule({ source, destination, reason });
    if (!rule) return { ok: false, error: 'invalid-domain' };
    const existing = (await listCorsairRules()).find(r => r.id === rule.id);
    if (!existing) await chrome.declarativeNetRequest.updateDynamicRules({ addRules: [rule] });
    return { ok: true, rule };
  }

  async function removeNavigationBlock(source, destination) {
    const rule = makeBlockRule({ source, destination });
    if (!rule) return { ok: false, error: 'invalid-domain' };
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [rule.id] });
    return { ok: true, id: rule.id };
  }

  async function clearCorsairRules() {
    const rules = await listCorsairRules();
    if (rules.length) await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: rules.map(r => r.id) });
    return rules.length;
  }

  async function rebuildFromProfiles() {
    const profiles = await CorsairStorage.getProfiles();
    const rules = [];
    for (const [host, profile] of Object.entries(profiles)) {
      if (profile?.blockedDestinationDomains && Array.isArray(profile.blockedDestinationDomains)) {
        for (const dst of profile.blockedDestinationDomains.slice(0, 1000)) {
          const rule = makeBlockRule({ source: host, destination: dst, reason: 'profile destination block' });
          if (rule) rules.push(rule);
        }
      }
    }
    const current = await listCorsairRules();
    const currentIds = new Set(current.map(r => r.id));
    const desiredIds = new Set(rules.map(r => r.id));
    const removeIds = current.filter(r => !desiredIds.has(r.id)).map(r => r.id);
    const addRules = rules.filter(r => !currentIds.has(r.id));
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: removeIds, addRules: addRules.slice(0, 5000) });
    return { added: Math.min(addRules.length, 5000), removed: removeIds.length };
  }

  return { ensureNavigationBlock, removeNavigationBlock, clearCorsairRules, rebuildFromProfiles, listCorsairRules, makeBlockRule };
})();

globalThis.CorsairDNR = CorsairDNR;

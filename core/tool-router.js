const CorsairTools = (() => {
'use strict';

async function run(name, args = {}) {
if (!name || typeof name !== 'string') {
return { ok: false, error: 'missing-tool-name' };
}
switch (name) {
  case 'inspect-domain': {
    const host = CorsairSecurity.normalizeHostname(args.domain);
    if (!host || !CorsairSecurity.isValidHostname(host)) {
      return { ok: false, error: 'invalid-domain' };
    }
    const profile = await CorsairStorage.getProfile(host);
    const graph = await CorsairStorage.getGraph();
    const node = graph.nodes?.[`origin:${host}`] || null;
    const events = (await CorsairStorage.getEvents(50)).filter(e => e.domain === host || e.destination === host);
    return { ok: true, domain: host, profile, graphNode: node, events };
  }

  case 'add-fortress-rule': {
    const src = CorsairSecurity.normalizeHostname(args.source);
    const dst = CorsairSecurity.normalizeHostname(args.destination);
    if (!CorsairSecurity.isValidHostname(src) || !CorsairSecurity.isValidHostname(dst)) {
      return { ok: false, error: 'invalid-domain' };
    }
    return CorsairDNR.ensureNavigationBlock(src, dst, args.reason || 'tool-action');
  }

  case 'remove-fortress-rule': {
    const src = CorsairSecurity.normalizeHostname(args.source);
    const dst = CorsairSecurity.normalizeHostname(args.destination);
    return CorsairDNR.removeNavigationBlock(src, dst);
  }

  case 'list-rules': {
    const rules = await CorsairDNR.listCorsairRules();
    const registry = await CorsairStorage.getDnrRegistry();
    return { ok: true, count: rules.length, rules, registry };
  }

  case 'get-health': {
    const [settings, profiles, dnrRules, totalStorage] = await Promise.all([
      CorsairStorage.getSettings(),
      CorsairStorage.getProfiles(),
      CorsairDNR.listCorsairRules(),
      CorsairStorage.estimateTotalStorageBytes()
    ]);
    return {
      ok: true,
      health: {
        profileCount: Object.keys(profiles || {}).length,
        dnrRuleCount: dnrRules.length,
        totalBytes: totalStorage.total,
        // NOTE: `_version` is the canonical schema version tracked by
        // CorsairStorage.patchSettings(). The old `version` field was
        // never incremented and has been removed from defaultSettings()
        // — reading it here always returned `undefined`.
        settingsVersion: settings._version
      }
    };
  }

  default:
    return { ok: false, error: `unknown-tool: ${name}` };
}
}

return {
run
};
})();

globalThis.CorsairTools = CorsairTools;
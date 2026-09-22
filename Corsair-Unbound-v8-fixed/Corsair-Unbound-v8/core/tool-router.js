const CorsairTools = (() => {
  const READ_ONLY = new Set(['get_context','get_profile','get_events','get_evidence','get_graph','get_chains','get_network_observation','get_regressions','run_regressions','list_rules','verify_redirect']);
  const CONTROLLED = new Set(['protect_domain','patch_profile','block_destination','unblock_destination','capture_regression']);

  async function run(name, args = {}) {
    if (!READ_ONLY.has(name) && !CONTROLLED.has(name)) return { ok: false, error: 'unknown-tool' };
    switch (name) {
      case 'get_context': return { ok: true, result: await CorsairStorage.getAgentContext(args) };
      case 'get_profile': return { ok: true, result: await CorsairStorage.getProfile(args.domain) };
      case 'get_events': return { ok: true, result: await CorsairStorage.getEvents(args.limit || 200) };
      case 'get_evidence': return { ok: true, result: await CorsairEvidence.recent(args.limit || 200) };
      case 'get_graph': return { ok: true, result: await CorsairStorage.getGraph() };
      case 'get_chains': return { ok: true, result: await CorsairStorage.getChains(args.limit || 200) };
      case 'get_network_observation': return { ok: true, result: await CorsairObservation.recent(args.tabId, args.limit || 200) };
      case 'get_regressions': return { ok: true, result: await CorsairReplay.getCases() };
      case 'run_regressions': return { ok: true, result: await CorsairReplay.runAll() };
      case 'list_rules': return { ok: true, result: await CorsairDNR.listCorsairRules() };
      case 'verify_redirect': return { ok: true, result: CorsairVerifier.evaluateRedirectChain(args.chain || {}, args.profile || {}) };
      case 'protect_domain': {
        const host = CorsairSecurity.normalizeHostname(args.domain);
        if (!CorsairSecurity.isValidHostname(host)) return { ok: false, error: 'invalid-domain' };
        const saved = await CorsairStorage.upsertProfile(host, CorsairSecurity.fortressProfile(await CorsairStorage.getProfile(host) || {}));
        return { ok: true, result: saved };
      }
      case 'patch_profile': {
        const current = await CorsairStorage.getProfile(args.domain); if (!current) return { ok: false, error: 'profile-not-found' };
        const next = CorsairSecurity.normalizeProfile({ ...current, ...(args.patch || {}) });
        return { ok: true, result: await CorsairStorage.upsertProfile(args.domain, next) };
      }
      case 'block_destination': return { ok: true, result: await CorsairDNR.ensureNavigationBlock(args.source, args.destination, args.reason) };
      case 'unblock_destination': return { ok: true, result: await CorsairDNR.removeNavigationBlock(args.source, args.destination) };
      case 'capture_regression': return { ok: true, result: await CorsairReplay.capture(args.name, args.input, args.expected) };
    }
  }
  return { run, readOnlyTools:[...READ_ONLY], controlledTools:[...CONTROLLED] };
})();
globalThis.CorsairTools = CorsairTools;

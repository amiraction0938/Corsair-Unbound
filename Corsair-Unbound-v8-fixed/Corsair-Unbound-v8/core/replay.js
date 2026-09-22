const CorsairReplay = (() => {
  const MAX_CASES = 500;
  async function getCases() {
    const d = await chrome.storage.local.get('regressionCases');
    return Array.isArray(d.regressionCases) ? d.regressionCases : [];
  }
  async function saveCases(v) { await chrome.storage.local.set({ regressionCases: v.slice(0, MAX_CASES) }); return v; }
  async function capture(name, input, expected) {
    const cases = await getCases();
    const item = { id: crypto.randomUUID(), name: String(name || 'Corsair regression'), createdAt: Date.now(), input: JSON.parse(JSON.stringify(input || {})), expected: JSON.parse(JSON.stringify(expected || {})) };
    cases.unshift(item); await saveCases(cases); return item;
  }
  async function run(caseItem) {
    const input = caseItem?.input || {};
    const kind = String(input.kind || '');
    if (kind === 'redirect-verification') {
      const result = CorsairVerifier.evaluateRedirectChain(input.chain || { hops: [] }, input.profile || {});
      return { passed: JSON.stringify(result.verdict) === JSON.stringify(caseItem.expected?.verdict) || (caseItem.expected?.acceptableVerdicts || []).includes(result.verdict), result };
    }
    if (kind === 'page-observation') {
      const result = CorsairVerifier.verifyPageObservation(input.observation || {});
      return { passed: JSON.stringify(result.status) === JSON.stringify(caseItem.expected?.status), result };
    }
    return { passed: false, result: null, error: 'unsupported-regression-kind' };
  }
  async function runAll() {
    const cases = await getCases();
    const results = [];
    for (const c of cases) results.push({ id: c.id, name: c.name, ...(await run(c)) });
    return results;
  }
  async function remove(id) { const next = (await getCases()).filter(x => x.id !== id); await saveCases(next); return true; }
  async function clear() { await saveCases([]); }
  return { getCases, capture, run, runAll, remove, clear };
})();

globalThis.CorsairReplay = CorsairReplay;

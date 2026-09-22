const CorsairObservation = (() => {
  const MAX_PER_TAB = 500;
  async function saveBatch(tabId, records) {
    if (!Number.isInteger(tabId) || !Array.isArray(records) || !records.length) return;
    const key = `networkObs:${tabId}`;
    const d = await chrome.storage.session.get(key);
    const old = Array.isArray(d[key]) ? d[key] : [];
    await chrome.storage.session.set({ [key]: [...records, ...old].slice(0, MAX_PER_TAB) });
  }
  async function recent(tabId, limit = 200) {
    if (!Number.isInteger(tabId)) return [];
    const key = `networkObs:${tabId}`;
    const d = await chrome.storage.session.get(key);
    return (Array.isArray(d[key]) ? d[key] : []).slice(0, Math.max(1, Math.min(MAX_PER_TAB, Number(limit) || 200)));
  }
  async function clear(tabId) {
    if (Number.isInteger(tabId)) await chrome.storage.session.remove(`networkObs:${tabId}`);
  }
  function normalizeRecord(record = {}) {
    return {
      id: crypto.randomUUID(),
      timestamp: Date.now(),
      type: String(record.type || 'resource'),
      url: CorsairSecurity.normalizeUrl(record.url || ''),
      host: CorsairSecurity.extractHostname(record.url || ''),
      initiatorHost: CorsairSecurity.normalizeHostname(record.initiatorHost || ''),
      resourceType: String(record.resourceType || 'other'),
      duration: Number.isFinite(record.duration) ? Number(record.duration) : null,
      transferSize: Number.isFinite(record.transferSize) ? Number(record.transferSize) : null,
      status: Number.isFinite(record.status) ? Number(record.status) : null,
      method: String(record.method || ''),
      phase: String(record.phase || 'runtime'),
      documentId: record.documentId || null,
      tags: Array.isArray(record.tags) ? record.tags.slice(0, 16) : []
    };
  }
  return { saveBatch, recent, clear, normalizeRecord };
})();
globalThis.CorsairObservation = CorsairObservation;

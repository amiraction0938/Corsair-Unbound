const CorsairEvidence = (() => {
  const MAX = 1500;
  const safe = value => {
    try { return JSON.parse(JSON.stringify(value)); } catch { return null; }
  };
  async function getAll() {
    const d = await chrome.storage.local.get('evidenceStore');
    return Array.isArray(d.evidenceStore) ? d.evidenceStore : [];
  }
  async function add(record) {
    const item = {
      id: crypto.randomUUID(),
      timestamp: Date.now(),
      kind: String(record?.kind || 'observation'),
      tabId: Number.isInteger(record?.tabId) ? record.tabId : null,
      documentId: record?.documentId || null,
      origin: record?.origin || '',
      data: safe(record?.data || {}),
      tags: Array.isArray(record?.tags) ? record.tags.slice(0, 24) : []
    };
    const arr = await getAll();
    await chrome.storage.local.set({ evidenceStore: [item, ...arr].slice(0, MAX) });
    return item;
  }
  async function recent(limit = 200) { return (await getAll()).slice(0, Math.max(1, Math.min(MAX, Number(limit) || 200))); }
  async function byTab(tabId, limit = 200) { return (await getAll()).filter(x => x.tabId === tabId).slice(0, Math.max(1, Math.min(MAX, Number(limit) || 200))); }
  async function clear() { await chrome.storage.local.set({ evidenceStore: [] }); }
  return { add, recent, byTab, clear };
})();
globalThis.CorsairEvidence = CorsairEvidence;

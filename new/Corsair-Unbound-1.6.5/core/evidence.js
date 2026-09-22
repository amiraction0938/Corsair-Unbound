const CorsairEvidence = (() => {
'use strict';

const MAX = 500;
const MAX_BYTES = 2 * 1024 * 1024;

function boundSingleRecord(record) {
const r = CorsairSecurity.sanitizeObject(record) || {};
return {
id: crypto.randomUUID(),
timestamp: Date.now(),
kind: String(r.kind || 'observation').slice(0, 50),
origin: CorsairSecurity.normalizeHostname(r.origin || ''),
tabId: Number.isInteger(r.tabId) ? r.tabId : null,
data: r.data && typeof r.data === 'object' ? r.data : {}
};
}

function pruneEvidence(arr, maxBytes, maxCount) {
let out = Array.isArray(arr) ? [...arr] : [];
if (out.length > maxCount) {
out = out.slice(0, maxCount);
}
while (out.length > 10 && CorsairStorage.estimateBytes(out) > maxBytes) {
out.pop();
}
return out;
}

async function getAll() {
if (typeof chrome === 'undefined' || !chrome.storage?.local) return [];
const res = await chrome.storage.local.get('evidenceStore');
return Array.isArray(res.evidenceStore) ? res.evidenceStore : [];
}

async function add(record) {
const item = boundSingleRecord(record);
return CorsairStorage.withTransactionGateShared(async () => {
if (typeof CorsairStorage !== 'undefined' && CorsairStorage.ensureQuotaBudgetBeforeWrite) {
await CorsairStorage.ensureQuotaBudgetBeforeWrite('evidenceStore', CorsairStorage.estimateBytes(item));
}
return CorsairStorage.withPartitionLock('evidenceStore', async () => {
const arr = await getAll();
const combined = [item, ...arr];
const pruned = pruneEvidence(combined, MAX_BYTES, MAX);
    await CorsairStorage.safeSetWithQuotaRetry('evidenceStore', pruned, async val => {
      return pruneEvidence(val, MAX_BYTES * 0.5, Math.floor(MAX * 0.5));
    });
    return item;
  });
});
}

async function recent(limit = 100) {
const arr = await getAll();
return arr.slice(0, limit);
}

async function byTab(tabId, limit = 50) {
if (!Number.isInteger(tabId)) return [];
const arr = await getAll();
return arr.filter(e => e.tabId === tabId).slice(0, limit);
}

return {
MAX,
MAX_BYTES,
add,
recent,
byTab,
getAll
};
})();

globalThis.CorsairEvidence = CorsairEvidence;
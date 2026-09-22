const CorsairObservation = (() => {
'use strict';

const MAX_PER_TAB = 100;
const _tabLocks = new Map();

async function withPartitionLock(lockKey, fn) {
while (_tabLocks.get(lockKey)) {
await _tabLocks.get(lockKey);
}
let resolveLock;
const p = new Promise(resolve => {
resolveLock = resolve;
});
_tabLocks.set(lockKey, p);
try {
return await fn();
} finally {
_tabLocks.delete(lockKey);
resolveLock();
}
}

async function saveBatch(tabId, batch, docId = null) {
if (!Number.isInteger(tabId) || !Array.isArray(batch)) return [];
const lockKey = `networkObs:${tabId}`;
return withPartitionLock(lockKey, async () => {
if (typeof chrome === 'undefined' || !chrome.storage?.session) return [];
const key = `networkObs:${tabId}`;
const existing = (await chrome.storage.session.get(key))[key] || [];
  const sanitizedBatch = batch
    .slice(0, 40)
    .map(b => ({
      url: CorsairSecurity.normalizeUrl(b.url),
      timestamp: Date.now(),
      docId: docId || null
    }))
    .filter(b => Boolean(b.url));

  const combined = [...existing, ...sanitizedBatch].slice(-MAX_PER_TAB);
  await chrome.storage.session.set({ [key]: combined });
  return combined;
});
}

async function clear(tabId) {
if (!Number.isInteger(tabId)) return;
const lockKey = `networkObs:${tabId}`;
return withPartitionLock(lockKey, async () => {
if (typeof chrome === 'undefined' || !chrome.storage?.session) return;
await chrome.storage.session.remove(`networkObs:${tabId}`);
});
}

async function get(tabId) {
if (!Number.isInteger(tabId)) return [];
if (typeof chrome === 'undefined' || !chrome.storage?.session) return [];
const key = `networkObs:${tabId}`;
const res = await chrome.storage.session.get(key);
return Array.isArray(res[key]) ? res[key] : [];
}

async function reconcileSessionTabs(activeTabIds) {
if (typeof chrome === 'undefined' || !chrome.storage?.session) return;
const activeSet = new Set(activeTabIds);
const all = await chrome.storage.session.get(null);
const toRemove = [];
for (const k of Object.keys(all || {})) {
  if (k.startsWith('networkObs:') || k.startsWith('redirectTab:')) {
    const tid = Number(k.split(':')[1]);
    if (Number.isInteger(tid) && !activeSet.has(tid)) {
      toRemove.push(k);
    }
  }
}
if (toRemove.length > 0) {
  await chrome.storage.session.remove(toRemove);
}
}

return {
MAX_PER_TAB,
saveBatch,
clear,
get,
reconcileSessionTabs
};
})();

globalThis.CorsairObservation = CorsairObservation;
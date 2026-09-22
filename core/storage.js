const CorsairStorage = (() => {
'use strict';

const KEYS = {
profiles: 'domainProfiles',
settings: 'globalSettings',
events: 'activityLog',
graph: 'siteGraph',
chains: 'redirectChains',
evidence: 'evidenceStore',
dnrRegistry: 'dnrRuleRegistry',
cases: 'regressionCases'
};

const SOFT_BUDGETS = {
activityLog: 2 * 1024 * 1024,
siteGraph: 2.5 * 1024 * 1024,
redirectChains: 1.5 * 1024 * 1024,
evidenceStore: 2 * 1024 * 1024,
domainProfiles: 1 * 1024 * 1024,
dnrRuleRegistry: 512 * 1024
};

const GLOBAL_HARD_CAP = 10 * 1024 * 1024;
const MAX_EVENTS = 1000;
const MAX_CHAINS = 200;
const MAX_NODES = 500;
const MAX_EDGES = 1000;

const CANONICAL_PARTITION_ORDER = [
'activityLog',
'dnrRuleRegistry',
'domainProfiles',
'evidenceStore',
'globalSettings',
'redirectChains',
'regressionCases',
'siteGraph'
];

let _lockObserver = null;
let _profilesCache = null;
let _settingsCache = null;
let _eventSeq = 0;
let _readyPromise = null;

let _gateExclusiveActive = false;
let _gateActiveReaders = 0;
const _waitingExclusive = [];
const _waitingShared = [];

const _partitionLocks = new Map();
let _partitionByteCache = null;
let _fullScanCount = 0;
let _storageReadCount = 0;

function setLockObserver(observerFn) {
_lockObserver = typeof observerFn === 'function' ? observerFn : null;
}

function recordLockEvent(event, name) {
if (_lockObserver) {
try {
_lockObserver(event, name);
} catch {}
}
}

function defaultSettings() {
return {
version: 8,
logEvents: true,
logEvidence: true,
theme: 'dark',
dampeningWindowMs: 4000,
autoContainRedirects: true,
clickbaitGuard: true,
updatedAt: Date.now()
};
}

function estimateBytes(val) {
if (val === undefined || val === null) return 0;
try {
const str = JSON.stringify(val);
return str ? str.length * 2 : 0;
} catch {
return 0;
}
}

function invalidateByteCache() {
_partitionByteCache = null;
}

function getByteAccountingMetrics() {
return {
fullScanCount: _fullScanCount,
storageReadCount: _storageReadCount,
isHydrated: _partitionByteCache !== null,
cachedTotal: _partitionByteCache ? Object.values(_partitionByteCache).reduce((a, b) => a + b, 0) : null,
byKey: _partitionByteCache ? { ..._partitionByteCache } : null
};
}

function resetByteAccountingMetrics() {
_fullScanCount = 0;
_storageReadCount = 0;
}

async function estimateTotalStorageBytes(forceScan = false) {
if (typeof chrome === 'undefined' || !chrome.storage?.local) return { total: 0, byKey: {} };
if (!forceScan && _partitionByteCache !== null) {
  let total = 0;
  const byKey = {};
  for (const [k, b] of Object.entries(_partitionByteCache)) {
    byKey[k] = b;
    total += b;
  }
  return { total, byKey };
}

_fullScanCount++;
_storageReadCount++;
const all = await chrome.storage.local.get(null);
let total = 0;
const byKey = {};
for (const [k, v] of Object.entries(all || {})) {
  const b = estimateBytes(v);
  byKey[k] = b;
  total += b;
}
_partitionByteCache = { ...byKey };
return { total, byKey };
}

async function ensureQuotaBudgetBeforeWrite(partitionKey, incomingBytes) {
const { total, byKey } = await estimateTotalStorageBytes();
const currentPartitionBytes = byKey[partitionKey] || 0;
const replacementDelta = Math.max(0, incomingBytes - currentPartitionBytes);
if (total + replacementDelta > GLOBAL_HARD_CAP) {
throw new Error(`QuotaExceededError: global storage cap ${GLOBAL_HARD_CAP} bytes exceeded`);
}
return true;
}

async function withTransactionGateShared(fn) {
while (_gateExclusiveActive || _waitingExclusive.length > 0) {
await new Promise(resolve => _waitingShared.push(resolve));
}
_gateActiveReaders++;
recordLockEvent('L0+', 'shared');
try {
return await fn();
} finally {
_gateActiveReaders--;
recordLockEvent('L0-', 'shared');
if (_gateActiveReaders === 0 && _waitingExclusive.length > 0) {
const nextExclusive = _waitingExclusive.shift();
nextExclusive();
}
}
}

async function withTransactionGateExclusive(fn) {
if (_gateExclusiveActive || _gateActiveReaders > 0) {
await new Promise(resolve => _waitingExclusive.push(resolve));
}
_gateExclusiveActive = true;
recordLockEvent('L0+', 'exclusive');
try {
return await fn();
} finally {
_gateExclusiveActive = false;
recordLockEvent('L0-', 'exclusive');
if (_waitingExclusive.length > 0) {
const nextExclusive = _waitingExclusive.shift();
nextExclusive();
} else {
while (_waitingShared.length > 0) {
const nextShared = _waitingShared.shift();
nextShared();
}
}
}
}

async function withPartitionLock(partitionName, fn) {
while (_partitionLocks.get(partitionName)) {
await _partitionLocks.get(partitionName);
}
let resolveLock;
const lockPromise = new Promise(resolve => {
resolveLock = resolve;
});
_partitionLocks.set(partitionName, lockPromise);
recordLockEvent('L1+', partitionName);
try {
return await fn();
} finally {
_partitionLocks.delete(partitionName);
recordLockEvent('L1-', partitionName);
resolveLock();
}
}

async function withMultiPartitionLock(partitionNames, fn) {
const sorted = [...new Set(partitionNames)].sort((a, b) => {
return CANONICAL_PARTITION_ORDER.indexOf(a) - CANONICAL_PARTITION_ORDER.indexOf(b);
});
async function acquire(index) {
  if (index >= sorted.length) {
    return await fn();
  }
  return withPartitionLock(sorted[index], () => acquire(index + 1));
}

return acquire(0);
}

async function get(key, defaultValue = null) {
if (typeof chrome === 'undefined' || !chrome.storage?.local) return defaultValue;
_storageReadCount++;
const res = await chrome.storage.local.get(key);
return res[key] !== undefined ? res[key] : defaultValue;
}

async function set(key, val) {
if (typeof chrome === 'undefined' || !chrome.storage?.local) return;
_storageReadCount++;
await chrome.storage.local.set({ [key]: val });
if (_partitionByteCache !== null) {
_partitionByteCache[key] = estimateBytes(val);
}
}

async function safeSetWithQuotaRetry(key, val, prunerFn = null) {
const bytes = estimateBytes(val);
try {
await set(key, val);
if (_partitionByteCache !== null) {
_partitionByteCache[key] = bytes;
}
return val;
} catch (err) {
if (prunerFn) {
const pruned = await prunerFn(val);
const prunedBytes = estimateBytes(pruned);
await set(key, pruned);
if (_partitionByteCache !== null) {
_partitionByteCache[key] = prunedBytes;
}
return pruned;
}
throw err;
}
}

function pruneTieredEvents(events, maxBytes, maxCount) {
let arr = Array.isArray(events) ? [...events] : [];
if (arr.length > maxCount) {
arr = arr.slice(0, maxCount);
}
while (arr.length > 10 && estimateBytes(arr) > maxBytes) {
const lowIndex = arr.findIndex(e => e.severity === 'low');
if (lowIndex !== -1) {
arr.splice(lowIndex, 1);
} else {
const infoIndex = arr.findIndex(e => e.severity === 'info');
if (infoIndex !== -1) {
arr.splice(infoIndex, 1);
} else {
arr.pop();
}
}
}
return arr;
}

function pruneRedirectChains(chains, maxBytes, maxCount) {
let arr = Array.isArray(chains) ? [...chains] : [];
if (arr.length > maxCount) {
arr = arr.slice(0, maxCount);
}
while (arr.length > 5 && estimateBytes(arr) > maxBytes) {
arr.pop();
}
return arr;
}

function sanitizeGraphNode(node) {
if (!node || typeof node !== 'object' || typeof node.id !== 'string') return null;
const sanitized = { ...node };
if (sanitized.id.startsWith('origin:')) {
  const hostPart = sanitized.id.slice('origin:'.length);
  if (typeof hostPart !== 'string' || hostPart.length === 0 || hostPart.length > 253 || /[\x00-\x1f\x7f\s]/.test(hostPart)) {
    return null;
  }
  const norm = CorsairSecurity.normalizeHostname(hostPart);
  if (!norm || !CorsairSecurity.isValidHostname(norm)) {
    return null;
  }
  sanitized.id = `origin:${norm}`;
  if (!sanitized.host) {
    sanitized.host = norm;
  }
}

if (sanitized.host) {
  if (typeof sanitized.host !== 'string' || sanitized.host.length === 0 || sanitized.host.length > 253 || /[\x00-\x1f\x7f\s]/.test(sanitized.host)) {
    return null;
  }
  const norm = CorsairSecurity.normalizeHostname(sanitized.host);
  if (!norm || !CorsairSecurity.isValidHostname(norm)) {
    return null;
  }
  sanitized.host = norm;
  if (sanitized.id.startsWith('origin:') && sanitized.id !== `origin:${norm}`) {
    return null;
  }
}

return sanitized;
}

async function getGraph() {
return get(KEYS.graph, { version: 2, nodes: {}, edges: [] });
}

async function mutateGraph(mutatorFn) {
await ensureReady();
return withTransactionGateShared(async () => {
await ensureQuotaBudgetBeforeWrite(KEYS.graph, 2048);
return withPartitionLock('siteGraph', async () => {
const graph = await getGraph();
const mutated = await mutatorFn(graph);
const target = mutated || graph;
    if (!target.nodes || typeof target.nodes !== 'object') target.nodes = {};
    if (!Array.isArray(target.edges)) target.edges = [];

    const protectedHosts = new Set(
      Object.entries(_profilesCache || {})
        .filter(([, p]) => p?.protected === true)
        .map(([h]) => h)
    );

    let curBytes = estimateBytes(target);
    let nodeCount = Object.keys(target.nodes).length;
    let edgeCount = target.edges.length;

    while (nodeCount > MAX_NODES || edgeCount > MAX_EDGES || curBytes > SOFT_BUDGETS.siteGraph) {
      let madeProgress = false;

      if (target.edges.length > MAX_EDGES) {
        target.edges.sort((a, b) => (Number(a.lastSeen || a.timestamp) || 0) - (Number(b.lastSeen || b.timestamp) || 0));
        const excess = target.edges.length - MAX_EDGES;
        target.edges.splice(0, excess);
        madeProgress = true;
      }

      const connected = new Set();
      for (const e of target.edges) {
        if (e.from) connected.add(e.from);
        if (e.to) connected.add(e.to);
      }
      for (const [id, n] of Object.entries(target.nodes)) {
        const host = n?.host || id.replace(/^origin:/, '');
        if (!protectedHosts.has(host) && !connected.has(id)) {
          delete target.nodes[id];
          madeProgress = true;
        }
      }

      nodeCount = Object.keys(target.nodes).length;
      curBytes = estimateBytes(target);

      if (nodeCount > MAX_NODES || curBytes > SOFT_BUDGETS.siteGraph) {
        const candidates = Object.entries(target.nodes).filter(([id, n]) => {
          const host = n?.host || id.replace(/^origin:/, '');
          return !protectedHosts.has(host);
        });

        if (candidates.length > 0) {
          candidates.sort((a, b) => (Number(a[1]?.lastSeen) || 0) - (Number(b[1]?.lastSeen) || 0));
          const numToRemove = Math.max(1, Math.min(candidates.length, Math.ceil(candidates.length * 0.25)));
          const toRemoveSet = new Set(candidates.slice(0, numToRemove).map(c => c[0]));

          for (const id of toRemoveSet) {
            delete target.nodes[id];
          }

          target.edges = target.edges.filter(e => !toRemoveSet.has(e.from) && !toRemoveSet.has(e.to));
          madeProgress = true;
        } else if (target.edges.length > 0) {
          const numEdgesToRemove = Math.max(1, Math.ceil(target.edges.length * 0.25));
          target.edges.sort((a, b) => (Number(a.lastSeen || a.timestamp) || 0) - (Number(b.lastSeen || b.timestamp) || 0));
          target.edges.splice(0, numEdgesToRemove);
          madeProgress = true;
        }
      }

      nodeCount = Object.keys(target.nodes).length;
      edgeCount = target.edges.length;
      curBytes = estimateBytes(target);

      if (!madeProgress) break;
    }

    if (curBytes > SOFT_BUDGETS.siteGraph) {
      return graph;
    }

    await safeSetWithQuotaRetry(KEYS.graph, target, async g => {
      g.edges = g.edges.slice(-Math.floor(MAX_EDGES * 0.5));
      return g;
    });
    return target;
  });
});
}

async function addGraphNode(node) {
if (!node?.id || typeof node !== 'object') return getGraph();
const sanitizedNode = sanitizeGraphNode(node);
if (!sanitizedNode) return getGraph();
return mutateGraph(graph => {
  const now = Date.now();
  const old = graph.nodes[sanitizedNode.id] || {};
  graph.nodes[sanitizedNode.id] = {
    ...old,
    ...CorsairSecurity.sanitizeObject(sanitizedNode),
    lastSeen: now,
    seenCount: Number(old.seenCount || 0) + 1
  };
});
}

async function addGraphEdge(edge) {
if (!edge || typeof edge !== 'object') return getGraph();
return addGraphEdgesBatch([edge]);
}

async function addGraphEdgesBatch(edgesArray) {
if (!Array.isArray(edgesArray) || edgesArray.length === 0) return getGraph();
const validatedEntries = [];

for (const item of edgesArray) {
  if (!item || typeof item !== 'object') continue;

  const validNodes = [];
  for (const n of item.nodes || []) {
    const sanitized = sanitizeGraphNode(n);
    if (!sanitized) continue;
    validNodes.push(sanitized);
  }

  const edgeObj = item.edge;
  if (!edgeObj || typeof edgeObj !== 'object' || !edgeObj.from || !edgeObj.to) {
    continue;
  }

  let fromId = String(edgeObj.from);
  let toId = String(edgeObj.to);

  if (fromId.startsWith('origin:')) {
    const hostPart = fromId.slice('origin:'.length);
    if (typeof hostPart !== 'string' || hostPart.length === 0 || hostPart.length > 253 || /[\x00-\x1f\x7f\s]/.test(hostPart)) continue;
    const norm = CorsairSecurity.normalizeHostname(hostPart);
    if (!norm || !CorsairSecurity.isValidHostname(norm)) continue;
    fromId = `origin:${norm}`;
  }

  if (toId.startsWith('origin:')) {
    const hostPart = toId.slice('origin:'.length);
    if (typeof hostPart !== 'string' || hostPart.length === 0 || hostPart.length > 253 || /[\x00-\x1f\x7f\s]/.test(hostPart)) continue;
    const norm = CorsairSecurity.normalizeHostname(hostPart);
    if (!norm || !CorsairSecurity.isValidHostname(norm)) continue;
    toId = `origin:${norm}`;
  }

  validatedEntries.push({ validNodes, edgeObj, fromId, toId });
}

if (validatedEntries.length === 0) {
  return getGraph();
}

return mutateGraph(graph => {
  const now = Date.now();
  const updatedNodesInBatch = new Set();

  for (const entry of validatedEntries) {
    for (const n of entry.validNodes) {
      if (!n?.id) continue;
      const old = graph.nodes[n.id] || {};
      const countIncrement = updatedNodesInBatch.has(n.id) ? 0 : 1;
      updatedNodesInBatch.add(n.id);
      graph.nodes[n.id] = {
        ...old,
        ...CorsairSecurity.sanitizeObject(n),
        lastSeen: now,
        seenCount: Number(old.seenCount || 0) + countIncrement
      };
    }

    const sanitized = CorsairSecurity.sanitizeObject({
      ...entry.edgeObj,
      from: entry.fromId,
      to: entry.toId
    });

    const existing = graph.edges.find(e => e.from === sanitized.from && e.to === sanitized.to && e.kind === sanitized.kind);
    if (existing) {
      existing.seenCount = (Number(existing.seenCount) || 1) + 1;
      existing.lastSeen = now;
      existing.timestamp = now;
      if (sanitized.data) {
        existing.data = { ...(existing.data || {}), ...sanitized.data };
      }
    } else {
      graph.edges.push({
        ...sanitized,
        seenCount: 1,
        lastSeen: now,
        timestamp: now
      });
    }
  }
});
}

async function getProfiles() {
await ensureReady();
return { ...(_profilesCache || {}) };
}

async function getProfile(host) {
await ensureReady();
const h = CorsairSecurity.normalizeHostname(host);
return _profilesCache && _profilesCache[h] ? { ..._profilesCache[h] } : null;
}

async function saveProfilesUnlocked(v) {
await ensureQuotaBudgetBeforeWrite(KEYS.profiles, estimateBytes(v));
return withPartitionLock('domainProfiles', async () => {
const sanitized = CorsairSecurity.sanitizeObject(v) || {};
const prev = _profilesCache;
_profilesCache = { ...sanitized };
try {
await safeSetWithQuotaRetry(KEYS.profiles, sanitized);
return sanitized;
} catch (err) {
_profilesCache = prev;
throw err;
}
});
}

async function saveProfiles(v) {
await ensureReady();
return withTransactionGateShared(() => saveProfilesUnlocked(v));
}

async function upsertProfile(host, profile) {
return mutateProfile(host, () => profile);
}

async function mutateProfileUnlocked(host, mutatorFn) {
await ensureQuotaBudgetBeforeWrite(KEYS.profiles, 1024);
return withPartitionLock('domainProfiles', async () => {
const h = CorsairSecurity.normalizeHostname(host);
if (!CorsairSecurity.isValidHostname(h)) throw new Error('invalid-domain');
const current = _profilesCache[h] ? { ..._profilesCache[h] } : null;
const mutated = await mutatorFn(current);
if (!mutated) return null;
const normalized = CorsairSecurity.normalizeProfile(mutated);
const previous = _profilesCache[h] ? { ..._profilesCache[h] } : undefined;
_profilesCache[h] = normalized;
try {
await safeSetWithQuotaRetry(KEYS.profiles, _profilesCache);
return { ...normalized };
} catch (err) {
if (previous !== undefined) {
_profilesCache[h] = previous;
} else {
delete _profilesCache[h];
}
throw err;
}
});
}

async function mutateProfile(host, mutatorFn) {
await ensureReady();
return withTransactionGateShared(() => mutateProfileUnlocked(host, mutatorFn));
}

async function removeProfileUnlocked(host) {
return withPartitionLock('domainProfiles', async () => {
const h = CorsairSecurity.normalizeHostname(host);
const previous = _profilesCache[h] ? { ..._profilesCache[h] } : undefined;
delete _profilesCache[h];
try {
await safeSetWithQuotaRetry(KEYS.profiles, _profilesCache);
return true;
} catch (err) {
if (previous !== undefined) _profilesCache[h] = previous;
throw err;
}
});
}

async function removeProfile(host) {
await ensureReady();
return withTransactionGateShared(() => removeProfileUnlocked(host));
}

async function getSettings() {
await ensureReady();
return { ...(_settingsCache || defaultSettings()) };
}

async function patchSettings(patch) {
await ensureReady();
return withTransactionGateShared(async () => {
await ensureQuotaBudgetBeforeWrite(KEYS.settings, estimateBytes(patch));
return withPartitionLock('globalSettings', async () => {
const safePatch = CorsairSecurity.sanitizeObject(patch) || {};
const previous = { ..._settingsCache };
const nextVer = (Number(_settingsCache._version) || 0) + 1;
_settingsCache = { ..._settingsCache, ...safePatch, _version: nextVer, updatedAt: Date.now() };
try {
await safeSetWithQuotaRetry(KEYS.settings, _settingsCache);
return { ..._settingsCache };
} catch (err) {
_settingsCache = previous;
throw err;
}
});
});
}

async function getEvents(limit = 200) {
const arr = await get(KEYS.events, []);
return Array.isArray(arr) ? arr.slice(0, limit) : [];
}

async function appendEventUnlocked(event) {
const s = await getSettings();
if (!s.logEvents) return null;
await ensureQuotaBudgetBeforeWrite(KEYS.events, estimateBytes(event));
return withPartitionLock('activityLog', async () => {
const arr = await get(KEYS.events, []);
_eventSeq += 1;
const rec = {
id: crypto.randomUUID(),
seq: _eventSeq,
timestamp: Date.now(),
...CorsairSecurity.sanitizeObject(event)
};
const combined = [rec, ...(Array.isArray(arr) ? arr : [])];
const pruned = pruneTieredEvents(combined, SOFT_BUDGETS.activityLog, MAX_EVENTS);
await safeSetWithQuotaRetry(KEYS.events, pruned, async val => {
return pruneTieredEvents(val, SOFT_BUDGETS.activityLog * 0.7, Math.floor(MAX_EVENTS * 0.7));
});
return rec;
});
}

async function appendEvent(event) {
await ensureReady();
return withTransactionGateShared(() => appendEventUnlocked(event));
}

async function clearEvents() {
return withTransactionGateShared(async () => {
return withPartitionLock('activityLog', async () => {
_eventSeq = 0;
return set(KEYS.events, []);
});
});
}

async function getChains(limit = 100) {
const arr = await get(KEYS.chains, []);
return Array.isArray(arr) ? arr.slice(0, limit) : [];
}

async function saveChain(chain) {
return withTransactionGateShared(async () => {
await ensureQuotaBudgetBeforeWrite(KEYS.chains, estimateBytes(chain));
return withPartitionLock('redirectChains', async () => {
const arr = await get(KEYS.chains, []);
const item = { id: crypto.randomUUID(), timestamp: Date.now(), ...CorsairSecurity.sanitizeObject(chain) };
const combined = [item, ...(Array.isArray(arr) ? arr : [])];
const pruned = pruneRedirectChains(combined, SOFT_BUDGETS.redirectChains, MAX_CHAINS);
if (estimateBytes(pruned) > SOFT_BUDGETS.redirectChains) {
return item;
}
await safeSetWithQuotaRetry(KEYS.chains, pruned, async c => {
return pruneRedirectChains(c, SOFT_BUDGETS.redirectChains * 0.5, Math.floor(MAX_CHAINS * 0.5));
});
return item;
});
});
}

async function clearTransientTelemetry() {
return withTransactionGateShared(async () => {
return withMultiPartitionLock(['evidenceStore', 'redirectChains', 'siteGraph'], async () => {
await set(KEYS.graph, { version: 2, nodes: {}, edges: [] });
await set(KEYS.chains, []);
if (typeof chrome !== 'undefined' && chrome.storage?.local) {
await chrome.storage.local.set({ [KEYS.evidence]: [] });
}
});
});
}

async function getDnrRegistry() {
return get(KEYS.dnrRegistry, { rules: {}, reverse: {}, meta: {}, nextId: 100001 });
}

async function saveDnrRegistryUnlocked(registry) {
return safeSetWithQuotaRetry(KEYS.dnrRegistry, registry);
}

async function saveDnrRegistry(registry) {
return withTransactionGateShared(async () => {
await ensureQuotaBudgetBeforeWrite(KEYS.dnrRegistry, estimateBytes(registry));
return withPartitionLock('dnrRuleRegistry', async () => {
return saveDnrRegistryUnlocked(registry);
});
});
}

async function getRegressionCases() {
return get(KEYS.cases, []);
}

async function saveRegressionCasesUnlocked(cases) {
const clean = Array.isArray(cases) ? cases.slice(0, 500).map(c => CorsairSecurity.sanitizeObject(c)) : [];
return safeSetWithQuotaRetry(KEYS.cases, clean);
}

async function saveRegressionCases(cases) {
await ensureReady();
return withTransactionGateShared(async () => {
await ensureQuotaBudgetBeforeWrite(KEYS.cases, estimateBytes(cases));
return withPartitionLock('regressionCases', async () => {
return saveRegressionCasesUnlocked(cases);
});
});
}

async function commitImportConfig(candidate) {
await ensureQuotaBudgetBeforeWrite(KEYS.profiles, estimateBytes(candidate.profiles));
const batch = {
[KEYS.profiles]: candidate.profiles,
[KEYS.settings]: candidate.settings,
[KEYS.cases]: candidate.regressionCases
};
await chrome.storage.local.set(batch);
_profilesCache = { ...candidate.profiles };
_settingsCache = { ...candidate.settings };
invalidateByteCache();
}

async function rollbackImportConfig(snapshot) {
const batch = {
[KEYS.profiles]: snapshot.profiles,
[KEYS.settings]: snapshot.settings,
[KEYS.cases]: snapshot.regression,
[KEYS.dnrRegistry]: snapshot.registry
};
await chrome.storage.local.set(batch);
_profilesCache = { ...snapshot.profiles };
_settingsCache = { ...snapshot.settings };
invalidateByteCache();
}

async function initializeSequence() {
const events = await get(KEYS.events, []);
let max = 0;
for (const e of events) {
if (typeof e.seq === 'number' && e.seq > max) max = e.seq;
}
return max;
}

async function ensureReady() {
if (_readyPromise) return _readyPromise;
_readyPromise = (async () => {
_profilesCache = await get(KEYS.profiles, {});
_settingsCache = await get(KEYS.settings, defaultSettings());
_eventSeq = await initializeSequence();
await estimateTotalStorageBytes(true);
return true;
})();
return _readyPromise;
}

async function getAgentContext({ domain = '', limit = 50 } = {}) {
await ensureReady();
const hasDomain = typeof domain === 'string' && domain.trim().length > 0;
const d = hasDomain ? CorsairSecurity.normalizeHostname(domain) : '';
const isValidDomain = hasDomain ? CorsairSecurity.isValidHostname(d) : false;
const [events, graph, chains] = await Promise.all([
  getEvents(limit * 2),
  getGraph(),
  getChains(limit)
]);

let filteredEvents = [];
let filteredChains = [];
let relevantNodes = {};
let relevantEdges = [];
let evidence = [];

if (hasDomain && !isValidDomain) {
  filteredEvents = [];
  filteredChains = [];
  relevantNodes = {};
  relevantEdges = [];
  evidence = [];
} else if (hasDomain && isValidDomain) {
  filteredEvents = events.filter(e => {
    const dom = CorsairSecurity.normalizeHostname(e.domain || '');
    const dst = CorsairSecurity.normalizeHostname(e.destination || '');
    return dom === d || dst === d;
  }).slice(0, limit);

  filteredChains = chains.filter(c => {
    const src = CorsairSecurity.normalizeHostname(c.sourceHost || '');
    const hasHops = Array.isArray(c.hops) && c.hops.some(h => CorsairSecurity.normalizeHostname(h.host || '') === d);
    return src === d || hasHops;
  }).slice(0, limit);

  if (graph.nodes) {
    for (const [id, node] of Object.entries(graph.nodes)) {
      const nodeHost = CorsairSecurity.normalizeHostname(node.host || id.replace(/^origin:/, ''));
      if (nodeHost === d || id === `origin:${d}`) {
        relevantNodes[id] = node;
      }
    }
  }

  relevantEdges = (graph.edges || []).filter(e => {
    const fromHost = e.from ? CorsairSecurity.normalizeHostname(e.from.replace(/^origin:/, '')) : '';
    const toHost = e.to ? CorsairSecurity.normalizeHostname(e.to.replace(/^origin:/, '')) : '';
    return fromHost === d || toHost === d;
  });

  if (typeof CorsairEvidence !== 'undefined') {
    const rawEvidence = await CorsairEvidence.recent(limit * 2);
    evidence = rawEvidence.filter(e => {
      const evOrigin = CorsairSecurity.normalizeHostname(e.origin || '');
      return evOrigin === d;
    }).slice(0, limit);
  }
} else {
  filteredEvents = events.slice(0, limit);
  filteredChains = chains.slice(0, limit);
  relevantNodes = graph.nodes || {};
  relevantEdges = graph.edges || [];
  if (typeof CorsairEvidence !== 'undefined') {
    evidence = (await CorsairEvidence.recent(limit)).slice(0, limit);
  }
}

return {
  domain: d,
  profiles: (hasDomain && isValidDomain) ? { [d]: _profilesCache[d] || null } : (hasDomain ? {} : { ..._profilesCache }),
  events: filteredEvents,
  chains: filteredChains,
  graph: {
    nodes: relevantNodes,
    edges: relevantEdges
  },
  evidence
};
}

const _unlockedStorageCapability = Object.freeze({
async ensureReadyUnlocked() {
await ensureReady();
return _profilesCache !== null;
},
isReadyUnlocked() {
return _profilesCache !== null;
},
getProfileUnlocked(host) {
const h = CorsairSecurity.normalizeHostname(host);
return _profilesCache && _profilesCache[h] ? { ..._profilesCache[h] } : null;
},
getProfilesUnlocked() {
return _profilesCache !== null ? { ..._profilesCache } : null;
},
async getDnrRegistryUnlocked() {
return get(KEYS.dnrRegistry, { rules: {}, reverse: {}, meta: {}, nextId: 100001 });
},
async saveDnrRegistryUnlocked(registry) {
return safeSetWithQuotaRetry(KEYS.dnrRegistry, registry);
},
async saveProfileUnlocked(host, profile) {
const h = CorsairSecurity.normalizeHostname(host);
_profilesCache[h] = profile ? CorsairSecurity.normalizeProfile(profile) : undefined;
if (!_profilesCache[h]) delete _profilesCache[h];
await safeSetWithQuotaRetry(KEYS.profiles, _profilesCache);
return _profilesCache[h];
},
async addBlockedDestinationUnlocked(host, destination) {
const h = CorsairSecurity.normalizeHostname(host);
const dst = CorsairSecurity.normalizeHostname(destination);
if (!CorsairSecurity.isValidHostname(h) || !CorsairSecurity.isValidHostname(dst)) return null;
if (h === dst || CorsairSecurity.sameOrSubdomain(dst, h)) return null;
const base = (_profilesCache && _profilesCache[h]) || CorsairSecurity.fortressProfile({});
const setDests = new Set(base.blockedDestinationDomains || []);
setDests.add(dst);
const updated = CorsairSecurity.normalizeProfile({
...base,
blockedDestinationDomains: [...setDests].slice(0, 1000)
});
_profilesCache[h] = updated;
await safeSetWithQuotaRetry(KEYS.profiles, _profilesCache);
return { ...updated };
},
async removeBlockedDestinationUnlocked(host, destination) {
const h = CorsairSecurity.normalizeHostname(host);
const dst = CorsairSecurity.normalizeHostname(destination);
if (!_profilesCache || !_profilesCache[h]) return null;
const base = _profilesCache[h];
const updated = CorsairSecurity.normalizeProfile({
...base,
blockedDestinationDomains: (base.blockedDestinationDomains || []).filter(d => d !== dst)
});
_profilesCache[h] = updated;
await safeSetWithQuotaRetry(KEYS.profiles, _profilesCache);
return { ...updated };
}
});

return {
KEYS,
SOFT_BUDGETS,
GLOBAL_HARD_CAP,
setLockObserver,
ensureReady,
estimateTotalStorageBytes,
ensureQuotaBudgetBeforeWrite,
getByteAccountingMetrics,
resetByteAccountingMetrics,
invalidateByteCache,
estimateBytes,
withTransactionGateShared,
withTransactionGateExclusive,
withPartitionLock,
withMultiPartitionLock,
getGraph,
mutateGraph,
addGraphNode,
addGraphEdge,
addGraphEdgesBatch,
getProfiles,
getProfile,
saveProfiles,
saveProfilesUnlocked,
saveProfileUnlocked: (h, p) => _unlockedStorageCapability.saveProfileUnlocked(h, p),
upsertProfile,
mutateProfile,
mutateProfileUnlocked,
removeProfile,
removeProfileUnlocked,
getSettings,
patchSettings,
getEvents,
appendEvent,
appendEventUnlocked,
clearEvents,
getChains,
saveChain,
clearTransientTelemetry,
getDnrRegistry,
saveDnrRegistry,
saveDnrRegistryUnlocked,
getRegressionCases,
saveRegressionCases,
commitImportConfig,
rollbackImportConfig,
getAgentContext,
safeSetWithQuotaRetry,
_unlockedStorageCapability
};
})();

globalThis.CorsairStorage = CorsairStorage;
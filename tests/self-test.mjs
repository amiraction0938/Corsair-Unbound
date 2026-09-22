import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

const ROOT = path.resolve(new URL('..', import.meta.url).pathname);
const coreFiles = [
  'core/security.js',
  'core/storage.js',
  'core/dnr.js',
  'core/redirects.js',
  'core/intelligence.js',
  'core/verifier.js',
  'core/observation.js',
  'core/evidence.js',
  'core/migration.js',
  'core/tool-router.js',
  'core/replay.js'
];

function makeEvent() {
  const listeners = [];
  return {
    addListener(fn) { listeners.push(fn); },
    async trigger(...args) {
      return Promise.all(listeners.map(fn => fn(...args)));
    },
    listeners
  };
}

function clone(value) { return JSON.parse(JSON.stringify(value)); }

function makeStorageArea() {
  const store = new Map();
  return {
    async get(keys = null) {
      if (keys === null) return Object.fromEntries(store.entries());
      if (typeof keys === 'string') return { [keys]: store.get(keys) };
      if (Array.isArray(keys)) return Object.fromEntries(keys.map(k => [k, store.get(k)]));
      const out = {};
      for (const [k, def] of Object.entries(keys || {})) out[k] = store.has(k) ? store.get(k) : def;
      return out;
    },
    async set(obj) { for (const [k, v] of Object.entries(obj || {})) store.set(k, clone(v)); },
    async remove(keys) { for (const k of Array.isArray(keys) ? keys : [keys]) store.delete(k); }
  };
}

function makeChrome() {
  const dynamicRules = new Map();
  const runtime = {
    id: 'test-extension-id',
    getURL: file => `chrome-extension://test-extension-id/${file}`,
    onStartup: makeEvent(),
    onInstalled: makeEvent(),
    onMessage: makeEvent()
  };
  const chrome = {
    runtime,
    storage: { local: makeStorageArea(), session: makeStorageArea() },
    declarativeNetRequest: {
      MAX_NUMBER_OF_DYNAMIC_RULES: 30000,
      async getDynamicRules() { return [...dynamicRules.values()].map(clone); },
      async updateDynamicRules({ removeRuleIds = [], addRules = [] }) {
        const next = new Map(dynamicRules);
        for (const id of removeRuleIds) next.delete(Number(id));
        const seen = new Set(next.keys());
        for (const rule of addRules) {
          if (!Number.isInteger(rule?.id) || seen.has(rule.id)) throw new Error('duplicate-or-invalid-rule-id');
          seen.add(rule.id);
          next.set(rule.id, clone(rule));
        }
        if (next.size > 30000) throw new Error('rule-capacity');
        dynamicRules.clear();
        for (const [id, rule] of next) dynamicRules.set(id, rule);
      }
    },
    tabs: {
      async get() { return null; },
      async update() {},
      async remove() {},
      async query() { return []; },
      onRemoved: makeEvent(),
      onCreated: makeEvent()
    },
    downloads: { onCreated: makeEvent(), async cancel() {} },
    windows: { onCreated: makeEvent() },
    notifications: { async create() {} },
    webNavigation: {
      onBeforeNavigate: makeEvent(),
      onCommitted: makeEvent(),
      onErrorOccurred: makeEvent()
    }
  };
  return chrome;
}

async function sendMessage(chrome, message, sender) {
  const listener = chrome.runtime.onMessage.listeners[0];
  assert(listener, 'runtime.onMessage listener missing');
  return new Promise((resolve, reject) => {
    let settled = false;
    const send = value => { settled = true; resolve(value); };
    try {
      const result = listener(message, sender, send);
      if (result !== true && !settled) resolve(undefined);
    } catch (error) {
      reject(error);
    }
  });
}

const chrome = makeChrome();
const context = vm.createContext({
  chrome,
  console,
  URL,
  URLSearchParams,
  crypto,
  setTimeout,
  clearTimeout,
  Date,
  Math,
  Map,
  Set,
  Promise,
  Number,
  String,
  Boolean,
  Object,
  Array,
  JSON,
  RegExp,
  Error,
  TypeError
});

for (const file of coreFiles) {
  vm.runInContext(fs.readFileSync(path.join(ROOT, file), 'utf8'), context, { filename: file });
}
const backgroundSource = fs.readFileSync(path.join(ROOT, 'background.js'), 'utf8').replace(/^import .*;\r?\n/gm, '');
vm.runInContext(backgroundSource, context, { filename: 'background.js' });

await chrome.runtime.onInstalled.trigger({ reason: 'install' });
await context.CorsairStorage.ensureReady();
assert.equal(JSON.stringify(await context.CorsairStorage.getProfiles()), '{}');

const pageSender = {
  id: chrome.runtime.id,
  url: 'https://example.com/',
  origin: 'https://example.com',
  tab: { id: 7 }
};
const pageResult = await sendMessage(chrome, {
  type: 'page-observation',
  observation: { url: 'https://example.com/', externalHosts: ['cdn.example.net', 'cdn.example.net'] }
}, pageSender);
assert.equal(pageResult.ok, true);
const graph = await context.CorsairStorage.getGraph();
assert(graph.nodes['origin:example.com']);
assert(graph.nodes['origin:cdn.example.net']);
assert.equal(graph.edges.length, 1);

const internalSender = {
  id: chrome.runtime.id,
  url: chrome.runtime.getURL('popup.html'),
  origin: `chrome-extension://${chrome.runtime.id}`
};
const patchResult = await sendMessage(chrome, {
  type: 'patch-profile',
  domain: 'example.com',
  patch: { protected: true, mode: 'fortress', blockedDestinationDomains: ['bad.test'] }
}, internalSender);
assert.equal(patchResult.ok, true);
assert.equal(patchResult.profile.protected, true);
assert.deepEqual(patchResult.profile.blockedDestinationDomains, ['bad.test']);

const dnr = await context.CorsairDNR.listCorsairRules();
assert.equal(dnr.length, 1);
assert.deepEqual(dnr[0].condition.initiatorDomains, ['example.com']);
assert.deepEqual(dnr[0].condition.requestDomains, ['bad.test']);

const diagnostics = await sendMessage(chrome, { type: 'get-diagnostics' }, internalSender);
assert.equal(diagnostics.ok, true);
assert.equal(diagnostics.diagnostics.profileCount, 1);
assert.equal(diagnostics.diagnostics.dnrRuleCount, 1);

const evidence = await context.CorsairEvidence.add({
  kind: 'self-test',
  origin: 'example.com',
  tabId: 7,
  data: { ok: true }
});
assert.equal(evidence.kind, 'self-test');
assert.equal((await context.CorsairEvidence.byTab(7)).length, 1);

// Restart recovery: session-scoped observation/redirect data for tabs that
// no longer exist must be pruned once the service worker comes back up.
await chrome.storage.session.set({
  'networkObs:999': [{ url: 'https://stale.example/', timestamp: Date.now() }],
  'redirectTab:999': { tabId: 999, generationId: 'stale-gen', hops: [] }
});
chrome.tabs.query = async () => [{ id: 7 }];
await context.reconcileSessionState();
const staleAfterReconcile = await chrome.storage.session.get(['networkObs:999', 'redirectTab:999']);
assert.equal(staleAfterReconcile['networkObs:999'], undefined);
assert.equal(staleAfterReconcile['redirectTab:999'], undefined);

// Direct navigation to a blocked destination (no redirect chain to analyze,
// e.g. a typed URL) is blocked at the DNR layer; Chrome reports this via
// onErrorOccurred with net::ERR_BLOCKED_BY_CLIENT. That must surface as a
// real, evidenced event rather than being silently discarded.
await context.CorsairRedirects.beginNavigation({
  tabId: 42,
  frameId: 0,
  url: 'https://example.com/',
  transitionType: 'typed'
});
await chrome.webNavigation.onErrorOccurred.trigger({
  frameId: 0,
  tabId: 42,
  url: 'https://bad.test/',
  error: 'net::ERR_BLOCKED_BY_CLIENT'
});
const eventsAfterBlock = await context.CorsairStorage.getEvents(10);
assert(eventsAfterBlock.some(e => e.type === 'navigation_blocked' && e.destination === 'bad.test'));
const evidenceAfterBlock = await context.CorsairEvidence.recent(10);
assert(evidenceAfterBlock.some(e => e.kind === 'navigation_blocked'));

// A popup/new tab opened from a protected page toward an explicitly
// blocked destination must actually be closed, not just logged.
chrome.tabs.get = async id => (id === 501 ? { id: 501, url: 'https://example.com/' } : null);
let removedTabId = null;
chrome.tabs.remove = async id => { removedTabId = id; };
await chrome.tabs.onCreated.trigger({
  id: 777,
  openerTabId: 501,
  windowId: 1,
  url: 'https://bad.test/landing'
});
assert.equal(removedTabId, 777);
const eventsAfterPopup = await context.CorsairStorage.getEvents(10);
assert(eventsAfterPopup.some(e => e.type === 'new_tab_blocked' && e.destination === 'bad.test'));

const removeResult = await sendMessage(chrome, {
  type: 'remove-profile',
  domain: 'example.com'
}, internalSender);
assert.equal(removeResult.ok, true);
assert.equal((await context.CorsairDNR.listCorsairRules()).length, 0);
assert.equal(await context.CorsairStorage.getProfile('example.com'), null);

console.log('Corsair Unbound self-test: PASS');
console.log(JSON.stringify({
  graphNodes: Object.keys(graph.nodes).length,
  graphEdges: graph.edges.length,
  evidence: 1,
  dnrAfterCleanup: 0
}, null, 2));

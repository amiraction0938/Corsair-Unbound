/* ============================================================
   CHROME.* MOCK
   ------------------------------------------------------------
   Minimal in-memory implementation of only the chrome.* surface
   that the modules under test actually touch. Not a polyfill,
   not an abstraction — just enough to exercise the real code.
   ============================================================ */

function createStorageArea(initial = {}) {
  let data = { ...initial };
  return {
    async get(keys) {
      if (keys === null || keys === undefined) return { ...data };
      if (typeof keys === 'string') {
        return Object.prototype.hasOwnProperty.call(data, keys)
          ? { [keys]: data[keys] }
          : {};
      }
      if (Array.isArray(keys)) {
        const out = {};
        for (const k of keys) if (k in data) out[k] = data[k];
        return out;
      }
      // Object form: default values for missing keys
      const out = {};
      for (const k of Object.keys(keys)) {
        out[k] = Object.prototype.hasOwnProperty.call(data, k) ? data[k] : keys[k];
      }
      return out;
    },
    async set(obj) { Object.assign(data, obj); },
    async remove(keys) {
      if (Array.isArray(keys)) for (const k of keys) delete data[k];
      else delete data[keys];
    },
    async clear() { data = {}; },
    _dump() { return { ...data }; },
    _seed(obj) { Object.assign(data, obj); }
  };
}

export function installChromeMock({
  local = {},
  session = {}
} = {}) {
  const state = {
    dynamicRules: [],
    sessionRules: []
  };

  const declarativeNetRequest = {
    MAX_NUMBER_OF_DYNAMIC_RULES: 30000,
    MAX_NUMBER_OF_SESSION_RULES: 5000,

    async getDynamicRules() { return state.dynamicRules.map(r => ({ ...r })); },
    async getSessionRules() { return state.sessionRules.map(r => ({ ...r })); },

    async updateDynamicRules({ removeRuleIds = [], addRules = [] } = {}) {
      const rm = new Set(removeRuleIds);
      state.dynamicRules = state.dynamicRules.filter(r => !rm.has(r.id));
      for (const r of addRules) {
        if (!state.dynamicRules.some(x => x.id === r.id)) {
          state.dynamicRules.push({ ...r });
        }
      }
    },

    async updateSessionRules({ removeRuleIds = [], addRules = [] } = {}) {
      const rm = new Set(removeRuleIds);
      state.sessionRules = state.sessionRules.filter(r => !rm.has(r.id));
      for (const r of addRules) {
        if (!state.sessionRules.some(x => x.id === r.id)) {
          state.sessionRules.push({ ...r });
        }
      }
    }
  };

  const chrome = {
    runtime: {
      id: 'test-extension-id',
      getURL: (path) => `chrome-extension://test-extension-id/${path}`,
      getManifest: () => ({ version: '1.8.1', manifest_version: 3 })
    },
    storage: {
      local: createStorageArea(local),
      session: createStorageArea(session),
      onChanged: { addListener: () => {}, removeListener: () => {} }
    },
    declarativeNetRequest
  };

  globalThis.chrome = chrome;
  return { chrome, state };
}

export function uninstallChromeMock() {
  delete globalThis.chrome;
}
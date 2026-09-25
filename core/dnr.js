const CorsairDNR = (() => {
  'use strict';

  const BLOCK_BASE = 100000;
  const FORTRESS_BASE = 800000;
  const FORTRESS_ALLOW_BASE = 850000;
  const USER_BLOCK_BASE = 900000;

  const FORTRESS_SPAN = 40000;
  const FORTRESS_ALLOW_SPAN = 40000;
  const USER_BLOCK_SPAN = 40000;

  let _dnrLock = false;
  let _dnrLockWaiters = [];
  let _dnrLockObserver = null;
  const _unlockedStorage = typeof CorsairStorage !== 'undefined' ? CorsairStorage._unlockedStorageCapability : null;

  function setDnrLockObserver(observerFn) {
    _dnrLockObserver = typeof observerFn === 'function' ? observerFn : null;
  }
  function recordDnrLockEvent(ev, name) {
    if (_dnrLockObserver) { try { _dnrLockObserver(ev, name); } catch {} }
  }
  async function withDnrLock(fn) {
    while (_dnrLock) {
      await new Promise(resolve => _dnrLockWaiters.push(resolve));
    }
    _dnrLock = true;
    recordDnrLockEvent('L2+', 'dnrLock');
    try { return await fn(); }
    finally {
      _dnrLock = false;
      recordDnrLockEvent('L2-', 'dnrLock');
      if (_dnrLockWaiters.length > 0) {
        const next = _dnrLockWaiters.shift();
        next();
      }
    }
  }

  /* ------------------------------------------------------------------
     COLLISION-FREE RULE ID ALLOCATION
     ------------------------------------------------------------------
     Previous scheme hashed the host with djb2 and took `% 40000`, so
     two different hosts could (and inevitably did) land on the same
     Fortress rule ID. That meant: arming site B silently disarmed
     site A. The new scheme uses the hash ONLY as a *preferred starting
     point* and then does linear probing against the set of IDs that
     are currently in use. Allocation is therefore guaranteed unique
     within the active session-rule set.
     ------------------------------------------------------------------ */

  function fnv1a(str) {
    let h = 0x811c9dc5;
    for (let i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    return h >>> 0;
  }

  function findFreeId(base, span, key, usedIds) {
    const start = fnv1a(key) % span;
    for (let i = 0; i < span; i++) {
      const candidate = base + ((start + i) % span);
      if (!usedIds.has(candidate)) return candidate;
    }
    return null;
  }

  function getDynamicCapacity(type = 'block') {
    if (typeof chrome !== 'undefined' && chrome.declarativeNetRequest?.MAX_NUMBER_OF_DYNAMIC_RULES) {
      return Math.min(29500, chrome.declarativeNetRequest.MAX_NUMBER_OF_DYNAMIC_RULES);
    }
    return 29500;
  }

  function computeNextId(stagedRules, stagedReverse, currentDnrRules, maxCap) {
    const usedIds = new Set([
      ...currentDnrRules.map(r => Number(r.id)),
      ...Object.values(stagedRules || {}).map(Number),
      ...Object.keys(stagedReverse || {}).map(Number)
    ]);
    let candidate = BLOCK_BASE + 1;
    while (usedIds.has(candidate) && candidate <= BLOCK_BASE + maxCap) candidate++;
    if (candidate > BLOCK_BASE + maxCap) return null;
    return candidate;
  }

  function makeBlockRule({ source, destination, id = null, reason = 'auto-block' } = {}) {
    const src = CorsairSecurity.normalizeHostname(source);
    const dst = CorsairSecurity.normalizeHostname(destination);
    if (!CorsairSecurity.isValidHostname(src) || !CorsairSecurity.isValidHostname(dst)) return null;
    if (src === dst || CorsairSecurity.sameOrSubdomain(dst, src)) return null;
    const ruleId = Number(id);
    if (!Number.isInteger(ruleId) || ruleId <= BLOCK_BASE) return null;
    return {
      id: ruleId,
      priority: 100,
      action: { type: 'block' },
      condition: {
        initiatorDomains: [src],
        requestDomains: [dst],
        resourceTypes: ['main_frame']
      }
    };
  }

  async function listCorsairRules() {
    if (typeof chrome === 'undefined' || !chrome.declarativeNetRequest?.getDynamicRules) return [];
    const all = await chrome.declarativeNetRequest.getDynamicRules();
    return (Array.isArray(all) ? all : []).filter(r => r.id > BLOCK_BASE && r.id <= BLOCK_BASE + 30000);
  }

  /* =========================================================
     FORTRESS CATCH-ALL (session rules)
     ========================================================= */

  async function listFortressCatchAllRules() {
    if (typeof chrome === 'undefined' || !chrome.declarativeNetRequest?.getSessionRules) return [];
    const all = await chrome.declarativeNetRequest.getSessionRules();
    return (Array.isArray(all) ? all : []).filter(r =>
      r.id >= FORTRESS_BASE && r.id < FORTRESS_BASE + FORTRESS_SPAN
    );
  }

  async function listFortressAllowRules() {
    if (typeof chrome === 'undefined' || !chrome.declarativeNetRequest?.getSessionRules) return [];
    const all = await chrome.declarativeNetRequest.getSessionRules();
    return (Array.isArray(all) ? all : []).filter(r =>
      r.id >= FORTRESS_ALLOW_BASE && r.id < FORTRESS_ALLOW_BASE + FORTRESS_ALLOW_SPAN
    );
  }

  async function listUserBlockRules() {
    if (typeof chrome === 'undefined' || !chrome.declarativeNetRequest?.getSessionRules) return [];
    const all = await chrome.declarativeNetRequest.getSessionRules();
    return (Array.isArray(all) ? all : []).filter(r =>
      r.id >= USER_BLOCK_BASE && r.id < USER_BLOCK_BASE + USER_BLOCK_SPAN
    );
  }

  async function syncFortressCatchAll(profiles) {
    if (typeof chrome === 'undefined' || !chrome.declarativeNetRequest?.updateSessionRules) {
      return { ok: false, error: 'dnr-session-unavailable' };
    }

    const wanted = new Set();
    for (const [host, prof] of Object.entries(profiles || {})) {
      if (prof && prof.protected === true && prof.mode === 'fortress') {
        const norm = CorsairSecurity.normalizeHostname(host);
        if (CorsairSecurity.isValidHostname(norm)) wanted.add(norm);
      }
    }

    const current = await listFortressCatchAllRules();
    const currentByHost = new Map(); // host -> existing rule (kept as-is)
    const usedIds = new Set();

    for (const r of current) {
      const host = r.condition?.initiatorDomains?.[0];
      if (!host) continue;
      if (wanted.has(host)) {
        currentByHost.set(host, r);
        usedIds.add(r.id);
      }
    }

    const toAdd = [];
    const toRemove = [];

    for (const r of current) {
      const host = r.condition?.initiatorDomains?.[0];
      if (!host || !wanted.has(host)) toRemove.push(r.id);
    }

    for (const host of wanted) {
      if (currentByHost.has(host)) continue;
      const id = findFreeId(FORTRESS_BASE, FORTRESS_SPAN, 'catch-all::' + host, usedIds);
      if (id == null) continue; // span exhausted — extremely unlikely
      usedIds.add(id);
      toAdd.push({
        id,
        priority: 50,
        action: {
          type: 'redirect',
          redirect: {
            url: chrome.runtime.getURL(
              `blocked.html?reason=fortress&host=${encodeURIComponent(host)}`
            )
          }
        },
        condition: {
          initiatorDomains: [host],
          resourceTypes: ['main_frame'],
          domainType: 'thirdParty'
        }
      });
    }

    if (toAdd.length === 0 && toRemove.length === 0) {
      return { ok: true, installed: 0, removed: 0, total: wanted.size };
    }

    try {
      await chrome.declarativeNetRequest.updateSessionRules({
        removeRuleIds: toRemove,
        addRules: toAdd
      });
      return { ok: true, installed: toAdd.length, removed: toRemove.length, total: wanted.size };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  }

  async function installFortressAllow(source, destination, ttlMs = 30000) {
    if (typeof chrome === 'undefined' || !chrome.declarativeNetRequest?.updateSessionRules) {
      return { ok: false, error: 'dnr-session-unavailable' };
    }
    const src = CorsairSecurity.normalizeHostname(source);
    const dst = CorsairSecurity.normalizeHostname(destination);
    if (!CorsairSecurity.isValidHostname(src) || !CorsairSecurity.isValidHostname(dst)) {
      return { ok: false, error: 'invalid-domain' };
    }

    // Idempotency: if an allow rule for this exact pair already exists,
    // reuse its ID so repeated installs never leak duplicate rules.
    const existing = await listFortressAllowRules();
    const usedIds = new Set();
    for (const r of existing) {
      const rSrc = r.condition?.initiatorDomains?.[0];
      const rDst = r.condition?.requestDomains?.[0];
      if (rSrc === src && rDst === dst) {
        return { ok: true, ruleId: r.id, ttlMs, reused: true };
      }
      usedIds.add(r.id);
    }

    const ruleId = findFreeId(FORTRESS_ALLOW_BASE, FORTRESS_ALLOW_SPAN, src + '|' + dst, usedIds);
    if (ruleId == null) return { ok: false, error: 'allow-id-exhausted' };

    try {
      await chrome.declarativeNetRequest.updateSessionRules({
        addRules: [{
          id: ruleId,
          priority: 200,
          action: { type: 'allow' },
          condition: {
            initiatorDomains: [src],
            requestDomains: [dst],
            resourceTypes: ['main_frame']
          }
        }]
      });
      return { ok: true, ruleId, ttlMs };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  }

  async function clearFortressAllow(source, destination) {
    if (typeof chrome === 'undefined' || !chrome.declarativeNetRequest?.updateSessionRules) return { ok: true };
    const src = CorsairSecurity.normalizeHostname(source);
    const dst = CorsairSecurity.normalizeHostname(destination);
    if (!CorsairSecurity.isValidHostname(src) || !CorsairSecurity.isValidHostname(dst)) return { ok: true };
    try {
      const rules = await listFortressAllowRules();
      const ids = rules
        .filter(r => r.condition?.initiatorDomains?.[0] === src && r.condition?.requestDomains?.[0] === dst)
        .map(r => r.id);
      if (ids.length > 0) {
        await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: ids });
      }
    } catch {}
    return { ok: true };
  }

  async function syncUserBlocklist(domains) {
    if (typeof chrome === 'undefined' || !chrome.declarativeNetRequest?.updateSessionRules) {
      return { ok: false, error: 'dnr-session-unavailable' };
    }

    const wanted = new Set();
    for (const raw of (Array.isArray(domains) ? domains : [])) {
      const norm = CorsairSecurity.normalizeHostname(raw);
      if (CorsairSecurity.isValidHostname(norm)) wanted.add(norm);
    }

    const current = await listUserBlockRules();
    const currentByHost = new Map();
    const usedIds = new Set();

    for (const r of current) {
      const host = r.condition?.requestDomains?.[0];
      if (!host) continue;
      if (wanted.has(host)) {
        currentByHost.set(host, r);
        usedIds.add(r.id);
      }
    }

    const toAdd = [];
    const toRemove = [];

    for (const r of current) {
      const host = r.condition?.requestDomains?.[0];
      if (!host || !wanted.has(host)) toRemove.push(r.id);
    }

    for (const host of wanted) {
      if (currentByHost.has(host)) continue;
      const id = findFreeId(USER_BLOCK_BASE, USER_BLOCK_SPAN, 'userblock::' + host, usedIds);
      if (id == null) continue;
      usedIds.add(id);
      // extensionPath with a query string is not reliably preserved by
      // Chrome's DNR engine (documented behavior is path-only). We
      // instead redirect to blocked.html?host=... using a full URL
      // constructed at rule-install time so query params survive.
      toAdd.push({
        id,
        priority: 60,
        action: {
          type: 'redirect',
          redirect: {
            url: chrome.runtime.getURL(
              `blocked.html?reason=user-blocklist&host=${encodeURIComponent(host)}`
            )
          }
        },
        condition: {
          requestDomains: [host],
          resourceTypes: ['main_frame']
        }
      });
    }

    if (toAdd.length === 0 && toRemove.length === 0) {
      return { ok: true, installed: 0, removed: 0, total: wanted.size };
    }
    try {
      await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: toRemove, addRules: toAdd });
      return { ok: true, installed: toAdd.length, removed: toRemove.length, total: wanted.size };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  }

  /* =========================================================
     EXISTING BLOCK FUNCTIONS (dynamic rules, per-source block)
     ========================================================= */

  async function ensureNavigationBlockUnlocked(source, destination, reason) {
    const src = CorsairSecurity.normalizeHostname(source);
    const dst = CorsairSecurity.normalizeHostname(destination);
    if (!CorsairSecurity.isValidHostname(src) || !CorsairSecurity.isValidHostname(dst)) return { ok: false, error: 'invalid-domain' };
    if (src === dst || CorsairSecurity.sameOrSubdomain(dst, src)) return { ok: false, error: 'cannot-block-self-or-subdomain' };

    const profile = _unlockedStorage ? _unlockedStorage.getProfileUnlocked(src) : null;
    if (!profile || profile.protected !== true || profile.mode !== 'fortress') {
      return { ok: false, error: 'source-not-protected' };
    }

    const pairKey = `${src}>${dst}`;
    const originalReg = await _unlockedStorage.getDnrRegistryUnlocked();
    const stagedReg = {
      rules: { ...(originalReg.rules || {}) },
      reverse: { ...(originalReg.reverse || {}) },
      meta: { ...(originalReg.meta || {}) },
      nextId: originalReg.nextId || (BLOCK_BASE + 1)
    };

    const currentRules = await listCorsairRules();
    const existing = currentRules.find(r =>
      r.condition?.initiatorDomains?.includes(src) && r.condition?.requestDomains?.includes(dst)
    );

    let assignedId = null;
    if (existing) {
      const existingId = Number(existing.id);
      const revOwner = stagedReg.reverse[existingId];
      if (!revOwner || revOwner === pairKey) assignedId = existingId;
    }
    if (!assignedId && stagedReg.rules[pairKey]) {
      const stagedId = Number(stagedReg.rules[pairKey]);
      const revOwner = stagedReg.reverse[stagedId];
      const chromeRuleWithId = currentRules.find(r => r.id === stagedId);
      const chromeOwnerMatches = !chromeRuleWithId ||
        (chromeRuleWithId.condition?.initiatorDomains?.includes(src) && chromeRuleWithId.condition?.requestDomains?.includes(dst));
      if ((!revOwner || revOwner === pairKey) && chromeOwnerMatches) assignedId = stagedId;
    }
    if (!assignedId) {
      const maxCap = getDynamicCapacity('block');
      if (currentRules.length >= maxCap) await reconcileRegistryUnlocked();
      assignedId = computeNextId(stagedReg.rules, stagedReg.reverse, await listCorsairRules(), maxCap);
      if (!assignedId) return { ok: false, error: 'dnr-quota-saturated', saturated: true };
    }

    const assignedIdNum = Number(assignedId);
    const existingRevOwner = stagedReg.reverse[assignedIdNum];
    if (existingRevOwner && existingRevOwner !== pairKey) {
      assignedId = computeNextId(stagedReg.rules, stagedReg.reverse, await listCorsairRules(), getDynamicCapacity('block'));
      if (!assignedId) return { ok: false, error: 'dnr-quota-saturated', saturated: true };
    }

    const oldId = stagedReg.rules[pairKey];
    if (oldId && Number(oldId) !== Number(assignedId) && stagedReg.reverse[Number(oldId)] === pairKey) {
      delete stagedReg.reverse[Number(oldId)];
    }

    stagedReg.rules[pairKey] = Number(assignedId);
    stagedReg.reverse[Number(assignedId)] = pairKey;
    stagedReg.meta[pairKey] = {
      createdAt: stagedReg.meta[pairKey]?.createdAt || Date.now(),
      lastReferencedAt: Date.now(),
      source: src, destination: dst,
      reason: String(reason || 'profile destination block')
    };

    const rule = makeBlockRule({ source: src, destination: dst, id: assignedId, reason });
    if (!rule) return { ok: false, error: 'rule-creation-failed' };

    let ruleAddedToBrowser = false;
    const existingRuleInBrowser = currentRules.find(r => r.id === Number(assignedId));
    if (!existingRuleInBrowser) {
      try {
        await chrome.declarativeNetRequest.updateDynamicRules({ addRules: [rule] });
        ruleAddedToBrowser = true;
      } catch (err) { return { ok: false, error: err.message, rolledBack: false }; }
    }

    let registrySaved = false;
    try {
      await _unlockedStorage.saveDnrRegistryUnlocked(stagedReg);
      registrySaved = true;
      await _unlockedStorage.addBlockedDestinationUnlocked(src, dst);
    } catch (storageErr) {
      if (registrySaved) { try { await _unlockedStorage.saveDnrRegistryUnlocked(originalReg); } catch {} }
      if (ruleAddedToBrowser) {
        try { await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [rule.id] }); } catch {}
      }
      return { ok: false, error: 'storage-commit-failed: ' + storageErr.message, rolledBack: true };
    }
    return { ok: true, rule: existing || rule };
  }

  async function ensureNavigationBlock(source, destination, reason) {
    return CorsairStorage.withTransactionGateShared(async () => {
      if (typeof CorsairStorage !== 'undefined' && CorsairStorage.ensureQuotaBudgetBeforeWrite) {
        await CorsairStorage.ensureQuotaBudgetBeforeWrite(CorsairStorage.KEYS.dnrRegistry, 512);
      }
      return CorsairStorage.withMultiPartitionLock(['dnrRuleRegistry', 'domainProfiles'], async () => {
        return withDnrLock(() => ensureNavigationBlockUnlocked(source, destination, reason));
      });
    });
  }

  async function removeNavigationBlockUnlocked(source, destination) {
    const src = CorsairSecurity.normalizeHostname(source);
    const dst = CorsairSecurity.normalizeHostname(destination);
    const pairKey = `${src}>${dst}`;
    const stagedReg = await _unlockedStorage.getDnrRegistryUnlocked();
    const ruleId = stagedReg.rules[pairKey];
    if (ruleId) {
      try { await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [Number(ruleId)] }); } catch {}
      delete stagedReg.rules[pairKey];
      delete stagedReg.reverse[ruleId];
      if (stagedReg.meta) delete stagedReg.meta[pairKey];
      await _unlockedStorage.saveDnrRegistryUnlocked(stagedReg);
    }
    await _unlockedStorage.removeBlockedDestinationUnlocked(src, dst);
    return { ok: true };
  }

  async function removeNavigationBlock(source, destination) {
    return CorsairStorage.withTransactionGateShared(async () => {
      return CorsairStorage.withMultiPartitionLock(['dnrRuleRegistry', 'domainProfiles'], async () => {
        return withDnrLock(() => removeNavigationBlockUnlocked(source, destination));
      });
    });
  }

  async function removeRulesForHostUnlocked(source) {
    const src = CorsairSecurity.normalizeHostname(source);
    const stagedReg = await _unlockedStorage.getDnrRegistryUnlocked();
    const toRemoveIds = [];
    for (const [pairKey, id] of Object.entries(stagedReg.rules || {})) {
      if (pairKey.startsWith(`${src}>`)) {
        toRemoveIds.push(Number(id));
        delete stagedReg.rules[pairKey];
        delete stagedReg.reverse[id];
        if (stagedReg.meta) delete stagedReg.meta[pairKey];
      }
    }
    if (toRemoveIds.length > 0) {
      try { await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: toRemoveIds }); } catch {}
      await _unlockedStorage.saveDnrRegistryUnlocked(stagedReg);
    }
    return { ok: true, removedCount: toRemoveIds.length };
  }

  async function removeRulesForHost(source) {
    return CorsairStorage.withTransactionGateShared(async () => {
      return CorsairStorage.withMultiPartitionLock(['dnrRuleRegistry', 'domainProfiles'], async () => {
        return withDnrLock(() => removeRulesForHostUnlocked(source));
      });
    });
  }

  async function clearCorsairRulesUnlocked() {
    const current = await listCorsairRules();
    const ids = current.map(r => r.id);
    if (ids.length > 0) {
      await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: ids });
    }
    await _unlockedStorage.saveDnrRegistryUnlocked({ rules: {}, reverse: {}, meta: {}, nextId: 100001 });
    return { ok: true, clearedCount: ids.length };
  }

  async function clearCorsairRules() {
    return CorsairStorage.withTransactionGateShared(async () => {
      return CorsairStorage.withPartitionLock('dnrRuleRegistry', async () => {
        return withDnrLock(() => clearCorsairRulesUnlocked());
      });
    });
  }

  async function rebuildFromProfilesUnlocked() {
    return reconcileRegistryUnlocked();
  }

  async function rebuildFromProfiles() {
    return CorsairStorage.withTransactionGateShared(async () => {
      return CorsairStorage.withMultiPartitionLock(['dnrRuleRegistry', 'domainProfiles'], async () => {
        return withDnrLock(() => rebuildFromProfilesUnlocked());
      });
    });
  }

  async function reconcileRegistryUnlocked(activeProfiles = null) {
    let profiles = activeProfiles;
    if (!profiles && _unlockedStorage) {
      try {
        if (typeof _unlockedStorage.ensureReadyUnlocked === 'function') await _unlockedStorage.ensureReadyUnlocked();
        profiles = _unlockedStorage.getProfilesUnlocked();
      } catch (err) {
        return { ok: false, error: 'storage-unhydrated: ' + err.message, reconciled: false, rulesPreserved: true };
      }
    }
    if (!profiles || typeof profiles !== 'object') {
      return { ok: false, error: 'storage-unhydrated', reconciled: false, rulesPreserved: true };
    }

    const fortressSync = await syncFortressCatchAll(profiles);

    const currentRules = await listCorsairRules();
    const currentRuleMap = new Map(currentRules.map(r => [r.id, r]));

    const stagedReg = await _unlockedStorage.getDnrRegistryUnlocked();
    if (!stagedReg.rules) stagedReg.rules = {};
    if (!stagedReg.reverse) stagedReg.reverse = {};
    if (!stagedReg.meta) stagedReg.meta = {};

    const validPairs = new Map();
    for (const [source, profile] of Object.entries(profiles)) {
      if (profile && profile.protected === true && profile.mode === 'fortress') {
        const blocked = Array.isArray(profile.blockedDestinationDomains) ? profile.blockedDestinationDomains : [];
        for (const dest of blocked) {
          if (dest && CorsairSecurity.isValidHostname(source) && CorsairSecurity.isValidHostname(dest)) {
            const pairKey = `${source}>${dest}`;
            validPairs.set(pairKey, { source, destination: dest });
          }
        }
      }
    }

    const toRemoveRuleIds = new Set();
    for (const r of currentRules) {
      const pairKey = stagedReg.reverse[r.id];
      if (!pairKey || !validPairs.has(pairKey)) {
        toRemoveRuleIds.add(r.id);
      } else {
        const pair = validPairs.get(pairKey);
        const matchesCondition = r.condition?.initiatorDomains?.includes(pair.source) &&
                                 r.condition?.requestDomains?.includes(pair.destination);
        if (!matchesCondition) toRemoveRuleIds.add(r.id);
      }
    }
    for (const removeId of toRemoveRuleIds) {
      const pKey = stagedReg.reverse[removeId];
      if (pKey) {
        if (stagedReg.rules[pKey] === removeId) delete stagedReg.rules[pKey];
        delete stagedReg.reverse[removeId];
        if (stagedReg.meta) delete stagedReg.meta[pKey];
      }
    }
    for (const [pKey, rId] of Object.entries(stagedReg.rules)) {
      if (!validPairs.has(pKey)) {
        delete stagedReg.rules[pKey];
        if (stagedReg.reverse[rId] === pKey) delete stagedReg.reverse[rId];
        if (stagedReg.meta) delete stagedReg.meta[pKey];
      }
    }

    const toAddRules = [];
    let saturated = false;
    let installedCount = 0;
    let skippedCount = 0;
    const availableCap = getDynamicCapacity('block');

    for (const [pairKey, { source, destination }] of validPairs.entries()) {
      let id = stagedReg.rules[pairKey];
      if (id && stagedReg.reverse[id] && stagedReg.reverse[id] !== pairKey) id = null;
      if (id && toRemoveRuleIds.has(Number(id))) id = null;

      if (!id) {
        const activeRulesInPlay = [
          ...currentRules.filter(r => !toRemoveRuleIds.has(r.id)),
          ...toAddRules
        ];
        if (activeRulesInPlay.length >= availableCap) id = null;
        else id = computeNextId(stagedReg.rules, stagedReg.reverse, activeRulesInPlay, availableCap);

        if (!id) { saturated = true; skippedCount++; continue; }

        stagedReg.rules[pairKey] = Number(id);
        stagedReg.reverse[Number(id)] = pairKey;
        if (!stagedReg.meta) stagedReg.meta = {};
        stagedReg.meta[pairKey] = {
          createdAt: Date.now(), lastReferencedAt: Date.now(),
          source, destination, reason: 'reconciliation restore'
        };
      }

      if (!currentRuleMap.has(Number(id)) || toRemoveRuleIds.has(Number(id))) {
        const rule = makeBlockRule({ source, destination, id, reason: 'reconciliation restore' });
        if (rule) { toAddRules.push(rule); installedCount++; }
        else skippedCount++;
      } else installedCount++;
    }

    const cleanToAddRules = toAddRules.filter(Boolean);
    if (toRemoveRuleIds.size > 0 || cleanToAddRules.length > 0) {
      try {
        await chrome.declarativeNetRequest.updateDynamicRules({
          removeRuleIds: [...toRemoveRuleIds],
          addRules: cleanToAddRules
        });
      } catch (browserErr) {
        return { ok: false, error: 'browser-update-failed: ' + browserErr.message, reconciled: false };
      }
    }

    await _unlockedStorage.saveDnrRegistryUnlocked(stagedReg);

    return {
      ok: true, reconciled: true, saturated,
      installed: installedCount, skipped: skippedCount,
      rulesCount: (await listCorsairRules()).length,
      fortress: fortressSync
    };
  }

  async function reconcileDnrRegistry(activeProfiles = null) {
    return CorsairStorage.withTransactionGateShared(async () => {
      return CorsairStorage.withMultiPartitionLock(['dnrRuleRegistry', 'domainProfiles'], async () => {
        return withDnrLock(() => reconcileRegistryUnlocked(activeProfiles));
      });
    });
  }

  async function patchProfileAtomic(host, mutatorFn) {
    const h = CorsairSecurity.normalizeHostname(host);
    if (!CorsairSecurity.isValidHostname(h)) return { ok: false, error: 'invalid-hostname' };
    return CorsairStorage.withTransactionGateExclusive(async () => {
      const origProfiles = await CorsairStorage.getProfiles();
      const current = origProfiles[h] ? { ...origProfiles[h] } : CorsairSecurity.fortressProfile({});
      const mutated = await mutatorFn(current);
      if (!mutated) return { ok: false, error: 'mutator-returned-null' };

      const snapshotRules = await listCorsairRules();
      const snapshotReg = await CorsairStorage.getDnrRegistry();

      try {
        await CorsairStorage.mutateProfileUnlocked(h, () => mutated);
        const reconRes = await CorsairStorage.withMultiPartitionLock(['dnrRuleRegistry', 'domainProfiles'], async () => {
          return withDnrLock(() => reconcileRegistryUnlocked());
        });
        if (!reconRes.ok) throw new Error('dnr-reconcile-failed: ' + reconRes.error);
        return { ok: true, profile: mutated, fortress: reconRes.fortress };
      } catch (err) {
        let rolledBack = false;
        try {
          await CorsairStorage.saveProfilesUnlocked(origProfiles);
          await CorsairStorage.saveDnrRegistryUnlocked(snapshotReg);
          const cur = await listCorsairRules();
          await chrome.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: cur.map(r => r.id),
            addRules: snapshotRules
          });
          rolledBack = true;
        } catch {}
        return { ok: false, error: err.message, rolledBack, inconsistent: !rolledBack };
      }
    });
  }

  return {
    BLOCK_BASE,
    FORTRESS_BASE,
    FORTRESS_ALLOW_BASE,
    USER_BLOCK_BASE,
    setDnrLockObserver,
    withDnrLock,
    getDynamicCapacity,
    listCorsairRules,
    makeBlockRule,
    computeNextId,
    ensureNavigationBlockUnlocked,
    ensureNavigationBlock,
    removeNavigationBlockUnlocked,
    removeNavigationBlock,
    removeRulesForHostUnlocked,
    removeRulesForHost,
    clearCorsairRulesUnlocked,
    clearCorsairRules,
    rebuildFromProfilesUnlocked,
    rebuildFromProfiles,
    reconcileRegistryUnlocked,
    reconcileDnrRegistry,
    patchProfileAtomic,
    syncFortressCatchAll,
    installFortressAllow,
    clearFortressAllow,
    listFortressCatchAllRules,
    listFortressAllowRules,
    syncUserBlocklist,
    listUserBlockRules
  };
})();

globalThis.CorsairDNR = CorsairDNR;
const CorsairDNR = (() => {
  'use strict';

  const BLOCK_BASE = 100000;
  const FORTRESS_BASE = 800000;        // session rules for fortress catch-all
  const FORTRESS_ALLOW_BASE = 850000;  // session rules for temporary allows

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

  function fortressRuleIdFor(source) {
    let h = 5381;
    for (let i = 0; i < source.length; i++) h = ((h << 5) + h + source.charCodeAt(i)) | 0;
    return FORTRESS_BASE + (Math.abs(h) % 40000);
  }

  function fortressAllowRuleIdFor(source, destination) {
    const key = `${source}|${destination}`;
    let h = 5381;
    for (let i = 0; i < key.length; i++) h = ((h << 5) + h + key.charCodeAt(i)) | 0;
    return FORTRESS_ALLOW_BASE + (Math.abs(h) % 40000);
  }

  async function listFortressCatchAllRules() {
    if (typeof chrome === 'undefined' || !chrome.declarativeNetRequest?.getSessionRules) return [];
    const all = await chrome.declarativeNetRequest.getSessionRules();
    return (Array.isArray(all) ? all : []).filter(r =>
      r.id >= FORTRESS_BASE && r.id < FORTRESS_BASE + 40000
    );
  }

  async function listFortressAllowRules() {
    if (typeof chrome === 'undefined' || !chrome.declarativeNetRequest?.getSessionRules) return [];
    const all = await chrome.declarativeNetRequest.getSessionRules();
    return (Array.isArray(all) ? all : []).filter(r =>
      r.id >= FORTRESS_ALLOW_BASE && r.id < FORTRESS_ALLOW_BASE + 40000
    );
  }

  /**
   * Sync fortress catch-all rules with the set of Fortress-armed profiles.
   * Called after every profile mutation and on startup.
   */
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
    const currentMap = new Map(); // host -> ruleId
    for (const r of current) {
      const host = r.condition?.initiatorDomains?.[0];
      if (host) currentMap.set(host, r.id);
    }

    const toAdd = [];
    const toRemove = [];

    for (const host of wanted) {
      if (!currentMap.has(host)) {
        toAdd.push({
          id: fortressRuleIdFor(host),
          priority: 50,
          action: {
            type: 'redirect',
            redirect: { extensionPath: '/blocked.html' }
          },
          condition: {
            initiatorDomains: [host],
            resourceTypes: ['main_frame'],
            domainType: 'thirdParty'
          }
        });
      }
    }

    for (const [host, id] of currentMap) {
      if (!wanted.has(host)) toRemove.push(id);
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

  /**
   * Temporarily allow a specific source→destination main_frame navigation.
   * Higher priority than catch-all.
   *
   * IMPORTANT: expiry is scheduled by the CALLER (background.js) via
   * CorsairAlarms.scheduleFortressAllowExpiry(ruleId, ttlMs).
   * We intentionally do NOT use setTimeout here because service worker
   * restarts would silently drop the timer and leave the rule installed
   * forever. chrome.alarms survives restarts.
   */
  async function installFortressAllow(source, destination, ttlMs = 30000) {
    if (typeof chrome === 'undefined' || !chrome.declarativeNetRequest?.updateSessionRules) {
      return { ok: false, error: 'dnr-session-unavailable' };
    }
    const src = CorsairSecurity.normalizeHostname(source);
    const dst = CorsairSecurity.normalizeHostname(destination);
    if (!CorsairSecurity.isValidHostname(src) || !CorsairSecurity.isValidHostname(dst)) {
      return { ok: false, error: 'invalid-domain' };
    }
    const ruleId = fortressAllowRuleIdFor(src, dst);
    try {
      await chrome.declarativeNetRequest.updateSessionRules({
        removeRuleIds: [ruleId],
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
    const ruleId = fortressAllowRuleIdFor(src, dst);
    try {
      await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: [ruleId] });
    } catch {}
    return { ok: true };
  }

  /* =========================================================
     EXISTING BLOCK FUNCTIONS
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

    // === Fortress catch-all sync (session rules) ===
    const fortressSync = await syncFortressCatchAll(profiles);

    // === Dynamic block rules (existing behaviour) ===
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
    // Fortress API
    syncFortressCatchAll,
    installFortressAllow,
    clearFortressAllow,
    listFortressCatchAllRules,
    listFortressAllowRules
  };
})();

globalThis.CorsairDNR = CorsairDNR;
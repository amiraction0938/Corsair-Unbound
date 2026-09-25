const CorsairMigration = (() => {
  'use strict';

  const BACKUP_VERSION = 11;

  function validateCandidate(candidate) {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
    return { ok: false, error: 'invalid-candidate: payload must be an object' };
  }
  if (candidate.format !== 'corsair-unbound') {
    return { ok: false, error: 'invalid-format: format must be corsair-unbound' };
  }
  if (typeof candidate.version !== 'number' || candidate.version < 1) {
    return { ok: false, error: 'invalid-version: version must be a positive number' };
  }
  // Reject files from a FUTURE schema we don't understand. Older
  // schemas (v1–v10) are accepted — their missing fields will be
  // filled in below with empty defaults.
  if (candidate.version > BACKUP_VERSION) {
    return { ok: false, error: `backup-too-new: file was created by a newer version (v${candidate.version} > v${BACKUP_VERSION})` };
  }

  if (candidate.settings && (typeof candidate.settings !== 'object' || Array.isArray(candidate.settings))) {
    return { ok: false, error: 'invalid-settings: settings must be an object' };
  }
  if (candidate.regressionCases && !Array.isArray(candidate.regressionCases)) {
    return { ok: false, error: 'invalid-regression-cases: regressionCases must be an array' };
  }

  /* ---------- preferences (NEW in v11) ---------- */
  const rawPrefs = (candidate.preferences && typeof candidate.preferences === 'object' && !Array.isArray(candidate.preferences))
    ? candidate.preferences
    : {};
  const prefTheme = String(rawPrefs.theme || '').slice(0, 20);
  const prefLang  = String(rawPrefs.language || '').slice(0, 8);
  candidate.preferences = {
    theme: (prefTheme === 'light' || prefTheme === 'dark') ? prefTheme : null,
    language: /^[a-z]{2}$/.test(prefLang) ? prefLang : null,
    tourCompleted: rawPrefs.tourCompleted === true,
    onboardingCompletedV1: rawPrefs.onboardingCompletedV1 === true
  };

    /* ---------- profiles ---------- */
    if (candidate.profiles) {
      if (typeof candidate.profiles !== 'object' || Array.isArray(candidate.profiles)) {
        return { ok: false, error: 'invalid-profiles: profiles must be an object' };
      }

      const canonicalProfiles = {};
      for (const [rawHost, rawProf] of Object.entries(candidate.profiles)) {
        if (typeof rawHost !== 'string' || rawHost.length === 0 || rawHost.length > 253 || /[\x00-\x1f\x7f\s]/.test(rawHost)) {
          return { ok: false, error: `invalid-profile-host: ${rawHost}` };
        }
        const normHost = CorsairSecurity.normalizeHostname(rawHost);
        if (!normHost || !CorsairSecurity.isValidHostname(normHost)) {
          return { ok: false, error: `invalid-profile-host: ${rawHost}` };
        }
        if (!rawProf || typeof rawProf !== 'object' || Array.isArray(rawProf)) {
          return { ok: false, error: `invalid-profile-object: for host ${rawHost}` };
        }

        const normalizedProf = CorsairSecurity.normalizeProfile(rawProf);

        if (Array.isArray(normalizedProf.blockedDestinationDomains)) {
          const canonicalDests = [];
          const seenDests = new Set();
          for (const rawDst of normalizedProf.blockedDestinationDomains) {
            if (typeof rawDst !== 'string' || rawDst.length === 0 || rawDst.length > 253 || /[\x00-\x1f\x7f\s]/.test(rawDst)) {
              return { ok: false, error: `invalid-blocked-destination: ${rawDst} in host ${rawHost}` };
            }
            const normDst = CorsairSecurity.normalizeHostname(rawDst);
            if (!normDst || !CorsairSecurity.isValidHostname(normDst)) {
              return { ok: false, error: `invalid-blocked-destination: ${rawDst} in host ${rawHost}` };
            }
            if (normDst === normHost || CorsairSecurity.sameOrSubdomain(normDst, normHost)) {
              return { ok: false, error: `prohibited-destination-block: cannot block self or subdomain ${normDst} for host ${normHost}` };
            }
            if (!seenDests.has(normDst)) {
              seenDests.add(normDst);
              canonicalDests.push(normDst);
            }
          }
          normalizedProf.blockedDestinationDomains = canonicalDests;
        }

        canonicalProfiles[normHost] = normalizedProf;
      }
      candidate.profiles = canonicalProfiles;
    } else {
      candidate.profiles = {};
    }

    /* ---------- settings ---------- */
    if (candidate.settings) {
      candidate.settings = CorsairSecurity.sanitizeObject(candidate.settings) || {};
    } else {
      candidate.settings = {};
    }

    /* ---------- regression ---------- */
    if (candidate.regressionCases) {
      candidate.regressionCases = (candidate.regressionCases || []).slice(0, 500).map(c => CorsairSecurity.sanitizeObject(c));
    } else {
      candidate.regressionCases = [];
    }

    /* ---------- custom domain scripts ---------- */
    if (candidate.customDomainScripts != null) {
      if (typeof candidate.customDomainScripts !== 'object' || Array.isArray(candidate.customDomainScripts)) {
        return { ok: false, error: 'invalid-custom-scripts: must be an object' };
      }
      const cleanScripts = {};
      for (const [rawHost, entry] of Object.entries(candidate.customDomainScripts)) {
        const normHost = CorsairSecurity.normalizeHostname(rawHost);
        if (!normHost || !CorsairSecurity.isValidHostname(normHost)) continue;
        if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
        const code = typeof entry.code === 'string' ? entry.code.slice(0, CorsairSecurity.CUSTOM_SCRIPT_MAX_LEN) : '';
        // Re-lint every imported script — a backup could have been
        // edited by hand, so we do not trust it silently.
        if (code) {
          const lint = CorsairSecurity.lintCustomScript(code);
          if (!lint.ok) continue; // drop the offending script, keep the rest
        }
        cleanScripts[normHost] = {
          code,
          enabled: entry.enabled !== false,
          createdAt: Number(entry.createdAt) || Date.now(),
          updatedAt: Number(entry.updatedAt) || Date.now()
        };
      }
      candidate.customDomainScripts = cleanScripts;
    } else {
      candidate.customDomainScripts = {};
    }

    /* ---------- user trusted / blocked domains ---------- */
    candidate.userTrustedDomains = sanitizeDomainList(candidate.userTrustedDomains);
    candidate.userBlockedDomains = sanitizeDomainList(candidate.userBlockedDomains);

    /* ---------- threat cache (safe-scanned domains) ---------- */
    if (candidate.threatCache != null) {
      if (typeof candidate.threatCache !== 'object' || Array.isArray(candidate.threatCache)) {
        return { ok: false, error: 'invalid-threat-cache: must be an object' };
      }
      const cleanCache = {};
      let count = 0;
      for (const [rawHost, entry] of Object.entries(candidate.threatCache)) {
        if (count >= 5000) break;
        const normHost = CorsairSecurity.normalizeHostname(rawHost);
        if (!normHost || !CorsairSecurity.isValidHostname(normHost)) continue;
        if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
        const verdict = String(entry.verdict || '').slice(0, 20);
        if (!['clean', 'suspicious', 'malicious', 'unknown'].includes(verdict)) continue;
        cleanCache[normHost] = {
          host: normHost,
          status: String(entry.status || 'analyzed').slice(0, 30),
          verdict,
          riskPercentage: Math.max(0, Math.min(100, Number(entry.riskPercentage) || 0)),
          flaggedEngines: Array.isArray(entry.flaggedEngines)
            ? entry.flaggedEngines.slice(0, 20).map(String)
            : [],
          stats: entry.stats && typeof entry.stats === 'object' ? {
            harmless: Number(entry.stats.harmless) || 0,
            malicious: Number(entry.stats.malicious) || 0,
            suspicious: Number(entry.stats.suspicious) || 0,
            undetected: Number(entry.stats.undetected) || 0
          } : { harmless: 0, malicious: 0, suspicious: 0, undetected: 0 },
          lastChecked: Number(entry.lastChecked) || Date.now()
        };
        count++;
      }
      candidate.threatCache = cleanCache;
    } else {
      candidate.threatCache = {};
    }

    /* ---------- telemetry ---------- */
    if (candidate.events && !Array.isArray(candidate.events)) return { ok: false, error: 'invalid-events' };
    if (candidate.evidence && !Array.isArray(candidate.evidence)) return { ok: false, error: 'invalid-evidence' };
    if (candidate.chains && !Array.isArray(candidate.chains)) return { ok: false, error: 'invalid-chains' };
    if (candidate.graph && (typeof candidate.graph !== 'object' || Array.isArray(candidate.graph))) return { ok: false, error: 'invalid-graph' };
    candidate.events = Array.isArray(candidate.events) ? candidate.events.slice(0, 1000).map(v => CorsairSecurity.sanitizeObject(v)).filter(Boolean) : [];
    candidate.evidence = Array.isArray(candidate.evidence) ? candidate.evidence.slice(0, 500).map(v => CorsairSecurity.sanitizeObject(v)).filter(Boolean) : [];
    candidate.chains = Array.isArray(candidate.chains) ? candidate.chains.slice(0, 200).map(v => CorsairSecurity.sanitizeObject(v)).filter(Boolean) : [];
    candidate.graph = candidate.graph && typeof candidate.graph === 'object' ? CorsairSecurity.sanitizeObject(candidate.graph) : { version: 2, nodes: {}, edges: [] };

    return { ok: true, candidate };
  }

  function sanitizeDomainList(raw) {
    if (!Array.isArray(raw)) return [];
    const out = [];
    const seen = new Set();
    for (const d of raw) {
      if (out.length >= 500) break;
      const norm = CorsairSecurity.normalizeHostname(d);
      if (!norm || !CorsairSecurity.isValidHostname(norm)) continue;
      if (seen.has(norm)) continue;
      seen.add(norm);
      out.push(norm);
    }
    return out;
  }

  async function executeImportTransaction(payload) {
    const val = validateCandidate(payload);
    if (!val.ok) {
      return { ok: false, error: val.error, rolledBack: true, inconsistent: false };
    }
    const candidate = val.candidate;

    return CorsairStorage.withTransactionGateExclusive(async () => {
      const snapshot = {
        profiles: await CorsairStorage.getProfiles(),
        settings: await CorsairStorage.getSettings(),
        regression: await CorsairStorage.getRegressionCases(),
        registry: await CorsairStorage.getDnrRegistry(),
        events: await CorsairStorage.getEvents(1000),
        evidence: typeof CorsairEvidence !== 'undefined' ? await CorsairEvidence.recent(500) : [],
        graph: await CorsairStorage.getGraph(),
        chains: await CorsairStorage.getChains(200),
        customDomainScripts: await CorsairStorage.get('customDomainScripts', {}),
        userTrustedDomains: await CorsairStorage.get('userTrustedDomains', []),
        userBlockedDomains: await CorsairStorage.get('userBlockedDomains', []),
        threatCache: await CorsairStorage.get('threatCache', {})
      };
      const snapshotDnrRules = await CorsairDNR.listCorsairRules();
      const snapshotUserBlockRules = await CorsairDNR.listUserBlockRules();

      try {
        await CorsairStorage.commitImportConfig(candidate);

        // Restore user-level preferences (theme, language, onboarding
        // and tour flags). These live outside globalSettings so they
        // need to be written separately. We only write the keys that
        // the backup explicitly carried — a v10 backup will have
        // nulls here, in which case the user's current preferences
        // are preserved.
        try {
          const prefPatch = {};
          if (candidate.preferences) {
            if (candidate.preferences.theme) prefPatch.theme = candidate.preferences.theme;
            if (candidate.preferences.language) prefPatch.language = candidate.preferences.language;
            if (candidate.preferences.tourCompleted === true) prefPatch.tourCompleted = true;
            if (candidate.preferences.onboardingCompletedV1 === true) prefPatch.onboardingCompletedV1 = true;
          }
          if (Object.keys(prefPatch).length > 0) {
            await chrome.storage.local.set(prefPatch);
          }
        } catch {}

        const rebuildRes = await CorsairStorage.withMultiPartitionLock(['dnrRuleRegistry', 'domainProfiles'], async () => {
          return CorsairDNR.withDnrLock(() => CorsairDNR.rebuildFromProfilesUnlocked());
        });
        if (!rebuildRes.ok) {
          throw new Error('dnr-rebuild-failed: ' + (rebuildRes.error || 'unknown'));
        }

        // Re-sync the user blocklist session rules to match the imported list
        try {
          await CorsairDNR.syncUserBlocklist(candidate.userBlockedDomains);
        } catch {}

        // Refresh the in-memory trusted-domain cache used by threat-intel
        try {
          if (typeof CorsairThreatIntel !== 'undefined' && CorsairThreatIntel.refreshUserTrusted) {
            CorsairThreatIntel.refreshUserTrusted();
          }
        } catch {}

        if (payload.restoreTelemetry === true) {
          await CorsairStorage.replaceTelemetryUnlocked({
            events: candidate.events,
            evidence: candidate.evidence,
            graph: candidate.graph,
            chains: candidate.chains
          });
        }

        const importedProfiles = Object.keys(candidate.profiles).length;
        return {
          ok: true,
          importedProfiles,
          importedProfilesCount: importedProfiles,
          importedTelemetry: payload.restoreTelemetry === true,
          importedCustomScripts: Object.keys(candidate.customDomainScripts).length,
          importedUserTrusted: candidate.userTrustedDomains.length,
          importedUserBlocked: candidate.userBlockedDomains.length,
          importedThreatCache: Object.keys(candidate.threatCache).length
        };
      } catch (err) {
        let configRolledBack = false;
        let dnrRolledBack = false;

        try {
          await CorsairStorage.rollbackImportConfig(snapshot);
          await CorsairStorage.replaceTelemetryUnlocked({
            events: snapshot.events,
            evidence: snapshot.evidence,
            graph: snapshot.graph,
            chains: snapshot.chains
          });
          configRolledBack = true;
        } catch {}

        try {
          const curRules = await CorsairDNR.listCorsairRules();
          await chrome.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: curRules.map(r => r.id),
            addRules: snapshotDnrRules
          });
          // Restore user blocklist session rules too
          try {
            const curUserBlock = await CorsairDNR.listUserBlockRules();
            const keepUserBlockIds = new Set(snapshotUserBlockRules.map(r => r.id));
            const toRemoveUserBlock = curUserBlock
              .filter(r => !keepUserBlockIds.has(r.id))
              .map(r => r.id);
            if (toRemoveUserBlock.length > 0) {
              await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: toRemoveUserBlock });
            }
          } catch {}
          dnrRolledBack = true;
        } catch {}

        const completeRollback = configRolledBack && dnrRolledBack;
        return {
          ok: false,
          error: 'import-failed: ' + err.message,
          rolledBack: completeRollback,
          inconsistent: !completeRollback,
          recovery: completeRollback ? null : {
            configRolledBack,
            dnrRolledBack,
            snapshot
          }
        };
      }
    });
  }

  async function exportConfiguration() {
  return CorsairStorage.withTransactionGateShared(async () => {
    const [
      profiles, settings, regressionCases, dnrRegistry,
      events, graph, chains,
      customDomainScripts, userTrustedDomains, userBlockedDomains, threatCache
    ] = await Promise.all([
      CorsairStorage.getProfiles(),
      CorsairStorage.getSettings(),
      CorsairStorage.getRegressionCases(),
      CorsairStorage.getDnrRegistry(),
      CorsairStorage.getEvents(1000),
      CorsairStorage.getGraph(),
      CorsairStorage.getChains(200),
      CorsairStorage.get('customDomainScripts', {}),
      CorsairStorage.get('userTrustedDomains', []),
      CorsairStorage.get('userBlockedDomains', []),
      CorsairStorage.get('threatCache', {})
    ]);
    const evidence = typeof CorsairEvidence !== 'undefined' ? await CorsairEvidence.recent(500) : [];

    // Read user-level preferences from storage (they live outside
    // globalSettings so they aren't clobbered by settings patches).
    let prefs = { theme: null, language: null, tourCompleted: false, onboardingCompletedV1: false };
    try {
      const raw = await chrome.storage.local.get([
        'theme', 'language', 'tourCompleted', 'onboardingCompletedV1'
      ]);
      prefs = {
        theme: (raw.theme === 'light' || raw.theme === 'dark') ? raw.theme : null,
        language: typeof raw.language === 'string' && /^[a-z]{2}$/.test(raw.language) ? raw.language : null,
        tourCompleted: raw.tourCompleted === true,
        onboardingCompletedV1: raw.onboardingCompletedV1 === true
      };
    } catch {}

    // Strip the plaintext API key from settings if any legacy entry
    // still has it — the key must never leave the device in a backup.
    const safeSettings = { ...settings };
    delete safeSettings.vtApiKey;
    delete safeSettings.apiKey;

    // Build a human-readable summary so the user knows exactly what
    // they're about to download and can verify after restore.
    const summary = {
      profileCount: Object.keys(profiles || {}).length,
      trustedCount: Array.isArray(userTrustedDomains) ? userTrustedDomains.length : 0,
      blockedCount: Array.isArray(userBlockedDomains) ? userBlockedDomains.length : 0,
      customScriptsCount: Object.keys(customDomainScripts || {}).length,
      threatCacheCount: Object.keys(threatCache || {}).length,
      regressionCasesCount: Array.isArray(regressionCases) ? regressionCases.length : 0,
      eventCount: Array.isArray(events) ? events.length : 0,
      chainCount: Array.isArray(chains) ? chains.length : 0,
      graphNodeCount: graph && typeof graph === 'object' && graph.nodes ? Object.keys(graph.nodes).length : 0,
      evidenceCount: Array.isArray(evidence) ? evidence.length : 0,
      dnrRuleCount: dnrRegistry && dnrRegistry.rules ? Object.keys(dnrRegistry.rules).length : 0
    };

    // Snapshot the extension version so the recipient can tell which
    // build produced this file.
    let exportedByVersion = 'unknown';
    try { exportedByVersion = chrome.runtime.getManifest().version; } catch {}

    return {
      format: 'corsair-unbound',
      version: BACKUP_VERSION,
      exportedAt: Date.now(),
      exportedBy: {
        extension: 'Corsair Unbound',
        version: exportedByVersion
      },
      summary,
      profiles,
      settings: safeSettings,
      preferences: prefs,
      regressionCases,
      events,
      evidence,
      graph,
      chains,
      customDomainScripts,
      userTrustedDomains,
      userBlockedDomains,
      threatCache,
      dnrRegistryMeta: {
        rulesCount: Object.keys(dnrRegistry.rules || {}).length,
        nextId: dnrRegistry.nextId
      }
    };
  });
}

  return {
    validateCandidate,
    executeImportTransaction,
    exportConfiguration,
    BACKUP_VERSION
  };
})();

globalThis.CorsairMigration = CorsairMigration;
const CorsairMigration = (() => {
'use strict';

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
if (candidate.settings && (typeof candidate.settings !== 'object' || Array.isArray(candidate.settings))) {
return { ok: false, error: 'invalid-settings: settings must be an object' };
}
if (candidate.regressionCases && !Array.isArray(candidate.regressionCases)) {
return { ok: false, error: 'invalid-regression-cases: regressionCases must be an array' };
}
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
          return {
            ok: false,
            error: `prohibited-destination-block: cannot block self or subdomain ${normDst} for host ${normHost}`
          };
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

if (candidate.settings) {
  candidate.settings = CorsairSecurity.sanitizeObject(candidate.settings) || {};
} else {
  candidate.settings = {};
}

if (candidate.regressionCases) {
  candidate.regressionCases = (candidate.regressionCases || []).slice(0, 500).map(c => CorsairSecurity.sanitizeObject(c));
} else {
  candidate.regressionCases = [];
}

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
    chains: await CorsairStorage.getChains(200)
  };
  const snapshotDnrRules = await CorsairDNR.listCorsairRules();

  try {
    await CorsairStorage.commitImportConfig(candidate);

    const rebuildRes = await CorsairStorage.withMultiPartitionLock(['dnrRuleRegistry', 'domainProfiles'], async () => {
      return CorsairDNR.withDnrLock(() => CorsairDNR.rebuildFromProfilesUnlocked());
    });
    if (!rebuildRes.ok) {
      throw new Error('dnr-rebuild-failed: ' + (rebuildRes.error || 'unknown'));
    }

    if (payload.restoreTelemetry === true) await CorsairStorage.replaceTelemetryUnlocked({ events: candidate.events, evidence: candidate.evidence, graph: candidate.graph, chains: candidate.chains });
    return { ok: true, importedProfilesCount: Object.keys(candidate.profiles).length, importedTelemetry: payload.restoreTelemetry === true };
  } catch (err) {
    let configRolledBack = false;
    let dnrRolledBack = false;

    try {
      await CorsairStorage.rollbackImportConfig(snapshot);
      await CorsairStorage.replaceTelemetryUnlocked({ events: snapshot.events, evidence: snapshot.evidence, graph: snapshot.graph, chains: snapshot.chains });
      configRolledBack = true;
    } catch {}

    try {
      const curRules = await CorsairDNR.listCorsairRules();
      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: curRules.map(r => r.id),
        addRules: snapshotDnrRules
      });
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
const [profiles, settings, regressionCases, dnrRegistry, events, graph, chains] = await Promise.all([
CorsairStorage.getProfiles(),
CorsairStorage.getSettings(),
CorsairStorage.getRegressionCases(),
CorsairStorage.getDnrRegistry(),
CorsairStorage.getEvents(1000),
CorsairStorage.getGraph(),
CorsairStorage.getChains(200)
]);
const evidence = typeof CorsairEvidence !== 'undefined' ? await CorsairEvidence.recent(500) : [];
return {
format: 'corsair-unbound',
version: 9,
exportedAt: Date.now(),
profiles,
settings,
regressionCases,
events,
evidence,
graph,
chains,
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
exportConfiguration
};
})();

globalThis.CorsairMigration = CorsairMigration;
import './core/security.js';
import './core/storage.js';
import './core/dnr.js';
import './core/redirects.js';
import './core/intelligence.js';
import './core/verifier.js';
import './core/observation.js';
import './core/evidence.js';
import './core/migration.js';
import './core/tool-router.js';
import './core/replay.js';

let _startupReconcilePromise = null;

async function reconcileSessionState() {
try {
if (typeof chrome === 'undefined' || !chrome.tabs?.query || typeof CorsairObservation === 'undefined') return;
const tabs = await chrome.tabs.query({});
const activeTabIds = (Array.isArray(tabs) ? tabs : [])
.map(t => t.id)
.filter(id => Number.isInteger(id));
await CorsairObservation.reconcileSessionTabs(activeTabIds);
} catch {}
}

function classifySender(sender) {
if (!sender || typeof sender !== 'object' || Array.isArray(sender)) {
return 'UNTRUSTED';
}

const extId = (typeof chrome !== 'undefined' && chrome.runtime?.id) ? chrome.runtime.id : '';
const extBaseUrl = (typeof chrome !== 'undefined' && chrome.runtime?.getURL) ? chrome.runtime.getURL('') : '';
const senderUrl = typeof sender.url === 'string' ? sender.url : '';
const senderOrigin = typeof sender.origin === 'string' ? sender.origin : '';

if (extId && sender.id && sender.id !== extId) {
return 'UNTRUSTED';
}

const isExtensionUrl = Boolean(extBaseUrl && senderUrl.startsWith(extBaseUrl));
if (isExtensionUrl && (!extId || sender.id === extId)) {
return 'PRIVILEGED_INTERNAL';
}

const hasTabContext = Boolean(sender.tab && typeof sender.tab === 'object');
const hasExternalContext = Boolean(senderUrl || senderOrigin);
if (hasTabContext && hasExternalContext && (!extId || sender.id === extId)) {
return 'PAGE_OBSERVATION';
}

return 'UNTRUSTED';
}

globalThis.classifySender = classifySender;

async function performStartupDnrReconciliation() {
if (_startupReconcilePromise) return _startupReconcilePromise;

_startupReconcilePromise = (async () => {
try {
if (typeof CorsairStorage !== 'undefined' && typeof CorsairStorage.ensureReady === 'function') {
await CorsairStorage.ensureReady();
}
if (typeof CorsairDNR !== 'undefined' && typeof CorsairDNR.reconcileDnrRegistry === 'function') {
return await CorsairDNR.reconcileDnrRegistry();
}
} catch (err) {
return { ok: false, error: err.message, rulesPreserved: true };
} finally {
_startupReconcilePromise = null;
}
})();

return _startupReconcilePromise;
}

globalThis.performStartupDnrReconciliation = performStartupDnrReconciliation;
globalThis.reconcileSessionState = reconcileSessionState;

chrome.runtime.onStartup.addListener(() => {
performStartupDnrReconciliation().catch(() => {});
reconcileSessionState().catch(() => {});
});

chrome.runtime.onInstalled.addListener(() => {
performStartupDnrReconciliation().catch(() => {});
reconcileSessionState().catch(() => {});
});

chrome.runtime.onMessage.addListener((m, s, send) => {
(async () => {
try {
if (!m || typeof m !== 'object' || !m.type) {
send({ ok: false, error: 'invalid-message' });
return;
}
  const capability = classifySender(s);

  if (capability === 'PAGE_OBSERVATION') {
    if (m.type !== 'page-observation') {
      send({ ok: false, error: 'unauthorized-sender' });
      return;
    }
  } else if (capability !== 'PRIVILEGED_INTERNAL') {
    send({ ok: false, error: 'unauthorized-sender' });
    return;
  }

  switch (m.type) {
    case 'export-config': {
      const exportData = await CorsairMigration.exportConfiguration();
      send({ ok: true, data: exportData });
      break;
    }

    case 'import-config': {
      const importRes = await CorsairMigration.executeImportTransaction(m.candidate);
      send(importRes);
      break;
    }

    case 'get-profiles': {
      const profiles = await CorsairStorage.getProfiles();
      send({ ok: true, profiles });
      break;
    }

    case 'get-profile': {
      const host = CorsairSecurity.normalizeHostname(m.domain);
      const profile = await CorsairStorage.getProfile(host);
      send({ ok: true, profile });
      break;
    }

    case 'patch-profile': {
      const host = CorsairSecurity.normalizeHostname(m.domain);
      const safePatch = CorsairSecurity.sanitizeObject(m.patch) || {};
      const result = await CorsairDNR.patchProfileAtomic(host, current => {
        return {
          ...(current || CorsairSecurity.fortressProfile({})),
          ...safePatch
        };
      });
      send(result);
      break;
    }

    case 'remove-profile': {
      const host = CorsairSecurity.normalizeHostname(m.domain);
      const result = await CorsairStorage.withTransactionGateExclusive(async () => {
        const profileSnapshot = await CorsairStorage.getProfile(host);
        if (!profileSnapshot) {
          return { ok: true, removed: false };
        }
        const registrySnapshot = await CorsairStorage.getDnrRegistry();
        const browserRulesSnapshot = await CorsairDNR.listCorsairRules();
        const hostRulesSnapshot = browserRulesSnapshot.filter(r => r.condition?.initiatorDomains?.includes(host));

        const dnrRes = await CorsairStorage.withMultiPartitionLock(['dnrRuleRegistry', 'domainProfiles'], async () => {
          return CorsairDNR.withDnrLock(() => CorsairDNR.removeRulesForHostUnlocked(host));
        });
        if (!dnrRes.ok) {
          return {
            ok: false,
            error: 'dnr-removal-failed: ' + dnrRes.error,
            rolledBack: dnrRes.rolledBack !== false,
            inconsistent: Boolean(dnrRes.inconsistent)
          };
        }

        let profileRemoved = false;
        try {
          await CorsairStorage.removeProfileUnlocked(host);
          profileRemoved = true;
          await CorsairStorage.appendEventUnlocked({ type: 'domain_removed', domain: host, severity: 'info' });
          return { ok: true, removed: true };
        } catch (profileErr) {
          let dnrRestored = false;
          let registryRestored = false;
          let profileRestored = false;

          try {
            if (hostRulesSnapshot.length > 0) {
              await chrome.declarativeNetRequest.updateDynamicRules({ addRules: hostRulesSnapshot });
            }
            dnrRestored = true;
          } catch {}

          try {
            await CorsairStorage.saveDnrRegistryUnlocked(registrySnapshot);
            registryRestored = true;
          } catch {}

          if (profileRemoved) {
            try {
              await CorsairStorage.saveProfileUnlocked(host, profileSnapshot);
              profileRestored = true;
            } catch {}
          } else {
            profileRestored = true;
          }

          const completeRollback = dnrRestored && registryRestored && profileRestored;
          return {
            ok: false,
            error: 'profile-removal-failed: ' + profileErr.message,
            rolledBack: completeRollback,
            inconsistent: !completeRollback,
            recovery: { host, dnrRestored, registryRestored, profileRestored }
          };
        }
      });
      send(result);
      break;
    }

    case 'get-settings': {
      const settings = await CorsairStorage.getSettings();
      send({ ok: true, settings });
      break;
    }

    case 'patch-settings': {
      const settings = await CorsairStorage.patchSettings(m.patch);
      send({ ok: true, settings });
      break;
    }

    case 'get-events': {
      const events = await CorsairStorage.getEvents(m.limit || 200);
      send({ ok: true, events });
      break;
    }

    case 'clear-events': {
      await CorsairStorage.clearEvents();
      send({ ok: true });
      break;
    }

    case 'get-graph': {
      const graph = await CorsairStorage.getGraph();
      send({ ok: true, graph });
      break;
    }

    case 'clear-telemetry': {
      await CorsairStorage.clearTransientTelemetry();
      send({ ok: true });
      break;
    }

    case 'get-chains': {
      const chains = await CorsairStorage.getChains(m.limit || 200);
      send({ ok: true, chains });
      break;
    }

    case 'get-evidence': {
      const evidence = typeof CorsairEvidence !== 'undefined'
        ? (Number.isInteger(m.tabId) ? await CorsairEvidence.byTab(m.tabId, m.limit) : await CorsairEvidence.recent(m.limit))
        : [];
      send({ ok: true, evidence });
      break;
    }

    case 'get-agent-context': {
      const ctxData = await CorsairStorage.getAgentContext(m.params || {});
      send({ ok: true, context: ctxData });
      break;
    }

    case 'get-dnr-rules': {
      const rules = await CorsairDNR.listCorsairRules();
      const registry = await CorsairStorage.getDnrRegistry();
      send({ ok: true, rules, registry });
      break;
    }

    case 'get-diagnostics': {
      const [settings, profiles, dnrRules, dnrRegistry, graph, totalStorage] = await Promise.all([
        CorsairStorage.getSettings(),
        CorsairStorage.getProfiles(),
        CorsairDNR.listCorsairRules(),
        CorsairStorage.getDnrRegistry(),
        CorsairStorage.getGraph(),
        CorsairStorage.estimateTotalStorageBytes()
      ]);
      send({
        ok: true,
        diagnostics: {
          settings,
          profileCount: Object.keys(profiles || {}).length,
          dnrRuleCount: dnrRules.length,
          dnrRegistryNextId: dnrRegistry.nextId,
          graphNodeCount: Object.keys(graph.nodes || {}).length,
          graphEdgeCount: (graph.edges || []).length,
          totalStorageBytes: totalStorage.total,
          storageBreakdown: totalStorage.byKey
        }
      });
      break;
    }

    case 'tool-call': {
      const toolResult = await CorsairStorage.withTransactionGateShared(async () => {
        return CorsairTools.run(m.name, m.args || {});
      });
      send(toolResult);
      break;
    }

    case 'page-observation': {
      const obs = m.observation;
      if (!obs || typeof obs !== 'object' || !obs.url) {
        send({ ok: false, error: 'invalid-observation-payload' });
        break;
      }

      const pageHost = CorsairSecurity.extractHostname(obs.url);
      if (!pageHost || !CorsairSecurity.isValidHostname(pageHost)) {
        send({ ok: false, error: 'invalid-page-host' });
        break;
      }

      const rawHosts = Array.isArray(obs.externalHosts) ? obs.externalHosts : [];
      const seenInBatch = new Set();
      let ingestedCount = 0;
      const batchEdges = [];

      for (const raw of rawHosts.slice(0, 40)) {
        if (typeof raw !== 'string') continue;
        if (raw.length > 253) continue;
        if (/[\x00-\x1f\x7f\s]/.test(raw)) continue;

        const norm = CorsairSecurity.normalizeHostname(raw);
        if (!norm || !CorsairSecurity.isValidHostname(norm)) continue;
        if (norm === pageHost) continue;

        if (!seenInBatch.has(norm)) {
          seenInBatch.add(norm);
          ingestedCount++;
          batchEdges.push({
            nodes: [
              { id: `origin:${pageHost}`, kind: 'origin', host: pageHost },
              { id: `origin:${norm}`, kind: 'origin', host: norm }
            ],
            edge: {
              from: `origin:${pageHost}`,
              to: `origin:${norm}`,
              kind: 'requests'
            }
          });
        }
      }

      if (batchEdges.length > 0) {
        await CorsairStorage.addGraphEdgesBatch(batchEdges);
      } else {
        await CorsairStorage.addGraphNode({
          id: `origin:${pageHost}`,
          kind: 'origin',
          host: pageHost
        });
      }

      if (s.tab?.id) {
        await CorsairObservation.saveBatch(s.tab.id, (obs.externalHosts || []).map(h => ({ url: `https://${h}/` })));
      }

      send({ ok: true, externalHostsIngested: ingestedCount });
      break;
    }

    default: {
      send({ ok: false, error: 'unknown-message-type' });
      break;
    }
  }
} catch (err) {
  send({ ok: false, error: err.message });
}
})();
return true;
});

chrome.webNavigation.onBeforeNavigate.addListener(async details => {
if (details.frameId !== 0) return;
const tabId = details.tabId;
if (!Number.isInteger(tabId)) return;

try {
await CorsairRedirects.beginNavigation({
tabId,
frameId: details.frameId,
url: details.url,
initiator: details.initiator || null,
transitionType: details.transitionType || 'link'
});
} catch {}
});

chrome.webNavigation.onCommitted.addListener(async details => {
if (details.frameId !== 0) return;
const tabId = details.tabId;
if (!Number.isInteger(tabId)) return;

try {
let chain = await CorsairRedirects.reconcileCommittedHop({
tabId,
frameId: details.frameId,
url: details.url,
qualifiers: details.transitionQualifiers || []
});
if (!chain) {
chain = await CorsairRedirects.getTabChain(tabId);
}
if (!chain || !Array.isArray(chain.hops) || chain.hops.length === 0) return;
const currentUrl = CorsairSecurity.normalizeUrl(details.url);
const destinationHost = CorsairSecurity.extractHostname(currentUrl);
const sourceHost = CorsairSecurity.normalizeHostname(chain.sourceHost);

const profile = await CorsairStorage.getProfile(sourceHost);
if (!profile || profile.protected !== true || profile.mode !== 'fortress') return;

const recentEvents = await CorsairStorage.getEvents(50);
const intel = CorsairIntelligence.classifySignals({
  events: recentEvents,
  chain,
  destination: destinationHost,
  source: sourceHost,
  tabId
});

const assessment = CorsairVerifier.evaluateRedirectChain({
  profile,
  chain,
  intelligence: intel,
  destination: destinationHost,
  source: sourceHost
});

if (assessment.shouldContain) {
  await CorsairDNR.ensureNavigationBlock(sourceHost, destinationHost, assessment.reason);
  await CorsairStorage.appendEvent({
    type: 'navigation_contained',
    domain: sourceHost,
    destination: destinationHost,
    reason: assessment.reason,
    severity: 'high',
    tabId
  });
  await CorsairEvidence.add({
    kind: 'containment',
    origin: sourceHost,
    tabId,
    data: { destination: destinationHost, reason: assessment.reason, chainHops: chain.hops.length }
  });

  if (assessment.fallbackUrl && typeof chrome.tabs?.update === 'function') {
    chrome.tabs.update(tabId, { url: assessment.fallbackUrl }).catch(() => {});
  }

  if (typeof chrome.notifications?.create === 'function') {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: 'Corsair Unbound — Navigation Contained',
      message: `Suspicious navigation from ${sourceHost} to ${destinationHost} was intercepted.`
    }).catch(() => {});
  }
}
} catch {}
});

chrome.webNavigation.onErrorOccurred.addListener(async details => {
if (details.frameId !== 0) return;
const tabId = details.tabId;
if (!Number.isInteger(tabId)) return;

try {
const token = await CorsairRedirects.getGenerationToken(tabId);
const chain = await CorsairRedirects.getTabChain(tabId);

// A navigation error of net::ERR_BLOCKED_BY_CLIENT on a protected tab
// means our own DNR rule blocked the request outright (e.g. a direct
// click/typed URL to a blocked destination, with no redirect chain to
// analyze). Surface that as a real event + evidence entry so the
// block/allow decision made by DNR is actually observable, instead of
// silently discarding the navigation with no trace.
if (details.error === 'net::ERR_BLOCKED_BY_CLIENT' && chain) {
const sourceHost = CorsairSecurity.normalizeHostname(chain.sourceHost);
const destinationHost = CorsairSecurity.extractHostname(details.url);
if (sourceHost && destinationHost) {
const profile = await CorsairStorage.getProfile(sourceHost);
if (profile && profile.protected === true && profile.mode === 'fortress') {
await CorsairStorage.appendEvent({
type: 'navigation_blocked',
domain: sourceHost,
destination: destinationHost,
reason: 'dnr-rule-blocked',
severity: 'high',
tabId
});
await CorsairEvidence.add({
kind: 'navigation_blocked',
origin: sourceHost,
tabId,
data: { destination: destinationHost, error: details.error }
});
}
}
}

await CorsairRedirects.discardFailedNavigation({
tabId,
frameId: details.frameId,
url: details.url,
generationId: token
});
} catch {}
});

chrome.tabs.onRemoved.addListener(async tabId => {
try {
if (typeof CorsairObservation !== 'undefined' && typeof CorsairObservation.clear === 'function') {
await CorsairObservation.clear(tabId);
}
const token = await CorsairRedirects.getGenerationToken(tabId);
await CorsairRedirects.clearChainIfTabClosed(tabId, token);
} catch {}
});

chrome.downloads.onCreated.addListener(async downloadItem => {
try {
const rawUrl = downloadItem.finalUrl || downloadItem.url;
const downloadUrl = CorsairSecurity.normalizeUrl(rawUrl);
const downloadHost = CorsairSecurity.extractHostname(downloadUrl);
let originHost = '';
if (Number.isInteger(downloadItem.tabId) && downloadItem.tabId > 0) {
  try {
    const tab = await chrome.tabs.get(downloadItem.tabId);
    originHost = CorsairSecurity.extractHostname(tab?.url || '');
  } catch {}
}

if (!originHost && downloadHost) {
  originHost = downloadHost;
}

const profile = await CorsairStorage.getProfile(originHost);
if (!profile || profile.protected !== true || profile.mode !== 'fortress') return;

const ext = (downloadItem.filename || '').split('.').pop()?.toLowerCase() || '';
const dangerousExts = ['exe', 'msi', 'bat', 'cmd', 'ps1', 'vbs', 'scr', 'pif', 'hta'];

if (dangerousExts.includes(ext) && typeof chrome.downloads?.cancel === 'function') {
  await chrome.downloads.cancel(downloadItem.id);
  await CorsairStorage.appendEvent({
    type: 'download_blocked',
    domain: originHost,
    destination: downloadHost,
    filename: downloadItem.filename,
    severity: 'high'
  });
  await CorsairEvidence.add({
    kind: 'download_cancelled',
    origin: originHost,
    data: { downloadHost, filename: downloadItem.filename, extension: ext }
  });
  if (typeof chrome.notifications?.create === 'function') {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: 'Corsair Unbound — Executable Download Blocked',
      message: `Blocked hazardous download (${ext}) from ${originHost}.`
    }).catch(() => {});
  }
}
} catch {}
});

chrome.tabs.onCreated.addListener(async tab => {
try {
if (!Number.isInteger(tab.openerTabId)) return;
const opener = await chrome.tabs.get(tab.openerTabId).catch(() => null);
if (!opener?.url) return;

const originHost = CorsairSecurity.extractHostname(opener.url);
const profile = await CorsairStorage.getProfile(originHost);
if (!profile || profile.protected !== true || profile.mode !== 'fortress') return;

const blocked = Array.isArray(profile.blockedDestinationDomains) ? profile.blockedDestinationDomains : [];
if (blocked.length === 0 || !Number.isInteger(tab.id)) return;

// A freshly created tab frequently has no url yet (it is still on
// about:blank while the destination loads); pendingUrl carries the
// real target in that case. Give it one short retry if both are empty.
let destUrl = tab.pendingUrl || tab.url || '';
if (!destUrl) {
await new Promise(resolve => setTimeout(resolve, 150));
const fresh = await chrome.tabs.get(tab.id).catch(() => null);
destUrl = fresh?.pendingUrl || fresh?.url || '';
}
const destHost = CorsairSecurity.extractHostname(destUrl);
if (!destHost) return;

const isDestBlocked = blocked.some(d => destHost === d || CorsairSecurity.sameOrSubdomain(destHost, d));
if (!isDestBlocked) return;

let isPopupWindow = false;
if (Number.isInteger(tab.windowId) && typeof chrome.windows?.get === 'function') {
const win = await chrome.windows.get(tab.windowId).catch(() => null);
isPopupWindow = win?.type === 'popup';
}

try {
await chrome.tabs.remove(tab.id);
} catch {}

const eventType = isPopupWindow ? 'popup_blocked' : 'new_tab_blocked';
await CorsairStorage.appendEvent({
type: eventType,
domain: originHost,
destination: destHost,
severity: 'medium',
tabId: tab.id
});
await CorsairEvidence.add({
kind: eventType,
origin: originHost,
tabId: tab.id,
data: { destination: destHost, isPopupWindow }
});
} catch {}
});
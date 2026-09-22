importScripts('core/security.js','core/observation.js','core/evidence.js','core/storage.js','core/graph.js','core/redirects.js','core/verifier.js','core/dnr.js','core/replay.js','core/tool-router.js','core/intelligence.js');

const RESOLVER_HOSTS=new Set(['ouo.io','ouo.press','ouo.today']);
const EXEC_EXTS=new Set(['.exe','.scr','.msi','.com','.bat','.cmd','.ps1','.vbs','.js','.jar','.hta']);

async function notify(title,message){const s=await CorsairStorage.getSettings(); if(!s.notifications)return; try{await chrome.notifications.create({type:'basic',iconUrl:'icon128.png',title,message,priority:0});}catch{}}
async function profileFor(host){return CorsairStorage.getProfile(host);}
async function protectDomain(url){
  const host=CorsairSecurity.extractHostname(url);
  if(!CorsairSecurity.isValidHostname(host)) return {ok:false,error:'invalid-domain'};
  const existing=await profileFor(host); const profile=CorsairSecurity.fortressProfile(existing||{});
  const saved=await CorsairStorage.upsertProfile(host,profile);
  await CorsairStorage.appendEvent({type:'domain_protected',domain:host,severity:'info',mode:'fortress',details:'All domain protections enabled immediately.'});
  return {ok:true,domain:host,profile:saved};
}
function executable(url){try{const p=new URL(url).pathname.toLowerCase();return [...EXEC_EXTS].some(x=>p.endsWith(x));}catch{return false;}}

chrome.downloads.onCreated.addListener(async item=>{
  try{const host=CorsairSecurity.extractHostname(item.referrer||''); const p=await profileFor(host); if(!p?.downloadGuard)return; const url=item.finalUrl||item.url||''; if(p.blockExecutables && executable(url)){await chrome.downloads.cancel(item.id); await CorsairStorage.appendEvent({type:'download_blocked',domain:host,url,filename:item.filename||'',severity:'high',reason:'executable download from protected domain'}); await notify('Corsair blocked a download',`${host}: executable file`);}}
  catch(e){console.debug('download guard',e);}
});

chrome.windows.onCreated.addListener(async win=>{if(win.type!=='popup')return; try{const tabs=await chrome.tabs.query({windowId:win.id});const tab=tabs[0];if(!tab?.openerTabId)return;const opener=await chrome.tabs.get(tab.openerTabId);const host=CorsairSecurity.extractHostname(opener.url||'');const p=await profileFor(host);if(!p?.popupGuard)return;await chrome.windows.remove(win.id);await CorsairStorage.appendEvent({type:'popup_blocked',domain:host,url:tab.pendingUrl||tab.url||'',severity:'high',reason:'popup opened by protected domain'});}catch(e){console.debug('popup guard',e);}});

chrome.tabs.onCreated.addListener(async tab=>{if(!tab.openerTabId)return;try{const opener=await chrome.tabs.get(tab.openerTabId);const host=CorsairSecurity.extractHostname(opener.url||'');const p=await profileFor(host);if(!p?.newTabGuard)return;await chrome.tabs.remove(tab.id);await CorsairStorage.appendEvent({type:'new_tab_blocked',domain:host,url:tab.pendingUrl||tab.url||'',severity:'high',reason:'new tab opened by protected domain'});}catch(e){}});

chrome.webNavigation.onBeforeNavigate.addListener(async details=>{
  try{
    const chain=await CorsairRedirects.beginNavigation(details);
    const sourceHost=CorsairSecurity.extractHostname(details.initiator||chain.sourceHost||'');
    const targetHost=CorsairSecurity.extractHostname(details.url);
    const nav=CorsairSecurity.classifyNavigation(details,chain.hops.length);
    if(sourceHost&&targetHost) await CorsairGraph.recordNavigation({sourceUrl:details.initiator||`https://${sourceHost}/`,targetUrl:details.url,tabId:details.tabId,type:nav.redirect?'redirect':'navigation',details});
    const profile=await profileFor(sourceHost);
    if(profile?.eventLogging){
      const risk=CorsairSecurity.riskScore({external:CorsairSecurity.isExternal(sourceHost,targetHost),redirect:nav.redirect,auto:nav.auto,chainLength:chain.hops.length,unknownDestination:true});
      await CorsairStorage.appendEvent({type:'navigation_observed',domain:sourceHost,destination:targetHost,url:details.url,severity:risk>=70?'high':risk>=40?'medium':'low',risk,details:{tabId:details.tabId,frameId:details.frameId,documentId:details.documentId||null,transitionType:nav.transitionType,qualifiers:nav.qualifiers}});
    }
    if(await CorsairStorage.getSettings().then(x=>x.verificationEnabled)){
      await CorsairEvidence.add({kind:'navigation',tabId:details.tabId,documentId:details.documentId||null,origin:targetHost,data:{url:details.url,initiator:details.initiator||'',transitionType:nav.transitionType,qualifiers:nav.qualifiers,chainLength:chain.hops.length}});
    }
  }catch(e){console.debug('navigation observer',e);}
},{url:[{urlMatches:'^https?://.*'}]});

chrome.webNavigation.onCommitted.addListener(async details=>{
  if(details.frameId!==0)return;
  try{
    const host=CorsairSecurity.extractHostname(details.url);
    const profile=await profileFor(host);
    if(profile){profile.lastSeen=Date.now();await CorsairStorage.upsertProfile(host,profile);}
    const chain=await CorsairRedirects.getChain(details.tabId);
    if(chain){
      await CorsairStorage.saveChain({...chain, tabId:details.tabId, committedUrl:details.url});
      await CorsairEvidence.add({kind:'redirect-chain',tabId:details.tabId,documentId:details.documentId||null,origin:host,data:{sourceHost:chain.sourceHost,hops:chain.hops,committedUrl:details.url},tags:['redirect','chain']});
      const sourceProfile=await profileFor(chain.sourceHost);
      const verdict=CorsairVerifier.evaluateRedirectChain(chain,sourceProfile||{});
      const recentEvents=await CorsairStorage.getEvents(120);
      const assessment=CorsairIntelligence.classifySignals({events:recentEvents.filter(e=>e.domain===chain.sourceHost||e.destination===host),chain,destination:host,source:chain.sourceHost,profile:sourceProfile||{}});
      await CorsairEvidence.add({kind:'redirect-verification',tabId:details.tabId,documentId:details.documentId||null,origin:host,data:{...verdict,behavior:assessment}});
      await CorsairStorage.appendEvent({type:'behavior_assessed',domain:chain.sourceHost,destination:host,severity:assessment.risk>=75?'high':assessment.risk>=45?'medium':'low',risk:assessment.risk,reason:assessment.reasons.join(', '),details:assessment.metrics});
      const contain = CorsairIntelligence.shouldContain({assessment,profile:sourceProfile||{},destination:host,source:chain.sourceHost,userInitiated:chain.hops.some(h=>String(h.transitionType||'').includes('typed'))});
      if(sourceProfile?.dnrAutoBlock && sourceProfile.clickbaitGuard && contain && chain.sourceHost && host && chain.sourceHost!==host){
        const dnrResult=await CorsairDNR.ensureNavigationBlock(chain.sourceHost,host,'behavior-correlated suspicious redirect');
        await CorsairStorage.appendEvent({type:'dnr_rule_added',domain:chain.sourceHost,destination:host,severity:'high',reason:'verified suspicious redirect',ruleId:dnrResult.rule?.id||null,risk:verdict.risk});
        const profileNow=await CorsairStorage.getProfile(chain.sourceHost);
        if(profileNow){
          const list=Array.from(new Set([...(profileNow.blockedDestinationDomains||[]),host])).slice(-1000);
          profileNow.blockedDestinationDomains=list;
          await CorsairStorage.upsertProfile(chain.sourceHost,profileNow);
        }
      }
      if(sourceProfile?.autoContainRedirects && sourceProfile.clickbaitGuard && contain){
        const lastSafe=chain.lastSafeUrl||`https://${chain.sourceHost}/`;
        if(lastSafe!==details.url){
          await chrome.tabs.update(details.tabId,{url:lastSafe});
          await CorsairStorage.appendEvent({type:'redirect_contained',domain:chain.sourceHost,destination:host,severity:'high',reason:verdict.reasons.join(', '),risk:verdict.risk,hopCount:chain.hops.length,restored:lastSafe});
          await notify('Corsair contained a suspicious redirect',`${chain.sourceHost} → ${host}`);
        }
      }
    }
  }catch(e){console.debug('commit handler',e);}
});

chrome.webNavigation.onErrorOccurred.addListener(async details=>{
  if(details.frameId!==0)return;
  try{await CorsairEvidence.add({kind:'navigation-error',tabId:details.tabId,documentId:details.documentId||null,origin:CorsairSecurity.extractHostname(details.url),data:{url:details.url,error:details.error}});await CorsairStorage.appendEvent({type:'navigation_error',domain:CorsairSecurity.extractHostname(details.url),severity:'medium',reason:details.error,url:details.url});}catch{}
},{url:[{urlMatches:'^https?://.*'}]});

chrome.tabs.onRemoved.addListener(tabId=>CorsairRedirects.clearChain(tabId).catch(()=>{}));

chrome.runtime.onInstalled.addListener(async()=>{try{await CorsairDNR.rebuildFromProfiles();}catch(e){console.debug('DNR rebuild',e);}});
chrome.runtime.onStartup.addListener(async()=>{try{await CorsairDNR.rebuildFromProfiles();}catch(e){console.debug('DNR startup rebuild',e);}});

chrome.runtime.onMessage.addListener((m,s,send)=>{(async()=>{
  switch(m?.type){
    case 'protect-current-domain':send(await protectDomain(m.url||s?.tab?.url||''));break;
    case 'get-profile':send({profile:await profileFor(m.domain)});break;
    case 'get-profiles':send({profiles:await CorsairStorage.getProfiles()});break;
    case 'remove-profile':await CorsairStorage.removeProfile(m.domain);await CorsairStorage.appendEvent({type:'domain_removed',domain:CorsairSecurity.normalizeHostname(m.domain),severity:'info'});send({ok:true});break;
    case 'patch-profile':{const existing=await profileFor(m.domain);if(!existing)throw new Error('profile-not-found');const p=CorsairSecurity.normalizeProfile({...existing,...(m.patch||{})});if(m.patch?.mode==='fortress')Object.assign(p,CorsairSecurity.fortressProfile(p));send({ok:true,profile:await CorsairStorage.upsertProfile(m.domain,p)});break;}
    case 'get-events':send({events:await CorsairStorage.getEvents(m.limit||200)});break;
    case 'assess-domain-risk': { const domain=CorsairSecurity.normalizeHostname(m.domain||''); const profile=await profileFor(domain); const events=await CorsairStorage.getEvents(500); const chains=(await CorsairStorage.getChains(200)).filter(c=>c.sourceHost===domain); const assessment=CorsairIntelligence.classifySignals({events:events.filter(e=>e.domain===domain),chain:chains[0]||null,source:domain,destination:chains[0]?.committedUrl?CorsairSecurity.extractHostname(chains[0].committedUrl):'',profile:profile||{}}); send({assessment}); break; }
    case 'clear-events':await CorsairStorage.clearEvents();send({ok:true});break;
    case 'get-graph':send({graph:await CorsairStorage.getGraph()});break;
    case 'get-chains':send({chains:await CorsairStorage.getChains(m.limit||200)});break;
    case 'get-settings':send({settings:await CorsairStorage.getSettings()});break;
    case 'patch-settings':send({settings:await CorsairStorage.patchSettings(m.patch||{})});break;
    case 'export-config': {
      const [settings,profiles,regressionCases,events,evidence,graph,chains] = await Promise.all([
        CorsairStorage.getSettings(), CorsairStorage.getProfiles(), CorsairReplay.getCases(),
        CorsairStorage.getEvents(3000), CorsairEvidence.recent(3000), CorsairStorage.getGraph(), CorsairStorage.getChains(1500)
      ]);
      const dnrRules=await CorsairDNR.listCorsairRules();
      send({ok:true,export:{format:'corsair-unbound',version:1,appVersion:'5.0.0',exportedAt:new Date().toISOString(),settings,profiles,regressionCases,events,evidence,graph,chains,dnrRules,meta:{note:'Local-first configuration export. Runtime caches/events are included for diagnostics; importing profiles/settings is the primary supported restore path.'}}});
      break;
    }
    case 'import-config': {
      const data=m.data;
      if(!data || data.format!=='corsair-unbound' || !data.profiles || typeof data.profiles!=='object') throw new Error('invalid-corsair-export');
      const cleaned={};
      for(const [host,profile] of Object.entries(data.profiles)){
        const h=CorsairSecurity.normalizeHostname(host);
        if(!CorsairSecurity.isValidHostname(h)) continue;
        cleaned[h]=CorsairSecurity.normalizeProfile(profile);
      }
      await CorsairStorage.saveProfiles(cleaned);
      if(data.settings && typeof data.settings==='object') await CorsairStorage.patchSettings(data.settings);
      if(Array.isArray(data.regressionCases)) await chrome.storage.local.set({regressionCases:data.regressionCases.slice(0,500)});
      if(m.restoreTelemetry){
        if(Array.isArray(data.events)) await chrome.storage.local.set({activityLog:data.events.slice(0,3000)});
        if(Array.isArray(data.evidence)) await chrome.storage.local.set({evidenceStore:data.evidence.slice(0,3000)});
        if(data.graph && typeof data.graph==='object') await chrome.storage.local.set({siteGraph:data.graph});
        if(Array.isArray(data.chains)) await chrome.storage.local.set({redirectChains:data.chains.slice(0,1500)});
      }
      const rebuild=await CorsairDNR.rebuildFromProfiles();
      await CorsairStorage.appendEvent({type:'config_imported',severity:'info',details:`Imported ${Object.keys(cleaned).length} domain profiles.`,restoreTelemetry:Boolean(m.restoreTelemetry)});
      send({ok:true,importedProfiles:Object.keys(cleaned).length,rebuild,restoreTelemetry:Boolean(m.restoreTelemetry)});
      break;
    }
    case 'clear-telemetry':await CorsairStorage.clearTransientTelemetry();send({ok:true});break;
    case 'tool-call':send(await CorsairTools.run(m.name,m.args||{}));break;
    case 'run-regressions':send({results:await CorsairReplay.runAll()});break;
    case 'get-regressions':send({cases:await CorsairReplay.getCases()});break;
    case 'capture-regression':send({case:await CorsairReplay.capture(m.name,m.input,m.expected)});break;
    case 'list-dnr-rules':send({rules:await CorsairDNR.listCorsairRules()});break;
    case 'page-observation':{
      const obs=m.observation||{}; const host=CorsairSecurity.extractHostname(obs.url||s?.tab?.url||''); const profile=await profileFor(host); const settings=await CorsairStorage.getSettings();
      if(!settings.observationEnabled||profile?.observePages===false){send({ok:true,enabled:false});break;}
      const obsForVerify=CorsairVerifier.verifyPageObservation(obs);
      const networkRecords=(Array.isArray(obs.network) ? obs.network : []).slice(0,120).map(CorsairObservation.normalizeRecord);
      await CorsairObservation.saveBatch(s?.tab?.id ?? null, networkRecords);
      if(networkRecords.length){
        await CorsairEvidence.add({kind:'network-observation',tabId:s?.tab?.id??null,documentId:obs.documentId||null,origin:host,data:{records:networkRecords,summary:{count:networkRecords.length,hosts:[...new Set(networkRecords.map(x=>x.host).filter(Boolean))].slice(0,100)}},tags:['network','observation']});
        for(const rec of networkRecords.slice(0,80)){
          if(rec.host) await CorsairGraph.recordNetworkRequest({sourceHost:host,record:rec,tabId:s?.tab?.id??null,documentId:obs.documentId||null});
        }
      }
      await CorsairEvidence.add({kind:'page-observation',tabId:s?.tab?.id??null,documentId:obs.documentId||null,origin:host,data:obs,tags:['page','observation']});
      await CorsairGraph.recordPageObservation(obs);
      for(const h of (obs.externalHosts||[]).slice(0,40)) await CorsairGraph.recordAsset({host,url:`https://${h}/`,type:'external-host',tabId:s?.tab?.id??null,documentId:obs.documentId||null});
      if(obsForVerify.status!=='clean-observation') await CorsairStorage.appendEvent({type:'page_observation_finding',domain:host,severity:obsForVerify.findings.some(f=>f.severity==='high')?'high':'medium',findings:obsForVerify.findings,summary:obsForVerify.summary});
      send({ok:true,enabled:true,verification:obsForVerify}); break;
    }
    case 'get-evidence':send({evidence:await CorsairEvidence.recent(m.limit||200)});break;
    case 'get-tab-evidence':send({evidence:await CorsairEvidence.byTab(m.tabId,m.limit||200)});break;
    case 'get-network-observation':send({observation:await CorsairObservation.recent(m.tabId,m.limit||200)});break;
    case 'clear-network-observation':await CorsairObservation.clear(m.tabId);send({ok:true});break;
    case 'clear-evidence':await CorsairEvidence.clear();send({ok:true});break;
    case 'get-agent-context':send({context:await CorsairStorage.getAgentContext({tabId:m.tabId,domain:m.domain,limit:m.limit||120})});break;
    default:send({ok:false,error:'unknown-message'});
  }
})().catch(e=>send({ok:false,error:String(e?.message||e)})); return true;});

chrome.runtime.onInstalled.addListener(async({reason})=>{if(reason==='install'){await CorsairStorage.patchSettings({resolverEnabled:true,theme:'dark',observationEnabled:true,verificationEnabled:true});await CorsairStorage.appendEvent({type:'corsair_installed',severity:'info',details:'Corsair Unbound v5 initialized: enforcement + observation + evidence + verification + agent tools enabled.'});}});

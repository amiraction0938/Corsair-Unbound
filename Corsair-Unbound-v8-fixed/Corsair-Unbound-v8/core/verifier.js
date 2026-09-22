const CorsairVerifier = (() => {
  function evaluateRedirectChain(chain, profile = {}) {
    const hops = Array.isArray(chain?.hops) ? chain.hops : [];
    const maxHops = Math.max(1, Math.min(32, Number(profile.maxRedirectHops) || 8));
    const externalHops = hops.filter(h => h.external === true).length;
    const redirectHops = hops.filter(h => h.redirect === true).length;
    const autoHops = hops.filter(h => h.auto === true).length;
    const distinctHosts = new Set(hops.map(h => h.host).filter(Boolean));
    const reasons = [];
    if (hops.length > maxHops) reasons.push(`hop-count>${maxHops}`);
    if (externalHops >= 2) reasons.push('multiple-external-hops');
    if (redirectHops >= 2) reasons.push('redirect-chain');
    if (autoHops >= 1) reasons.push('automatic-navigation');
    if (distinctHosts.size >= 4) reasons.push('many-distinct-hosts');
    const risk = Math.min(100,(externalHops>=1?30:0)+(redirectHops>=1?25:0)+(autoHops>=1?15:0)+(hops.length>=3?15:0)+(hops.length>maxHops?30:0)+(distinctHosts.size>=4?15:0));
    return { verdict:risk>=60?'suspicious':reasons.length?'review':'normal',confirmedBy:'deterministic-redirect-verifier',risk,reasons,metrics:{hops:hops.length,externalHops,redirectHops,autoHops,distinctHosts:distinctHosts.size,maxHops} };
  }
  function verifyPageObservation(observation) {
    const findings=[]; const forms=Number(observation?.forms||0); const insecure=Number(observation?.insecureForms||0); const scripts=Number(observation?.externalScripts||0); const resources=Number(observation?.resourceCount||0); const apiCount=Array.isArray(observation?.apiCandidates)?observation.apiCandidates.length:0; const routeCount=Array.isArray(observation?.routes)?observation.routes.length:0;
    if(insecure>0)findings.push({id:'client.insecure-form-action',severity:'high',confidence:0.98,evidence:{insecureForms:insecure}});
    if(scripts>=40)findings.push({id:'client.high-third-party-script-count',severity:'medium',confidence:0.82,evidence:{externalScripts:scripts}});
    if(resources>=250)findings.push({id:'client.high-resource-count',severity:'low',confidence:0.8,evidence:{resourceCount:resources}});
    if(apiCount>=50)findings.push({id:'client.high-api-candidate-count',severity:'low',confidence:0.72,evidence:{apiCandidates:apiCount}});
    return {status:findings.length?'attention':'clean-observation',findings,summary:{forms,insecureForms:insecure,externalScripts:scripts,resourceCount:resources,apiCandidates:apiCount,routes:routeCount}};
  }
  function correlateEvidence({finding,evidence=[]}) {
    const kinds=new Set(evidence.map(x=>x?.kind).filter(Boolean)); const required=Array.isArray(finding?.requiredEvidenceKinds)?finding.requiredEvidenceKinds:[]; const missing=required.filter(k=>!kinds.has(k));
    return {verdict:missing.length?'unverified':'supported',confidence:missing.length?0.35:Math.min(0.99,0.55+Math.min(0.4,evidence.length*0.08)),missingEvidence:missing,supportedKinds:[...kinds]};
  }
  function verifyFinding(finding,evidence=[]) { return correlateEvidence({finding,evidence}); }
  return {evaluateRedirectChain,verifyPageObservation,verifyFinding,correlateEvidence};
})();
globalThis.CorsairVerifier=CorsairVerifier;

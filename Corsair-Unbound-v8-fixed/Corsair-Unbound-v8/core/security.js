const DEFAULT_PROFILE = Object.freeze({
  version: 4,
  protected: true,
  mode: 'fortress',
  redirectGuard: true,
  redirectChainGuard: true,
  popupGuard: true,
  newTabGuard: true,
  downloadGuard: true,
  navigationGuard: true,
  frameGuard: true,
  safeResolver: true,
  clickbaitGuard: true,
  eventLogging: true,
  blockedDestinationDomains: [],
  dnrAutoBlock: true,
  autoContainRedirects: true,
  blockExecutables: true,
  maxRedirectHops: 8,
  observePages: true,
  verifyObservations: true,
  createdAt: 0,
  updatedAt: 0,
  lastSeen: 0
});

function clone(value) { return JSON.parse(JSON.stringify(value)); }
function normalizeHostname(hostname) {
  let host = String(hostname || '').trim().toLowerCase();
  host = host.replace(/^[.]+|[.]+$/g, '');
  if (host.startsWith('www.')) host = host.slice(4);
  return host;
}
function isValidHostname(hostname) {
  const host = normalizeHostname(hostname);
  if (!host || host.length > 253 || host.includes('..')) return false;
  if (host === 'localhost' || host.endsWith('.localhost')) return false;
  return /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(host);
}
function sameOrSubdomain(host, parent) {
  const a = normalizeHostname(host), b = normalizeHostname(parent);
  return Boolean(a && b && (a === b || a.endsWith(`.${b}`)));
}
function extractHostname(value) {
  try { return normalizeHostname(new URL(value).hostname); } catch { return ''; }
}
function normalizeUrl(value) {
  try {
    const u = new URL(value);
    if (!['http:','https:'].includes(u.protocol)) return '';
    if (u.username || u.password) return '';
    u.hash = '';
    return u.href;
  } catch { return ''; }
}
function isHttpUrl(value) { return Boolean(normalizeUrl(value)); }
function isExternal(sourceHost, targetHost) {
  return Boolean(sourceHost && targetHost && !sameOrSubdomain(targetHost, sourceHost));
}
function fortressProfile(existing={}) {
  const now=Date.now();
  return {
    ...clone(DEFAULT_PROFILE),
    ...clone(existing),
    ...clone({
      protected:true, mode:'fortress',
      redirectGuard:true, redirectChainGuard:true, popupGuard:true,
      newTabGuard:true, downloadGuard:true, navigationGuard:true,
      frameGuard:true, safeResolver:true, clickbaitGuard:true,
      eventLogging:true, autoContainRedirects:true, blockExecutables:true, dnrAutoBlock:true
    }),
    createdAt:Number(existing.createdAt)||now,
    updatedAt:now,
    lastSeen:Number(existing.lastSeen)||now
  };
}
function normalizeProfile(existing={}) {
  const now=Date.now();
  const p={...clone(DEFAULT_PROFILE),...clone(existing)};
  p.version=5; p.updatedAt=now; p.createdAt=Number(p.createdAt)||now; p.lastSeen=Number(p.lastSeen)||now;
  p.protected=p.protected!==false;
  p.maxRedirectHops=Math.max(1,Math.min(32,Number(p.maxRedirectHops)||8));
  return p;
}
function classifyNavigation(details, chainLength=0) {
  const q=Array.isArray(details?.transitionQualifiers)?details.transitionQualifiers:[];
  const t=String(details?.transitionType||'');
  const auto = t==='auto_toplevel' || q.includes('client_redirect') || q.includes('server_redirect');
  const redirect = q.includes('client_redirect') || q.includes('server_redirect');
  return { auto, redirect, transitionType:t, qualifiers:q, chainLength };
}
function classifyResource(url) { try { const u=new URL(url); return u.protocol==='https:'?'secure-web':'insecure-web'; } catch { return 'unknown'; } }
function riskScore(input={}) {
  let score=0;
  if(input.external) score+=30;
  if(input.redirect) score+=25;
  if(input.auto) score+=15;
  if(input.newTab) score+=20;
  if(input.popup) score+=25;
  if(input.chainLength>=3) score+=15;
  if(input.chainLength>=6) score+=20;
  if(input.unknownDestination) score+=15;
  if(input.executableDownload) score+=45;
  return Math.min(100,score);
}

globalThis.CorsairSecurity={clone,normalizeHostname,isValidHostname,sameOrSubdomain,extractHostname,normalizeUrl,isHttpUrl,isExternal,fortressProfile,normalizeProfile,classifyNavigation,classifyResource,riskScore,DEFAULT_PROFILE};

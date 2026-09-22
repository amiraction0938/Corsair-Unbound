function chainKey(tabId){return `tab:${tabId}`;}
async function getSession(){const d=await chrome.storage.session.get('redirectSession');return d.redirectSession||{};}
async function setSession(s){await chrome.storage.session.set({redirectSession:s});}
async function beginNavigation(details){
  const s=await getSession();const key=chainKey(details.tabId);const current=s[key]||{hops:[],lastSafeUrl:'',sourceHost:'',documentId:null};
  const target=CorsairSecurity.normalizeUrl(details.url);if(!target)return current;
  const sourceHost=CorsairSecurity.extractHostname(details.initiator||current.sourceHost||'');
  const targetHost=CorsairSecurity.extractHostname(target);
  const nav=CorsairSecurity.classifyNavigation(details,current.hops.length);
  const hop={url:target,host:targetHost,timestamp:Date.now(),external:CorsairSecurity.isExternal(sourceHost,targetHost),initiator:sourceHost,documentId:details.documentId||null,...nav};
  current.hops=[...current.hops,hop].slice(-32);current.sourceHost=current.sourceHost||sourceHost;current.documentId=details.documentId||current.documentId;
  if(!nav.redirect&&!nav.auto)current.lastSafeUrl=target;
  s[key]=current;await setSession(s);return current;
}
async function getChain(tabId){const s=await getSession();return s[chainKey(tabId)]||null;}
async function clearChain(tabId){const s=await getSession();delete s[chainKey(tabId)];await setSession(s);}
globalThis.CorsairRedirects={beginNavigation,getChain,clearChain};

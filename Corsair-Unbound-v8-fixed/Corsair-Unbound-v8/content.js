(() => {
  const RESOLVER_HOSTS=new Set(['ouo.io','ouo.press','ouo.today']);
  const shim={isHttp(v){try{const u=new URL(v);return u.protocol==='http:'||u.protocol==='https:';}catch{return false;}}};
  const send=(message)=>new Promise(resolve=>{try{chrome.runtime.sendMessage(message,resolve);}catch{resolve(null);}});

  function safeUrl(value){try{const u=new URL(value);return ['http:','https:'].includes(u.protocol)?u.href:'';}catch{return '';}}
  function collectObservation(){
    const forms=[...document.forms];
    const insecureForms=forms.filter(f=>{const action=safeUrl(f.action||location.href);return action&&location.protocol==='https:'&&action.startsWith('http:');});
    const scripts=[...document.scripts].filter(s=>{try{return s.src&&new URL(s.src,location.href).origin!==location.origin;}catch{return false;}});
    const anchors=[...document.querySelectorAll('a[href]')].slice(0,700).map(a=>safeUrl(a.href)).filter(Boolean);
    const externalLinks=[...new Set(anchors.filter(u=>{try{return new URL(u).origin!==location.origin;}catch{return false;}}))].slice(0,250);
    const resources=performance.getEntriesByType('resource').slice(0,700).map(x=>({url:safeUrl(x.name),duration:Number(x.duration||0),transferSize:Number(x.transferSize||0),initiatorType:String(x.initiatorType||'other')})).filter(x=>x.url);
    const hostSet=new Set();for(const x of [...resources.map(r=>r.url),...externalLinks]){try{hostSet.add(new URL(x).hostname);}catch{}}
    const routes=[...new Set([...anchors.map(u=>{try{return new URL(u).pathname}catch{return ''}}),...forms.map(f=>{try{return new URL(f.action||location.href).pathname}catch{return ''}})].filter(Boolean))].slice(0,200);
    const apiCandidates=[...new Set(resources.map(r=>r.url).filter(u=>/\/(api|graphql|rest|v\d+)(\/|\?|$)/i.test(u)||/graphql/i.test(u)))].slice(0,200);
    const network=resources.slice(0,160).map(r=>({type:'resource',url:r.url,resourceType:r.initiatorType,duration:r.duration,transferSize:r.transferSize,phase:'performance'}));
    return {
      url:location.href,path:location.pathname,title:document.title,documentId:null,
      forms:forms.length,insecureForms:insecureForms.length,externalScripts:scripts.length,
      externalHosts:[...hostSet].slice(0,250),resourceCount:resources.length,externalLinks:externalLinks.slice(0,120),
      canonical:document.querySelector('link[rel="canonical"]')?.href||'',routes,apiCandidates,network,timestamp:Date.now()
    };
  }
  async function observe(){
    try{const r=await send({type:'page-observation',observation:collectObservation()});if(r?.enabled===false)return;}catch{}
  }
  const host=location.hostname.toLowerCase().replace(/^www\./,'');
  chrome.storage.local.get(['globalSettings','ouoBypassEnabled']).then(data=>{
    const enabled=data.globalSettings?.resolverEnabled===true||data.ouoBypassEnabled===true;
    if(enabled&&RESOLVER_HOSTS.has(host)){
      const encoded=new URLSearchParams(location.search).get('s');if(encoded){let dest='';try{dest=decodeURIComponent(encoded);}catch{}if(shim.isHttp(dest)){const u=new URL(dest);if(!u.username&&!u.password)location.replace(u.href);}}
    }
  }).catch(()=>{});
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',observe,{once:true});else observe();
})();

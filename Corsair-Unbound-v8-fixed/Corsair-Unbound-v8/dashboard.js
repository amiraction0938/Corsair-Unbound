function send(m){return new Promise(resolve=>{try{chrome.runtime.sendMessage(m,resolve);}catch(e){resolve({ok:false,error:String(e?.message||e)});}});}
let profiles={},events=[],evidence=[],network=[],settings={};
const $=id=>document.getElementById(id);
const safeOn=(id,event,handler)=>{const el=$(id);if(el)el.addEventListener(event,handler);};

function downloadJSON(filename,data){
  const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});
  const url=URL.createObjectURL(blob);
  const a=document.createElement('a'); a.href=url; a.download=filename; a.style.display='none';
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
}
function showStatus(text,ok=true){const el=$('backupStatus');if(el){el.textContent=text;el.className=ok?'status-ok':'status-error';}}
function humanTime(ts){const n=Number(ts);return new Date(Number.isFinite(n)?n:Date.now()).toLocaleString();}
function boolLabel(v){return v?'ON':'OFF';}

function renderProfiles(){
  const search=$('domainSearch'), box=$('profiles'); if(!box)return;
  const q=(search?.value||'').trim().toLowerCase(); box.innerHTML='';
  const entries=Object.entries(profiles).filter(([d])=>!q||d.includes(q)).sort(([a],[b])=>a.localeCompare(b));
  if(!entries.length){box.innerHTML='<div class="empty">No protected domains yet. Use “Protect current domain” from the extension popup.</div>';return;}
  for(const [d,p] of entries){
    const row=document.createElement('div');row.className='profile';
    const left=document.createElement('div');
    const title=document.createElement('strong');title.textContent=d;
    const sub=document.createElement('div');sub.className='muted';sub.textContent=`${String(p.mode||'custom').toUpperCase()} • max hops ${p.maxRedirectHops||8} • created ${p.createdAt?humanTime(p.createdAt):'—'}`;
    left.append(title,sub);
    const right=document.createElement('div');right.className='badge';
    const active=Object.entries(p).filter(([k,v])=>v===true).map(([k])=>k.replace(/Guard$/,''));
    right.textContent=active.length?active.join(' • '):'PROFILE';
    row.append(left,right);box.appendChild(row);
  }
}

function renderSettings(){
  const box=$('settingsForm'); if(!box)return; box.innerHTML='';
  const bools=[
    ['resolverEnabled','Safe Redirect Resolver'],
    ['notifications','Notifications'],
    ['logEvents','Event Logging'],
    ['observationEnabled','Page Observation'],
    ['verificationEnabled','Verification'],
    ['enforceSuspiciousRedirects','Suspicious Redirect Enforcement'],
    ['dnrAutoBlock','Automatic DNR Blocking'],
    ['strictUnknownRedirectContainment','Strict Unknown Redirect Containment']
  ];
  for(const [key,label] of bools){
    const l=document.createElement('label');l.className='setting';
    const input=document.createElement('input');input.type='checkbox';input.dataset.key=key;input.checked=settings[key]===true;
    const span=document.createElement('span');span.textContent=label;l.append(input,span);box.appendChild(l);
  }
  const wrap=document.createElement('label');wrap.className='setting';
  const span=document.createElement('span');span.textContent='Global max redirect hops';
  const num=document.createElement('input');num.type='number';num.min='1';num.max='32';num.step='1';num.value=settings.maxRedirectHops||8;num.dataset.key='maxRedirectHops';
  wrap.append(span,num);box.appendChild(wrap);
}
function readSettingsForm(){
  const patch={};document.querySelectorAll('#settingsForm [data-key]').forEach(el=>{
    patch[el.dataset.key]=el.type==='checkbox'?el.checked:Math.max(1,Math.min(32,Number(el.value)||8));
  });return patch;
}

function renderEvents(){
  const box=$('activity'); if(!box)return; box.innerHTML='';
  if(!events.length){box.innerHTML='<div class="empty">No activity yet. Visit a normal web page after enabling observation.</div>';return;}
  for(const e of events.slice(0,300)){
    const row=document.createElement('div');row.className='event';
    const main=document.createElement('div');main.className='event-main';
    const t=document.createElement('div');t.className='event-type';t.textContent=e.type||'event';
    const m=document.createElement('div');m.className='event-meta';
    m.textContent=`${humanTime(e.timestamp)} • ${e.domain||e.source||''}${e.destination?` → ${e.destination}`:''}${e.reason?` • ${e.reason}`:''}${Number.isFinite(e.risk)?` • risk ${e.risk}`:''}`;
    main.append(t,m);
    const sev=document.createElement('div');sev.className=e.severity||'low';sev.textContent=String(e.severity||'low').toUpperCase();
    row.append(main,sev);box.appendChild(row);
  }
}

function renderEvidence(){
  const box=$('evidence');if(!box)return;box.innerHTML='';
  if(!evidence.length){box.innerHTML='<div class="empty">No evidence stored yet. A page observation is created after a normal web page finishes loading.</div>';return;}
  for(const e of evidence.slice(0,300)){
    const row=document.createElement('div');row.className='event';
    const main=document.createElement('div');main.className='event-main';
    const t=document.createElement('div');t.className='event-type';t.textContent=e.kind||'observation';
    const m=document.createElement('div');m.className='event-meta';m.textContent=`${humanTime(e.timestamp)} • ${e.origin||''} • tab ${e.tabId??'-'} • ${(e.tags||[]).join(', ')}`;
    main.append(t,m);row.append(main);box.appendChild(row);
  }
}

function renderNetwork(){
  const box=$('network');if(!box)return;box.innerHTML='';
  if(!network.length){box.innerHTML='<div class="empty">No network observation for this tab. Enter a tab ID and reload that page.</div>';return;}
  for(const r of network.slice(0,120)){
    const row=document.createElement('div');row.className='event';
    const main=document.createElement('div');main.className='event-main';
    const t=document.createElement('div');t.className='event-type';t.textContent=r.resourceType||r.type||'resource';
    const m=document.createElement('div');m.className='event-meta';m.textContent=`${humanTime(r.timestamp)} • ${r.host||''} • ${r.method||''} • ${r.status??''} • ${r.url||''}`;
    main.append(t,m);row.append(main);box.appendChild(row);
  }
}

function behaviorDomains(){
  const set=new Set(Object.keys(profiles));
  for(const e of events){if(e.domain)set.add(e.domain);if(e.source)set.add(e.source);if(e.destination)set.add(e.destination);}
  return [...set].filter(Boolean).sort().slice(0,60);
}
function renderRisk(){
  const box=$('riskBoard');if(!box)return;box.innerHTML='';
  const domains=behaviorDomains();
  if(!domains.length){box.innerHTML='<div class="empty">No behavior data yet. Browse a site and refresh this dashboard.</div>';return;}
  for(const d of domains){
    const row=document.createElement('div');row.className='event';
    const main=document.createElement('div');main.className='event-main';
    const t=document.createElement('div');t.className='event-type';t.textContent=d;
    const m=document.createElement('div');m.className='event-meta';m.textContent='Calculating…';main.append(t,m);row.append(main);box.appendChild(row);
    send({type:'assess-domain-risk',domain:d}).then(r=>{
      if(r?.assessment){const a=r.assessment;m.textContent=`${String(a.verdict||'unknown').toUpperCase()} • risk ${a.risk}/100 • confidence ${Math.round((a.confidence||0)*100)}%${a.reasons?.length?' • '+a.reasons.join(', '):''}`;}
      else m.textContent='No assessment available.';
    });
  }
}

async function loadCurrentTabId(){
  const input=$('networkTabId'); if(!input)return;
  try{const tabs=await chrome.tabs.query({active:true,currentWindow:true});const id=tabs?.[0]?.id;if(Number.isInteger(id))input.value=String(id);}catch{}
}

async function refresh(){
  await loadCurrentTabId();
  const tabId=Number($('networkTabId')?.value);
  const requests=[
    send({type:'get-profiles'}),send({type:'get-events',limit:300}),send({type:'get-graph'}),send({type:'get-evidence',limit:300}),send({type:'get-settings'})
  ];
  requests.push(Number.isInteger(tabId)&&tabId>=0?send({type:'get-network-observation',tabId,limit:200}):Promise.resolve({observation:[]}));
  const [pr,ev,gr,ee,st,no]=await Promise.all(requests);
  profiles=pr?.profiles||{};events=ev?.events||[];evidence=ee?.evidence||[];settings=st?.settings||{};network=no?.observation||[];
  const nodes=Object.keys(gr?.graph?.nodes||{}).length;
  const set=(id,v)=>{const el=$(id);if(el)el.textContent=String(v);};
  set('protected',Object.keys(profiles).length);set('events',events.length);set('blocked',events.filter(e=>['blocked','contained'].some(x=>String(e.type).includes(x))).length);set('nodes',nodes);
  renderProfiles();renderSettings();renderEvents();renderEvidence();renderNetwork();renderRisk();
  const c=await send({type:'get-agent-context',tabId:Number.isInteger(tabId)&&tabId>=0?tabId:null,limit:120});
  const contextText=JSON.stringify(c?.context||{},null,2);if($('agentContext'))$('agentContext').textContent=contextText;
}

async function doExport(){
  try{const r=await send({type:'export-config'});if(!r?.ok)throw new Error(r?.error||'Export failed');downloadJSON(`corsair-unbound-${new Date().toISOString().replace(/[:.]/g,'-')}.corsair.json`,r.export);showStatus('Backup exported successfully.');}
  catch(e){showStatus(`Export failed: ${e.message}`,false);}
}
function openImport(){const f=$('configFile');if(f)f.value='';if(f)f.click();}
async function handleImport(file){
  try{
    if(!file)return;
    const text=await file.text();const data=JSON.parse(text);
    if(data?.format!=='corsair-unbound')throw new Error('This is not a Corsair Unbound backup.');
    const restoreTelemetry=$('restoreTelemetry')?.checked===true;
    const r=await send({type:'import-config',data,restoreTelemetry});
    if(!r?.ok)throw new Error(r?.error||'Import failed');
    showStatus(`Imported ${r.importedProfiles} domain profiles${restoreTelemetry?' + telemetry':''}.`);await refresh();
  }catch(e){showStatus(`Import failed: ${e.message}`,false);}
}

safeOn('refresh','click',refresh);
safeOn('domainSearch','input',renderProfiles);
safeOn('clearEvents','click',async()=>{await send({type:'clear-events'});await refresh();});
safeOn('clearTelemetry','click',async()=>{await send({type:'clear-telemetry'});await refresh();});
safeOn('clearEvidence','click',async()=>{await send({type:'clear-evidence'});await refresh();});
safeOn('networkTabId','change',refresh);safeOn('refreshNetwork','click',refresh);
safeOn('clearNetwork','click',async()=>{const tabId=Number($('networkTabId')?.value);if(Number.isInteger(tabId)&&tabId>=0)await send({type:'clear-network-observation',tabId});await refresh();});
safeOn('copyContext','click',async()=>{const c=await send({type:'get-agent-context',tabId:Number($('networkTabId')?.value),limit:120});const text=JSON.stringify(c?.context||{},null,2);if($('agentContext'))$('agentContext').textContent=text;try{await navigator.clipboard?.writeText(text);}catch{}});
safeOn('saveSettings','click',async()=>{const r=await send({type:'patch-settings',patch:readSettingsForm()});if(r?.settings){settings=r.settings;showStatus('Global settings saved.');}else showStatus(r?.error||'Could not save settings.',false);});
safeOn('exportConfig','click',doExport);safeOn('exportConfig2','click',doExport);safeOn('importConfig','click',openImport);safeOn('importConfig2','click',openImport);safeOn('configFile','change',e=>handleImport(e.target.files?.[0]));

refresh();

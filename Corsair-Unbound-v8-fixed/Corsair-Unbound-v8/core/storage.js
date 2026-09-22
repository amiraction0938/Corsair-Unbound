const KEYS={profiles:'domainProfiles',settings:'globalSettings',events:'activityLog',graph:'siteGraph',chains:'redirectChains'};
const MAX_EVENTS=3000, MAX_NODES=8000, MAX_CHAINS=1500;
const DEFAULT_SETTINGS={resolverEnabled:true,theme:'dark',notifications:true,logEvents:true,maxRedirectHops:8,strictUnknownRedirectContainment:true,observationEnabled:true,verificationEnabled:true,enforceSuspiciousRedirects:true,dnrAutoBlock:true};
async function get(key,fallback){const d=await chrome.storage.local.get(key);return d[key]??fallback;}
async function set(key,value){await chrome.storage.local.set({[key]:value});return value;}
async function getProfiles(){return get(KEYS.profiles,{});} async function saveProfiles(v){return set(KEYS.profiles,v);}
async function getProfile(host){const h=CorsairSecurity.normalizeHostname(host);const p=await getProfiles();return p[h]||null;}
async function upsertProfile(host,profile){const h=CorsairSecurity.normalizeHostname(host);if(!CorsairSecurity.isValidHostname(h))throw new Error('invalid-domain');const p=await getProfiles();p[h]=CorsairSecurity.normalizeProfile(profile);await saveProfiles(p);return p[h];}
async function removeProfile(host){const h=CorsairSecurity.normalizeHostname(host);const p=await getProfiles();delete p[h];await saveProfiles(p);return true;}
async function getSettings(){return {...DEFAULT_SETTINGS,...(await get(KEYS.settings,{}))};}
async function patchSettings(patch){const next={...(await getSettings()),...patch};return set(KEYS.settings,next);}
async function appendEvent(event){const s=await getSettings();if(!s.logEvents)return null;const arr=await get(KEYS.events,[]);const rec={id:crypto.randomUUID(),timestamp:Date.now(),...event};await set(KEYS.events,[rec,...(Array.isArray(arr)?arr:[])].slice(0,MAX_EVENTS));return rec;}
async function getEvents(limit=200){const arr=await get(KEYS.events,[]);return Array.isArray(arr)?arr.slice(0,Math.max(1,Math.min(MAX_EVENTS,Number(limit)||200))):[];}
async function clearEvents(){return set(KEYS.events,[]);}
async function getGraph(){return get(KEYS.graph,{version:2,nodes:{},edges:[]});}
async function addGraphNode(node){const graph=await getGraph();const now=Date.now();if(!node?.id)return graph;const old=graph.nodes[node.id]||{};graph.nodes[node.id]={...old,...node,lastSeen:now,seenCount:Number(old.seenCount||0)+1};const ids=Object.keys(graph.nodes);if(ids.length>MAX_NODES){for(const id of ids.sort((a,b)=>(graph.nodes[a].lastSeen||0)-(graph.nodes[b].lastSeen||0)).slice(0,ids.length-MAX_NODES))delete graph.nodes[id];}await set(KEYS.graph,graph);return graph;}
async function addGraphEdge(edge){const graph=await getGraph();const now=Date.now();for(const n of edge.nodes||[])await addGraphNode(n);const g=await getGraph();if(edge.edge){g.edges.push({...edge.edge,timestamp:now});if(g.edges.length>MAX_NODES)g.edges=g.edges.slice(-MAX_NODES);await set(KEYS.graph,g);}return g;}
async function saveChain(chain){const arr=await get(KEYS.chains,[]);const item={id:crypto.randomUUID(),timestamp:Date.now(),...chain};await set(KEYS.chains,[item,...arr].slice(0,MAX_CHAINS));return item;}
async function getChains(limit=200){const arr=await get(KEYS.chains,[]);return arr.slice(0,Math.max(1,Math.min(MAX_CHAINS,Number(limit)||200)));}
async function clearTransientTelemetry(){await set(KEYS.graph,{version:2,nodes:{},edges:[]});await set(KEYS.chains,[]);await chrome.storage.local.set({evidenceStore:[]});}
async function getAgentContext({tabId,domain,limit=120}={}){const d=CorsairSecurity.normalizeHostname(domain);const events=(await getEvents(1000)).filter(e=>!d||e.domain===d||e.destination===d).slice(0,limit);const evidence=await CorsairEvidence.recent(limit);const graph=await getGraph();const nodes=Object.values(graph.nodes||{}).filter(n=>!d||n.host===d);const profile=d?await getProfile(d):null;const network=Number.isInteger(tabId)?await CorsairObservation.recent(tabId,Math.min(limit,200)):[];return {version:'6.0',generatedAt:Date.now(),scope:{tabId:Number.isInteger(tabId)?tabId:null,domain:d||null},profile,summary:{eventCount:events.length,evidenceCount:evidence.length,graphNodeCount:nodes.length,networkObservationCount:network.length},events,evidence,network,graph:{nodes:Object.fromEntries(nodes.map(n=>[n.id,n])),edges:(graph.edges||[]).filter(e=>nodes.some(n=>n.id===e.from)||nodes.some(n=>n.id===e.to)).slice(-400)}};}
async function getRegressionCases(){const d=await chrome.storage.local.get('regressionCases');return Array.isArray(d.regressionCases)?d.regressionCases:[];}

globalThis.CorsairStorage={KEYS,getRegressionCases,getProfiles,saveProfiles,getProfile,upsertProfile,removeProfile,getSettings,patchSettings,appendEvent,getEvents,clearEvents,addGraphNode,addGraphEdge,getGraph,saveChain,getChains,clearTransientTelemetry,getAgentContext};

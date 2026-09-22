async function upsertOrigin(host, extra = {}) {
  const h = CorsairSecurity.normalizeHostname(host);
  if (!CorsairSecurity.isValidHostname(h)) return null;
  return CorsairStorage.addGraphNode({ id: `origin:${h}`, kind: 'origin', host: h, ...extra });
}
async function recordNavigation({ sourceUrl, targetUrl, tabId, type='navigation', details={} }) {
  const sourceHost = CorsairSecurity.extractHostname(sourceUrl);
  const targetHost = CorsairSecurity.extractHostname(targetUrl);
  if (!targetHost) return;
  const nodes = [];
  if (sourceHost) nodes.push({ id:`origin:${sourceHost}`, kind:'origin', host:sourceHost });
  nodes.push({ id:`origin:${targetHost}`, kind:'origin', host:targetHost });
  const edge = { from: sourceHost ? `origin:${sourceHost}` : `tab:${tabId}`, to: `origin:${targetHost}`, kind:type, tabId, transitionType:details.transitionType || '', qualifiers:details.transitionQualifiers || [], documentId: details.documentId || null };
  await CorsairStorage.addGraphEdge({ nodes, edge });
}
async function recordPageObservation(obs) {
  const host = CorsairSecurity.extractHostname(obs.url || '');
  if (!host) return;
  await upsertOrigin(host, { title: String(obs.title || '').slice(0, 300), lastDocumentId: obs.documentId || null });
  await CorsairStorage.addGraphNode({ id:`page:${obs.documentId || `${host}:${obs.path || '/'}`}`, kind:'page', host, url:obs.url || '', path:obs.path || '/', title:String(obs.title || '').slice(0, 300), resourceCount:Number(obs.resourceCount || 0), formCount:Number(obs.forms || 0), scriptCount:Number(obs.externalScripts || 0), routeCount:Array.isArray(obs.routes)?obs.routes.length:0, apiCount:Array.isArray(obs.apiCandidates)?obs.apiCandidates.length:0, lastSeen:Date.now() });
  for(const route of (Array.isArray(obs.routes)?obs.routes:[]).slice(0,120)) await CorsairStorage.addGraphNode({id:`route:${host}:${route}`,kind:'route',host,path:route});
  for(const api of (Array.isArray(obs.apiCandidates)?obs.apiCandidates:[]).slice(0,120)) await CorsairStorage.addGraphNode({id:`api:${host}:${api}`,kind:'api',host,url:api});
}
async function recordAsset({host, url, type, tabId, documentId}) {
  const assetHost = CorsairSecurity.extractHostname(url);
  if (!assetHost) return;
  await CorsairStorage.addGraphEdge({nodes:[{id:`origin:${host}`,kind:'origin',host},{id:`asset:${assetHost}:${type}`,kind:'asset-host',host:assetHost}],edge:{from:`origin:${host}`,to:`asset:${assetHost}:${type}`,kind:'loads',tabId,documentId}});
}
async function recordNetworkRequest({sourceHost,record,tabId,documentId}) {
  const targetHost=record.host;
  if(!sourceHost||!targetHost)return;
  const reqId=`request:${record.id}`;
  await CorsairStorage.addGraphNode({id:reqId,kind:'request',host:targetHost,url:record.url,method:record.method,resourceType:record.resourceType,status:record.status,timestamp:record.timestamp});
  await CorsairStorage.addGraphEdge({nodes:[{id:`origin:${sourceHost}`,kind:'origin',host:sourceHost},{id:reqId,kind:'request',host:targetHost}],edge:{from:`origin:${sourceHost}`,to:reqId,kind:'requests',tabId,documentId,resourceType:record.resourceType}});
  if(targetHost!==sourceHost) await CorsairStorage.addGraphNode({id:`origin:${targetHost}`,kind:'origin',host:targetHost});
}
globalThis.CorsairGraph={recordNavigation,recordPageObservation,recordAsset,upsertOrigin,recordNetworkRequest};

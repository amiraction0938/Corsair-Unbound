const fs=require('fs');const path=require('path');
for(const f of ['../core/observation.js','../core/graph.js','../core/verifier.js','../background.js','../content.js']){const text=fs.readFileSync(path.join(__dirname,f),'utf8');if(!text.trim())throw new Error('empty '+f);} 
const manifest=JSON.parse(fs.readFileSync(path.join(__dirname,'../manifest.json'),'utf8'));
if(manifest.version!=='8.1.0')throw new Error('unexpected version');
if(!manifest.permissions.includes('declarativeNetRequest'))throw new Error('DNR permission missing');
if(!fs.readFileSync(path.join(__dirname,'../background.js'),'utf8').includes('page-observation'))throw new Error('network observation handler missing');
if(!fs.readFileSync(path.join(__dirname,'../core/graph.js'),'utf8').includes('recordNetworkRequest'))throw new Error('network graph missing');
console.log('Corsair v7 smoke tests: PASS');

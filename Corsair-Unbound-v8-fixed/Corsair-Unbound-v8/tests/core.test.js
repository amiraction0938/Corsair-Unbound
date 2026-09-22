const vm=require('vm'),fs=require('fs'),assert=require('assert');
function load(file,extra={}){const ctx=vm.createContext({...extra,crypto:{randomUUID:()=> 'test-id'}});vm.runInContext(fs.readFileSync(file,'utf8'),ctx,{filename:file});return ctx;}
const sec=load(require('path').join(__dirname,'..','core','security.js')).CorsairSecurity;
assert.equal(sec.isExternal('example.com','evil.com'),true);
assert.equal(sec.isExternal('example.com','a.example.com'),false);
assert.equal(sec.normalizeHostname('WWW.Example.COM'),'example.com');
const f=sec.fortressProfile({createdAt:1});assert.equal(f.mode,'fortress');assert.equal(f.redirectGuard,true);assert.equal(f.safeResolver,true);assert.equal(f.blockExecutables,true);
const ver=load(require('path').join(__dirname,'..','core','verifier.js')).CorsairVerifier;
const out=ver.evaluateRedirectChain({hops:[{external:true,redirect:true,auto:true},{external:true,redirect:true,auto:true},{external:true,redirect:true,auto:true}]},{maxRedirectHops:8});
assert.ok(['suspicious','review'].includes(out.verdict));
console.log('Corsair core tests: PASS');

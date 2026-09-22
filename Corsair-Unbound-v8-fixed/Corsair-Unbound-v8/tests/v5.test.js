const vm=require('vm'),fs=require('fs'),path=require('path'),assert=require('assert');
function load(file,extra={}){const ctx=vm.createContext({...extra,crypto:{randomUUID:()=> 'test-id'},chrome:{}});vm.runInContext(fs.readFileSync(file,'utf8'),ctx,{filename:file});return ctx;}
const sec=load(path.join(__dirname,'..','core','security.js')).CorsairSecurity;
assert.equal(sec.isExternal('example.com','evil.com'),true);
const fortress=sec.fortressProfile({});
assert.equal(fortress.mode,'fortress');
assert.equal(fortress.downloadGuard,true);
assert.equal(fortress.dnrAutoBlock,true);
const ver=load(path.join(__dirname,'..','core','verifier.js')).CorsairVerifier;
const out=ver.evaluateRedirectChain({hops:[{external:true,redirect:true,auto:true},{external:true,redirect:true,auto:true},{external:true,redirect:true,auto:true}]},{maxRedirectHops:8});
assert.ok(out.risk>=60);
const dnr=load(path.join(__dirname,'..','core','dnr.js'),{CorsairSecurity:sec}).CorsairDNR;
const rule=dnr.makeBlockRule({source:'example.com',destination:'evil.com',reason:'test'});
assert.equal(rule.condition.initiatorDomains[0],'example.com');
assert.equal(rule.condition.requestDomains[0],'evil.com');
assert.ok(!Object.prototype.hasOwnProperty.call(rule,'_meta'));
const replay=load(path.join(__dirname,'..','core','replay.js'),{chrome:{storage:{local:{get:async()=>({regressionCases:[]}),set:async()=>{}}}}}).CorsairReplay;
assert.ok(replay.run && replay.runAll);
console.log('Corsair v5 tests: PASS');

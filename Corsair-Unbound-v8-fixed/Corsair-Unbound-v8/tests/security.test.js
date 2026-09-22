const fs=require('fs'),vm=require('vm');
const path=require('path');
const src=fs.readFileSync(path.join(__dirname,'../core/security.js'),'utf8');
const ctx={globalThis:{},URL};vm.createContext(ctx);vm.runInContext(src,ctx);const s=ctx.globalThis.CorsairSecurity;
function ok(v,msg){if(!v)throw new Error(msg)}
ok(s.normalizeHostname('WWW.Example.COM')==='example.com','normalize');
ok(s.sameOrSubdomain('a.example.com','example.com'),'subdomain');
ok(!s.sameOrSubdomain('evil-example.com','example.com'),'suffix false positive');
ok(!s.isValidHostname('localhost'),'localhost');
ok(s.isHttpUrl('https://example.com/a'),'https');
ok(!s.isHttpUrl('javascript:alert(1)'),'scheme');
const p=s.fortressProfile({}); ok(Object.values(p).filter(v=>v===true).length>=10,'fortress defaults');
console.log('Corsair security tests: PASS');

const assert=require('node:assert/strict'),fs=require('node:fs');
function verify(evidence){
 assert.equal(evidence.referenceSha256,'901619844a281628f9dc9eb17ff978cc3498cf05b9548cea15808c706c42c581');
 const normalize=scan=>(scan.findings||[]).filter(f=>f.evidence?.sca?.component?.detection==='filecontent').map(f=>{const c=f.evidence.sca.component;return {ruleId:f.ruleId,name:c.name,version:c.version,locations:[...new Set(c.locations.map(url=>new URL(url).pathname))].sort()};}).sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b)));
 for(const account of ['a','b','anonymous']){const own=evidence.owned.find(x=>x.account===account),ref=evidence.reference.find(x=>x.account===account);assert.ok(own&&ref);assert.deepEqual(normalize(own.scan),normalize(ref.scan),'Body findings differ for '+account);assert.equal(own.bodyRequests.length,2);assert.ok(own.bodyRequests.every(x=>x.account===account));if(account==='a')assert.ok(normalize(own.scan).length>0);else assert.equal(normalize(own.scan).length,0);if(account!=='anonymous')assert.equal(own.scan.scaBodyCoverage.analyzed,2);else assert.ok(own.scan.scaBodyCoverage.gaps>=2);}
 return {matchedAccounts:3,authenticatedContentPositive:true,cleanAndAnonymousControls:true,ownedRefetches:0};
}
module.exports={verify};
if(require.main===module)console.log(JSON.stringify(verify(JSON.parse(fs.readFileSync(process.argv[2]||'tools/security/evidence/sca-authenticated-browser.json','utf8')))));

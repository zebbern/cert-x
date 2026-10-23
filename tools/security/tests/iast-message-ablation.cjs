// Bounded diagnostic: revert exactly one existing propagation fix per temporary
// owned extension. The pinned reference, production tree and parity oracle stay unchanged.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {execFileSync}=require('node:child_process'),{pathToFileURL}=require('node:url');
const {prepare}=require('../prepare-reference.cjs');
const root=path.resolve(__dirname,'../../..'),directory=fs.mkdtempSync(path.join(os.tmpdir(),'cert-x-iast-ablation-'));
const sourceFile='security/ptk/content/iast.js',sha=value=>crypto.createHash('sha256').update(value).digest('hex');
let reference;const outcomes=[];
async function main(){
 const {parse}=await import(pathToFileURL(path.join(root,'security/ptk/background/sast/acorn/acorn.mjs')).href);
 const locate=(source,name)=>{let found;const visit=node=>{if(!node||typeof node!=='object')return;if(node.type==='FunctionDeclaration'&&node.id?.name===name)found=node;for(const value of Object.values(node)){if(Array.isArray(value))value.forEach(visit);else if(value&&typeof value==='object')visit(value);}};visit(parse(source,{ecmaVersion:'latest'}));assert.ok(found,name);return {start:found.start,end:found.end,text:source.slice(found.start,found.end)};};
 reference=prepare();const production=fs.readFileSync(path.join(root,sourceFile),'utf8'),upstream=fs.readFileSync(path.join(reference.extensionPath,'ptk/content/iast.js'),'utf8');
 const hashBefore=sha(production);
 for(const [variant,name]of [['ablation-no-boxing','getTaintEntry'],['ablation-no-reentrancy','propagateTaint']]){
  const checkout=path.join(directory,variant);fs.mkdirSync(checkout);
  for(const entry of ['_locales','assets','background','chunks','content-scripts','icon','media','pages','providers','security','manifest.json'])fs.cpSync(path.join(root,entry),path.join(checkout,entry),{recursive:true,errorOnExist:true});
  const selected=locate(production,name),replacement=locate(upstream,name),modified=production.slice(0,selected.start)+replacement.text+production.slice(selected.end);
  fs.writeFileSync(path.join(checkout,sourceFile),modified);assert.equal(sha(fs.readFileSync(path.join(root,sourceFile))),hashBefore);
  let output='',status=0;try{output=execFileSync(process.execPath,[path.join(__dirname,'collection-parity.browser.cjs')],{cwd:root,encoding:'utf8',timeout:180000,windowsHide:true,env:{...process.env,COLLECTION_CASES:'message',COLLECTION_VARIANT:variant,COLLECTION_OWNED_EXTENSION:checkout,PTK_REFERENCE_ROOT:reference.extensionPath}});}catch(error){status=error.status??'error';output=String(error.stdout||'')+'\n'+String(error.stderr||error.message);}
  const evidencePath=path.join(root,'tools/security/evidence','collection-parity-'+variant+'.json'),evidence=fs.existsSync(evidencePath)?JSON.parse(fs.readFileSync(evidencePath,'utf8')):null;
  const result={variant,revertedFunction:name,status,productionSha256:hashBefore,variantSha256:sha(modified),originalSourceSha256:sha(upstream),referenceObservations:evidence?.reference?.snapshots?.[0]?.observations,ownedObservations:evidence?.owned?.snapshots?.[0]?.observations,output};outcomes.push(result);console.log(JSON.stringify(result));
 }
 assert.equal(sha(fs.readFileSync(path.join(root,sourceFile))),hashBefore,'Production source must remain unchanged');
 fs.writeFileSync(path.join(root,'tools/security/evidence/iast-message-ablation.json'),JSON.stringify({schema:1,referenceSha256:reference.sha256,outcomes,productionUnchanged:true},null,2));
}
main().catch(error=>{console.error(error);process.exitCode=1;}).finally(()=>{for(const folder of [directory,reference?.directory])if(folder&&path.resolve(folder).startsWith(path.resolve(os.tmpdir())+path.sep)&&/^cert-x-(?:iast-ablation|security-reference)-/.test(path.basename(folder)))fs.rmSync(folder,{recursive:true,force:true,maxRetries:5,retryDelay:100});});

// One-time, auditable import. Normal builds use the maintained checkout, not inspiration folders.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const repo=path.resolve(__dirname,'../..');
const source=path.resolve(process.argv[2]||'C:/Users/zeb/Downloads/insp/pentestkit-10.0.0-release');
const previous=path.resolve(process.argv[3]||'C:/Users/zeb/Downloads/insp/pentestkit-9.9.9');
const prepared=path.join(process.env.LOCALAPPDATA,'cert-x/ptk/v10/src/ptk');
const dest=path.join(repo,'security/ptk');
if(fs.existsSync(dest))throw Error('Owned runtime already exists; edit it directly rather than reimporting.');
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const sourceRoot=path.join(source,'src/ptk');
const files=[];
const packages=new Set(['browser-polyfill','crypto-es','jose','lodash-es','retire','wappalyzer','dompurify','js-yaml','jspdf','jspdf-autotable']);
function walk(dir,rel=''){for(const e of fs.readdirSync(dir,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name))){const r=rel?rel+'/'+e.name:e.name;if(e.isDirectory())walk(path.join(dir,e.name),r);else if(e.isFile())files.push(r);}}
walk(sourceRoot);
function wanted(r){const p=r.split('/'); if(p[0]==='packages')return packages.has(p[1]);if(p[0]==='browser')return r.startsWith('browser/assets/icons/')||r.startsWith('browser/assets/images/')||r==='browser/showhtml.html'||r==='browser/assets/js/showhtml.js';return !['controller','devtools','internal','cert-x'].includes(p[0])&&!['automationBridge.js','ptkAgentAutomation.js','background.html','background_automation.html'].includes(r);}
const inventory=[];
function rebase(text){return text.replace(/(['"`])(\/?ptk\/)/g,(_,q,p)=>q+(p[0]==='/'?'/':'')+'security/ptk/');}
for(const r of files.filter(wanted)){
 let actual=path.join(sourceRoot,r),bytes=fs.readFileSync(actual),origin='v10';
 // Some official source package placeholders are populated by build_src from the locked dependencies.
 if(!bytes.length&&fs.existsSync(path.join(prepared,r))){actual=path.join(prepared,r);bytes=fs.readFileSync(actual);origin='v10-built-dependency';}
 let owned=bytes;
 if(/\.(?:m?js|html|css|json)$/.test(r))owned=Buffer.from(rebase(bytes.toString('utf8')));
 const target=path.join(dest,r);fs.mkdirSync(path.dirname(target),{recursive:true});fs.writeFileSync(target,owned);
 inventory.push({path:'security/ptk/'+r,source:r,origin,sourceSha256:sha(bytes),importedSha256:sha(owned)});
}
// build_src installs package files absent from the source tree. Copy only required package namespaces.
for(const pkg of packages){const root=path.join(prepared,'packages',pkg);if(!fs.existsSync(root))continue;const pending=[];function visit(d,rel=''){for(const e of fs.readdirSync(d,{withFileTypes:true})){const r=rel?rel+'/'+e.name:e.name;e.isDirectory()?visit(path.join(d,e.name),r):pending.push(r)}}visit(root);for(const rel of pending){const r='packages/'+pkg+'/'+rel,target=path.join(dest,r);if(fs.existsSync(target)&&fs.statSync(target).size)continue;const bytes=fs.readFileSync(path.join(root,rel));fs.mkdirSync(path.dirname(target),{recursive:true});fs.writeFileSync(target,bytes);inventory.push({path:'security/ptk/'+r,source:r,origin:'v10-built-dependency',sourceSha256:sha(bytes),importedSha256:sha(bytes)});}}
fs.writeFileSync(path.join(dest,'package.json'),' {"private":true,"type":"module"}\n');
fs.copyFileSync(path.join(source,'LICENSE.txt'),path.join(dest,'LICENSE-PTK.txt'));
fs.copyFileSync(path.join(source,'package-lock.json'),path.join(repo,'tools/security/upstream-package-lock.json'));
const modules=[],metadataOnly=[],v9Comparison=[];
for(const engine of ['dast','sast','iast'])for(const file of ['modules.json',...(engine==='dast'?['modules_cve.json']:[])]){
const rel='background/'+engine+'/modules/'+file,a=JSON.parse(fs.readFileSync(path.join(sourceRoot,rel))),b=JSON.parse(fs.readFileSync(path.join(previous,'ptk',rel)));
for(const m of a.modules)modules.push({engine:engine.toUpperCase(),id:m.id,name:m.name,source:rel,tier:file==='modules_cve.json'?'cve':'standard',executable:true,checks:(m.attacks||m.rules||[]).map(x=>({id:x.id||x.name||null})),verification:'pending'});
const oldOnly=b.modules.filter(m=>!a.modules.some(x=>x.id===m.id));v9Comparison.push({file:rel,additionalModuleIds:oldOnly.map(x=>x.id),identical:JSON.stringify(a)===JSON.stringify(b)});
}
for(const engine of ['dast','sast','iast']){const rel='background/'+engine+'/modules/modules_pro_metadata.json',d=JSON.parse(fs.readFileSync(path.join(sourceRoot,rel)));for(const m of d.modules)if(!modules.some(x=>x.engine===engine.toUpperCase()&&x.id===m.moduleId))metadataOnly.push({engine:engine.toUpperCase(),id:m.moduleId,name:m.name,source:rel,executable:false,reason:'metadata_only_in_standard_rulepacks'});}
const capabilities=['DAST','IAST','SAST','SCA','capture','replay','macros','jwt','reconnaissance','port_probe','encode','decode','report_export','macro_import','macro_export'];
fs.writeFileSync(path.join(repo,'security/capabilities.json'),JSON.stringify({schema:1,baseline:'PTK 10.0.0',capabilities:capabilities.map(id=>({id,verification:'pending'})),modules,metadataOnly,v9Comparison},null,2)+'\n');
fs.writeFileSync(path.join(repo,'security/provenance.json'),JSON.stringify({schema:1,baseline:'10.0.0',license:'AGPL-3.0-only',sourcePackageLockSha256:sha(fs.readFileSync(path.join(source,'package-lock.json'))),files:inventory.sort((a,b)=>a.path.localeCompare(b.path))},null,2)+'\n');
console.log(JSON.stringify({files:inventory.length,modules:modules.length,metadataOnly:metadataOnly.length,v9Comparison}));

const fs=require('fs'),path=require('path'),crypto=require('crypto');
(async()=>{
 const {parse}=await import('../../security/ptk/background/sast/acorn/acorn.mjs');
 const base='C:/Users/zeb/Downloads/insp/pentestkit-10.0.0-release/src/ptk/browser/assets/js';
 const src=fs.readFileSync(path.join(base,'report.js'),'utf8'),ast=parse(src,{ecmaVersion:'latest',sourceType:'module'});
 const declarations=new Map(),imports=new Map();
 for(const n of ast.body){if(n.type==='FunctionDeclaration')declarations.set(n.id.name,n);if(n.type==='VariableDeclaration')for(const d of n.declarations)if(d.id.type==='Identifier')declarations.set(d.id.name,n);if(n.type==='ImportDeclaration')for(const spec of n.specifiers)imports.set(spec.local.name,n);}
 function identifiers(n,out=new Set()){if(!n||typeof n!=='object')return out;if(n.type==='Identifier')out.add(n.name);for(const v of Object.values(n)){if(Array.isArray(v))v.forEach(x=>identifiers(x,out));else if(v&&typeof v==='object')identifiers(v,out);}return out;}
 const roots=['buildReportModel','buildMarkdownFromExportModel','buildPdfFromExportModel','buildExecutivePdfFromReportModel','buildExportFindingFromNormalized','buildExportFindingFromSca','buildScaEntries','buildScaEntriesFromFindings'];
 const selected=new Set(),selectedImports=new Set(),todo=roots.slice();while(todo.length){const id=todo.pop();if(declarations.has(id)){const n=declarations.get(id);if(selected.has(n))continue;selected.add(n);for(const ref of identifiers(n))todo.push(ref);}else if(imports.has(id))selectedImports.add(imports.get(id));}
 const parts=[...selectedImports,...selected].sort((a,b)=>a.start-b.start).map(n=>src.slice(n.start,n.end));
 const target='security/ptk/browser/assets/js/report-core.js';fs.mkdirSync(path.dirname(target),{recursive:true});fs.writeFileSync(target,'/* PTK v10 report builders, extracted into a UI-independent owned module. Original author: Denis Podgurskii. */\n'+parts.join('\n\n')+'\nexport { '+roots.join(', ')+', exportModel };\n');
 fs.cpSync(path.join(base,'report'),'security/ptk/browser/assets/js/report',{recursive:true});
 for(const file of ['rutils.js','scanResultViewModel.js','findingNormalizer.js','sastFindingItem.js','iastFindingItem.js','htmlPreview.js','safeUiText.js'])fs.copyFileSync(path.join(base,file),path.join('security/ptk/browser/assets/js',file));
 fs.writeFileSync('security/report-provenance.json',JSON.stringify({source:'PTK v10 browser/assets/js/report.js',sourceSha256:crypto.createHash('sha256').update(src).digest('hex'),extractedDeclarations:[...selected].flatMap(n=>n.id?[n.id.name]:n.declarations.map(d=>d.id.name)),purpose:'Reuse native report model, Markdown, technical PDF and executive PDF rendering without popup/controllers/event handlers'},null,2)+'\n');
 console.log(JSON.stringify({functions:selected.size,imports:[...selectedImports].map(n=>n.source.value)}));
})();

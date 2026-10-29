// Exercise portable setup even on a developer machine with Python installed.
const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path'),{promisify}=require('node:util'),{execFile}=require('node:child_process');
const {createSetup}=require('../../host/security/setup.cjs');
const source=process.env.CERT_X_TEST_RUNTIME||process.argv[2];if(!source)throw Error('Provide a prepared runtime to reuse its verified Node packages');
(async()=>{
 const root=await fs.mkdtemp(path.join(os.tmpdir(),'cert-x-python-fallback-'));
 const installed=JSON.parse(await fs.readFile(path.join(source,'installed.json'),'utf8'));delete installed.components.webhook;delete installed.components.python;
 const pin=require('../runtime/assets.lock.json').python,cacheName=pin.sha256+'.zip';
 try{await fs.mkdir(path.join(root,'cache'));await fs.copyFile(path.join(source,'cache',cacheName),path.join(root,'cache',cacheName));}catch(error){if(error.code!=='ENOENT')throw error;}
 await fs.writeFile(path.join(root,'installed.json'),JSON.stringify(installed));process.env.CERT_X_PYTHON=path.join(root,'absent-python.exe');
 const setup=createSetup({root});await setup.setup({components:['oast']});
 const result=await promisify(execFile)(await setup.componentPath('webhook'),['-I','-c','import sys,importlib.metadata; from server import run_server; print(sys.version.split()[0]); print(importlib.metadata.version("webhook-mcp-server"))'],{windowsHide:true});
 if(!result.stdout.includes('3.12.15')||!result.stdout.includes('3.0.0'))throw Error('Portable runtime compatibility failed');
 const evidence={portablePython:true,webhookImport:true,root,versions:result.stdout.trim().split(/\r?\n/)};
 await fs.writeFile(path.join(root,'verification.json'),JSON.stringify(evidence,null,2));console.log(JSON.stringify(evidence));
})().catch(error=>{console.error(error.message);process.exitCode=1;});

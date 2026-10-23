const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os'),{execFile}=require('node:child_process'),{promisify}=require('node:util');
const exec=promisify(execFile),repo=path.resolve(__dirname,'../../..'),id='abcdefghijklmnopabcdefghijklmnop';
const ps=script=>exec('powershell.exe',['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',...script],{windowsHide:true,timeout:60000,maxBuffer:1024*1024});
test('native host update stages a complete tree, preserves user files, and restores after publication failure',async t=>{
 const base=await fs.mkdtemp(path.join(os.tmpdir(),'cert-x-installer-')),source=path.join(base,'source'),output=path.join(base,'install with spaces');
 t.after(async()=>{assert.ok(path.resolve(base).startsWith(path.resolve(os.tmpdir())+path.sep));await fs.rm(base,{recursive:true,force:true,maxRetries:5,retryDelay:100});});
 const host=path.join(source,'tools/host');await fs.mkdir(host,{recursive:true});
 for(const name of ['install.ps1','stage-install.ps1','ki-host.js','jobs.js'])await fs.copyFile(path.join(repo,'tools/host',name),path.join(host,name));
 await fs.cp(path.join(repo,'tools/host/security'),path.join(host,'security'),{recursive:true});
 const locks=path.join(source,'tools/security/runtime');await fs.mkdir(locks,{recursive:true});
 for(const name of ['package.json','package-lock.json','assets.lock.json','requirements.lock','README.md','THIRD_PARTY_NOTICES.md'])await fs.copyFile(path.join(repo,'tools/security/runtime',name),path.join(locks,name));
 const args=[path.join(host,'install.ps1'),'-ExtensionId',id,'-Browser','Chromium','-GenerateOnly','-OutputDirectory',output];await ps(args);
 const target=path.join(output,'Chromium',id),manifest=JSON.parse(await fs.readFile(path.join(target,'com.cert_x.host.json')));
 assert.equal(manifest.path,path.join(target,'launch.cmd'));assert.deepEqual(manifest.allowed_origins,['chrome-extension://'+id+'/']);
 await fs.writeFile(path.join(target,'user-note.txt'),'preserve this installed file');
 await fs.appendFile(path.join(host,'ki-host.js'),'\n// installed upgrade fixture\n');await ps(args);
 const previous=await fs.readFile(path.join(target,'ki-host.js'),'utf8');assert.match(previous,/installed upgrade fixture/);assert.equal(await fs.readFile(path.join(target,'user-note.txt'),'utf8'),'preserve this installed file');
 // A failure after directory publication must restore the previous tree. This
 // invalid provider does not touch a browser registry key.
 await fs.appendFile(path.join(host,'ki-host.js'),'\n// must roll back\n');
 await assert.rejects(ps([path.join(host,'stage-install.ps1'),'-TargetDirectory',target,'-NodePath',process.execPath,'-ExtensionId',id,'-RegistryPath','NoSuchProvider:\\cert-x-fixture']));
 assert.equal(await fs.readFile(path.join(target,'ki-host.js'),'utf8'),previous);
 assert.deepEqual(await fs.readdir(path.dirname(target)),[id]);
 await fs.unlink(path.join(host,'jobs.js'));await assert.rejects(ps(args));assert.equal(await fs.readFile(path.join(target,'ki-host.js'),'utf8'),previous);
 const check=await exec(process.execPath,['-e',"require(process.argv[1]).dispatch('status',{}).then(x=>console.log(JSON.stringify(x.features)))",path.join(target,'ki-host.js')],{windowsHide:true});
 assert.ok(JSON.parse(check.stdout).includes('security_runtime_v1'));
});

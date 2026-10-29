// Controlled missing-Java install: reuse verified unrelated components, then
// exercise the real pinned JRE archive and its keytool used by the private guard.
const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path'),{createSetup,digest,run}=require('../../host/security/setup.cjs');
const source=process.env.CERT_X_TEST_RUNTIME||process.argv[2];if(!source)throw Error('Provide a prepared managed runtime');
(async()=>{
 const root=await fs.mkdtemp(path.join(os.tmpdir(),'cert-x-java-fallback-')),installed=JSON.parse(await fs.readFile(path.join(source,'installed.json'),'utf8'));
 delete installed.components.jre;for(const key of ['chromium','chromedriver','zap'])if(installed.components[key])installed.components[key].entrySha256=digest(await fs.readFile(installed.components[key].path));
 await fs.writeFile(path.join(root,'installed.json'),JSON.stringify(installed));process.env.CERT_X_JAVA=path.join(root,'absent-java.exe');
 const setup=createSetup({root});await setup.setup({components:['zap']});const java=await setup.componentPath('java');
 if(!path.resolve(java).startsWith(path.resolve(root)+path.sep))throw Error('Fallback unexpectedly reused the system Java');
 const version=await run(java,['-version']);if(!version.includes('21.0.12.1'))throw Error('Pinned JRE version differs');
 await run(path.join(path.dirname(java),'keytool.exe'),['-help']);
 const evidence={portableJava:true,keytool:true,version:version.split(/\r?\n/)[0],root};await fs.writeFile(path.join(root,'verification.json'),JSON.stringify(evidence,null,2));console.log(JSON.stringify(evidence));
})().catch(error=>{console.error(error.message);process.exitCode=1;});

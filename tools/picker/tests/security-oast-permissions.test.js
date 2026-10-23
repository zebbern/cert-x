const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),{webcrypto}=require('node:crypto');
function fixture(){
 const server={id:'callbacks',command:'python',args:['-m','provider'],secretRef:'private-reference'},data={ki_native_settings:{enabled:true,servers:[server]},ki_security_integrations:{oastConnectionId:'callbacks'},sidepanel_approval_mode:'full_access'};
 const selected={tools:{groups:{local:true,mcp:true,ptk:true},tools:{}},permissions:{groups:{},tools:{}},mcp:[]},approvals=[];
 const event={addListener(){},removeListener(){}},chrome={runtime:{onMessage:event,id:'fixture',getURL:file=>'chrome-extension://fixture/'+file},storage:{onChanged:event,local:{get:async keys=>Object.fromEntries((Array.isArray(keys)?keys:[keys]).map(key=>[key,data[key]])),set:async value=>Object.assign(data,value)}}};
 const c=vm.createContext({chrome,crypto:webcrypto,TextEncoder,console,setTimeout,clearTimeout,AbortController,kiWorkspaceOwner:x=>x,kiContextResolve:async()=>selected,kiContextFor:()=>selected,KN:{request:async value=>{approvals.push(value);return 'allow_once';}}});
 const source=name=>fs.readFileSync(path.join(__dirname,'../src',name),'utf8');
 vm.runInContext(source('ki-permissions.js'),c);vm.runInContext(source('ki-native.js'),c);vm.runInContext(source('ki-security.js'),c);
 const contexts=source('ki-context.js');vm.runInContext(contexts.slice(contexts.indexOf('function kiContextAllows('),contexts.indexOf('function kiContextArgs(')),c);
 const context={owner:'chat',session:'chat',workspaceId:'work',runId:'run',recheck:async()=>{},signal:new AbortController().signal};
 return {c,server,data,selected,approvals,context};
}
test('callback backend selection is independent of MCP exposure, but group and per-tool restrictions apply',async()=>{
 const f=fixture();await f.c.kiSecurityOastGrant('oast.create',{},f.context);assert.equal(f.approvals.length,0);
 await f.context.providerRecheck({connectionId:'callbacks',toolName:'configure_webhook'});
 const meta=await f.c.kiPolicyMcpMeta(f.server,'configure_webhook','local');f.selected.tools.tools[meta.id]=false;
 await assert.rejects(f.context.providerRecheck({connectionId:'callbacks',toolName:'configure_webhook'}),/disabled/);delete f.selected.tools.tools[meta.id];
 f.data.ki_tool_permissions={groups:{mcp:'disabled'},tools:{[meta.id]:'allow'}};
 await assert.rejects(f.context.providerRecheck({connectionId:'callbacks',toolName:'configure_webhook'}),/disabled/);
});
test('one callback approval covers declared provider methods, while stale rules and undeclared methods fail',async()=>{
 const f=fixture();f.data.ki_tool_permissions={groups:{mcp:'ask'}};f.context.oastActions=['create','events','wait'];
 await f.c.kiSecurityOastGrant('oast.create',{},f.context);assert.equal(f.approvals.length,1);
 for(const toolName of ['configure_webhook','get_webhook_info','get_webhook_requests','get_request','wait_for_request'])await f.context.providerRecheck({connectionId:'callbacks',toolName});
 assert.equal(f.approvals.length,1);await assert.rejects(f.context.providerRecheck({connectionId:'callbacks',toolName:'unadvertised'}),/not authorized/);
 f.data.ki_tool_permissions={groups:{mcp:'disabled'}};await assert.rejects(f.context.providerRecheck({connectionId:'callbacks',toolName:'get_request'}),/disabled/);
});
test('new follow-up methods are admitted explicitly and changed connections cannot receive target traffic',async()=>{
 const f=fixture();await f.c.kiSecurityOastGrant('oast.create',{},f.context);await f.c.kiSecurityOastGrant('oast.events',{},f.context);
 await f.context.providerRecheck({connectionId:'callbacks',toolName:'get_request'});assert.equal(f.approvals.length,0);
 f.data.ki_tool_permissions={groups:{mcp:'ask'}};await assert.rejects(f.context.providerRecheck({connectionId:'callbacks',toolName:'get_request'}),/changed/);
 f.data.ki_native_settings.servers[0]={...f.server,args:['different']};await assert.rejects(f.c.kiNativeSecurityRecheck(f.context),/connection changed/);
});
test('old action approval cannot silently cover newly requested provider methods',async()=>{
 const f=fixture();f.data.ki_tool_permissions={groups:{mcp:'ask'}};f.context.permissionApproved=true;
 await f.c.kiSecurityOastGrant('oast.create',{},f.context);assert.equal(f.approvals.length,0);
 await f.c.kiSecurityOastGrant('oast.events',{},f.context);assert.equal(f.approvals.length,1);
 await f.context.providerRecheck({connectionId:'callbacks',toolName:'get_request'});assert.equal(f.approvals.length,1);
});

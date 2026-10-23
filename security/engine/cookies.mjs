// Cookie policies reuse PTK's cookie reconstruction/comparison helpers, with exact
// browser cookie identities and private, owner-bound policy persistence.
import {ptk_session} from '../ptk/background/session.js';
import {sensitiveArtifactStorage} from '../ptk/background/sensitiveArtifactStore.js';
import {scopeAllows} from '../config.mjs';
const KEY='cert_x_cookie_policies_v1';
const copy=value=>JSON.parse(JSON.stringify(value));
function partition(value){if(value==null)return null;const result={topLevelSite:String(value.topLevelSite||''),hasCrossSiteAncestor:value.hasCrossSiteAncestor===true};return result;}
export function cookieIdentity(cookie){return JSON.stringify([String(cookie.domain||'').toLowerCase(),cookie.path||'/',cookie.name,String(cookie.storeId??''),partition(cookie.partitionKey)]);}
const publicCookie=c=>({name:c.name,domain:c.domain,path:c.path,storeId:c.storeId,hostOnly:c.hostOnly,secure:c.secure,httpOnly:c.httpOnly,sameSite:c.sameSite,session:c.session,...(c.expirationDate!=null?{expirationDate:c.expirationDate}:{}),...(c.partitionKey?{partitionKey:copy(c.partitionKey)}:{}),hasValue:!!c.value});
const cookieDomain=c=>String(c.domain||'').replace(/^\./,'').toLowerCase();
function applies(cookie,url){const u=new URL(url),host=u.hostname.toLowerCase(),domain=cookieDomain(cookie),p=cookie.path||'/';return (cookie.hostOnly?host===domain:host===domain||host.endsWith('.'+domain))&&(u.pathname===p||u.pathname.startsWith(p.endsWith('/')?p:p+'/'));}
function sameCookie(helper,a,b){return cookieIdentity(a)===cookieIdentity(b)&&helper.matchCookie(a,b)&&a.hostOnly===b.hostOnly&&a.session===b.session&&(a.session||Math.abs(Number(a.expirationDate)-Number(b.expirationDate))<0.00001);}
export function createCookiePolicies({browser,privateStore=sensitiveArtifactStorage,validateContext}={}) {
  if(!browser?.cookies)throw Error('Cookie access is unavailable.');
  const policies=new Map(),leases=new Map(),queues=new Map();let writes=Promise.resolve();
  const helper=Object.create(ptk_session.prototype);
  // PTK's original helper derived Secure from an unrelated dashboard tab. A selected
  // cookie's own attributes determine its reconstruction URL instead.
  helper.buildCookieUrl=c=>`${c.secure?'https':'http'}://${cookieDomain(c)}${c.path||'/'}`;
  const persist=()=>{const task=writes.then(()=>privateStore.setItem(KEY,{version:1,policies:[...policies.values()].map(copy)}));writes=task.catch(()=>{});return task;};
  const serial=(key,fn)=>{const task=(queues.get(key)||Promise.resolve()).catch(()=>{}).then(fn);queues.set(key,task);task.finally(()=>{if(queues.get(key)===task)queues.delete(key);}).catch(()=>{});return task;};
  const ready=(async()=>{const stored=await privateStore.getItem(KEY);for(const p of stored?.policies||[])if(p?.id&&p.owner&&['block','readonly'].includes(p.mode)&&p.selector?.name&&p.key===cookieIdentity(p.selector))policies.set(p.id,p);})();ready.catch(()=>{});
  function policyFor(key){return [...policies.values()].find(p=>p.key===key);}
  async function freshContext(record,fallback){const resolver=validateContext||globalThis.certXSecurityCookiePolicyContext;const current=typeof resolver==='function'?await resolver({owner:record.owner,workspaceId:record.workspaceId,scope:record.scope,grant:record.grant||null,tool:'security_utility'}):fallback||leases.get(record.owner);if(!current)throw Error('Policy validation is unavailable.');if(current.owner!==record.owner||(current.workspaceId||null)!==record.workspaceId)throw Error('Policy ownership changed.');await current.recheck?.();if(!scopeAllows(record.sourceUrl,current.scope))throw Error('Policy target left the permitted scope.');return current;}
  function view(p){return {policyId:p.id,mode:p.mode,cookie:publicCookie(p.selector),state:p.state||'active',sourceUrl:p.sourceUrl,...(p.error?{error:p.error}:{}),scopeNote:'Browser cookies share domain/path storage across ports; domain cookies also affect matching subdomains.'};}
  async function currentCookie(selector){const query={name:selector.name,domain:cookieDomain(selector),storeId:selector.storeId,...(selector.partitionKey?{partitionKey:selector.partitionKey}:{})};const all=await browser.cookies.getAll(query);return all.find(c=>cookieIdentity(c)===cookieIdentity(selector))||null;}
  async function setCookie(cookie){const details=helper.buildCookie(copy(cookie));if(cookie.partitionKey)details.partitionKey=copy(cookie.partitionKey);const saved=await browser.cookies.set(details);if(!saved||cookieIdentity(saved)!==cookieIdentity(cookie))throw Error('Cookie update did not retain the selected identity.');return saved;}
  async function removeCookie(cookie){
    // cookies.remove selects by URL/name and may delete a same-named parent-domain
    // cookie. Expiring the selected identity uses domain/path/partition explicitly.
    const details=helper.buildCookie({...copy(cookie),value:cookie.value||'',session:false,expirationDate:1});if(cookie.partitionKey)details.partitionKey=copy(cookie.partitionKey);
    await browser.cookies.set(details);if(await currentCookie(cookie))throw Error('The selected cookie could not be removed.');
  }
  async function enforce(id){await ready;if(disposed)return;const initial=policies.get(id);if(!initial)return;return serial(initial.key,async()=>{const policy=policies.get(id);if(!policy)return;try{await freshContext(policy);const current=await currentCookie(policy.selector);if(!policies.has(id))return;
      if(policy.mode==='block'){if(current){await freshContext(policy);await removeCookie(current);}}else{if(!policy.snapshot.session&&Number(policy.snapshot.expirationDate)<=Date.now()/1000){policy.state='expired';policy.error='The retained cookie expired; clear the policy or select a fresh cookie.';await persist();return;}if(!current||!sameCookie(helper,current,policy.snapshot)){await freshContext(policy);await setCookie(policy.snapshot);}}
      if(policy.state!=='active'||policy.error){policy.state='active';delete policy.error;await persist();}
    }catch{policy.state='paused';policy.error='Policy effect paused: current permissions, scope, cookie availability, or browser storage prevented the operation.';await persist();}});}
  let disposed=false;
  const changed=change=>{if(disposed)return;void ready.then(()=>{const p=policyFor(cookieIdentity(change.cookie));if(p)return enforce(p.id);}).catch(()=>{});};
  browser.cookies.onChanged.addListener(changed);
  async function selected(args,context,{create=false}={}) {
    let url=args.url;if(!url&&Number.isInteger(args.tabId??context.tabId))url=(await browser.tabs.get(args.tabId??context.tabId)).url;
    if(typeof url!=='string'||!scopeAllows(url,context.scope))throw Error('Choose a cookie URL inside the current scope.');
    const parsedUrl=new URL(url);if(parsedUrl.username||parsedUrl.password)throw Error('Cookie URLs must not contain credentials.');parsedUrl.search='';parsedUrl.hash='';url=parsedUrl.href;
    const raw=args.cookie||args.selector||{};let identity;
    if(args.cookieId){try{identity=JSON.parse(args.cookieId);if(!Array.isArray(identity)||identity.length!==5)throw Error();}catch{throw Error('Invalid cookie identity.');}}
    let storeId=args.storeId??raw.storeId??identity?.[3];
    if(storeId==null){const stores=await browser.cookies.getAllCookieStores(),tabId=args.tabId??context.tabId,store=stores.find(x=>x.tabIds?.includes(tabId))||(stores.length===1?stores[0]:null);if(!store)throw Error('Select a cookie store.');storeId=store.id;}
    const selectedPartition=raw.partitionKey||identity?.[4];
    const all=await browser.cookies.getAll({url,storeId:String(storeId),...(selectedPartition?{partitionKey:selectedPartition}:{})});
    if(args.cookieId){const cookie=all.find(c=>cookieIdentity(c)===args.cookieId);if(!cookie)throw Error('Selected cookie is no longer available for this URL/store.');return {cookie,url};}
    if(!create&&!raw.name)return {cookies:all,url};
    if(typeof raw.name!=='string'||!raw.name||/[\x00-\x20;=]/.test(raw.name))throw Error('Provide a valid cookie name.');
    const descriptor={name:raw.name,domain:raw.domain||new URL(url).hostname,path:raw.path||'/',storeId:String(storeId),hostOnly:raw.hostOnly??!String(raw.domain||'').startsWith('.'),secure:raw.secure===true,httpOnly:raw.httpOnly===true,sameSite:raw.sameSite||'lax',session:raw.session??raw.expirationDate==null,...(raw.expirationDate!=null?{expirationDate:raw.expirationDate}:{}),...(raw.partitionKey?{partitionKey:partition(raw.partitionKey)}:{})};
    if(!descriptor.hostOnly&&!descriptor.domain.startsWith('.'))descriptor.domain='.'+descriptor.domain;
    if(!descriptor.path.startsWith('/')||!applies(descriptor,url))throw Error('Selected cookie domain/path does not apply to the scoped URL.');
    const cookie=all.find(c=>cookieIdentity(c)===cookieIdentity(descriptor));
    return {cookie:cookie||descriptor,url,exists:!!cookie,raw};
  }
  async function invoke(args={},context={}) {
    const action=args.action||'list';
    await ready;if(typeof context.owner!=='string'||!context.owner)throw Error('Cookie operations require a chat owner.');
    // Releasing an owned persistent effect remains available after permission or
    // scope revocation, like stopping a scan. It cannot install or modify cookies.
    if(action!=='unset'&&action!=='clear'){await context.recheck?.();context.signal?.throwIfAborted();leases.set(context.owner,context);}
    if(action==='listpolicies')return {policies:[...policies.values()].filter(p=>p.owner===context.owner&&p.workspaceId===(context.workspaceId||null)).map(view)};
    if(action==='export'){
      const {cookies,cookie,url}=await selected(args,context),items=cookies||[cookie],artifactRef=crypto.randomUUID();
      await privateStore.setItem('cert_x_cookie_export:'+artifactRef,{owner:context.owner,workspaceId:context.workspaceId||null,url,cookies:copy(items)});
      return {artifactRef,cookieCount:items.length,url,valuesIncluded:false};
    }
    if(action==='import'){
      const record=await privateStore.getItem('cert_x_cookie_export:'+args.artifactRef);
      if(!record||record.owner!==context.owner)throw Error('Cookie artifact is unavailable or belongs to another chat.');
      if(!scopeAllows(record.url,context.scope))throw Error('Cookie artifact target is outside scope.');
      for(const cookie of record.cookies){if(policyFor(cookieIdentity(cookie)))throw Error('Clear affected cookie policies before restoring this artifact.');if(!applies(cookie,record.url))throw Error('Cookie artifact contains an unrelated domain or path.');}
      const restored=[];for(const cookie of record.cookies){context.signal?.throwIfAborted();await context.recheck?.();try{await setCookie(cookie);restored.push(cookieIdentity(cookie));}catch(error){return {success:false,error:'Cookie restore failed after '+restored.length+' updates: '+error.message,restored,total:record.cookies.length,valuesIncluded:false};}}
      return {restored:restored.length,total:record.cookies.length,valuesIncluded:false};
    }
    if(action==='unset'||action==='clear'){
      const p=policies.get(args.policyId);if(!p||p.owner!==context.owner)throw Error('Cookie policy is unavailable or belongs to another chat.');
      return serial(p.key,async()=>{policies.delete(p.id);try{await persist();}catch(error){policies.set(p.id,p);throw error;}return {cleared:true,policyId:p.id};});
    }
    if(action==='list'){const {cookies,cookie,url}=await selected(args,context);const list=cookies||[cookie];return {url,cookies:list.map(c=>({...publicCookie(c),cookieId:cookieIdentity(c)})),valuesIncluded:false};}
    if(!['set','remove','block','readonly'].includes(action))throw Error('Unknown cookie operation.');
    const selection=await selected(args,context,{create:action==='set'||action==='block'}),cookie=selection.cookie;if(!cookie)throw Error('Select one exact cookie.');const key=cookieIdentity(cookie);
    return serial(key,async()=>{
      const existing=policyFor(key);if(existing&&(existing.owner!==context.owner||existing.workspaceId!==(context.workspaceId||null)))throw Error('This cookie is controlled by another chat or workspace.');
      await context.recheck?.();if(!scopeAllows(selection.url,context.scope))throw Error('Cookie scope changed.');
      if(action==='remove'){if(existing)throw Error('Clear the cookie policy before removing this cookie.');await removeCookie(cookie);return {removed:true,cookie:publicCookie(cookie)};}
      if(action==='set'){
        if(existing)throw Error('Clear the cookie policy before editing this cookie.');
        const changes=args.changes||args.cookie||{};const next={...cookie};for(const field of ['value','httpOnly','secure','sameSite','session','expirationDate'])if(Object.hasOwn(changes,field))next[field]=changes[field];
        if(typeof next.value!=='string')throw Error('Set requires a string cookie value.');const saved=await setCookie(next);return {updated:true,cookie:publicCookie(saved),cookieId:cookieIdentity(saved)};
      }
      const current=await currentCookie(cookie);if(action==='readonly'&&!current)throw Error('Readonly requires an existing cookie snapshot.');
      const policy={id:existing?.id||crypto.randomUUID(),owner:context.owner,workspaceId:context.workspaceId||null,key,mode:action,selector:publicCookie(cookie),...(action==='readonly'?{snapshot:copy(current)}:{}),sourceUrl:selection.url,scope:copy(context.scope),grant:copy(context.cookiePolicyGrant||null),state:'active'};
      if(typeof privateStore._open==='function'&&!await privateStore._open())throw Error('Private cookie policy storage is unavailable.');
      policy.key=cookieIdentity(policy.selector);policies.set(policy.id,policy);
      try{await persist();}catch(error){if(existing)policies.set(existing.id,existing);else policies.delete(policy.id);throw error;}
      try{await freshContext(policy,context);const latest=await currentCookie(cookie);if(action==='block'&&latest){await freshContext(policy,context);await removeCookie(latest);}else if(action==='readonly'&&(!latest||!sameCookie(helper,latest,policy.snapshot))){await freshContext(policy,context);await setCookie(policy.snapshot);}}
      catch{policy.state='paused';policy.error='Policy was saved but its effect is paused because current permission, scope, or browser storage did not allow it.';await persist();}
      return view(policy);
    });
  }
  return {ready,invoke,reconcile:async()=>{await ready;await Promise.all([...policies.keys()].map(enforce));},dispose(){disposed=true;leases.clear();browser.cookies.onChanged.removeListener(changed);}};
}

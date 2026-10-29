// Native DAST helper tabs receive navigation rules before their first target load.
// These rules never apply to ordinary user tabs.
export function createNavigationScope(resources) {
  const owners=new Map();
  const escape=value=>String(value).replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
  const pathPattern=value=>Array.from(value).map(char=>{
    const encoded=Array.from(new TextEncoder().encode(char)).map(byte=>'%'+byte.toString(16).padStart(2,'0').replace(/[a-f]/g,letter=>'['+letter+letter.toUpperCase()+']')).join('');
    return '(?:'+escape(char)+'|'+encoded+')';
  }).join('');
  async function admit(tabId,context) {
    if(owners.has(tabId))return;
    const api=resources.forOwner('security-navigation:'+tabId);
    const rules=[{id:1,priority:1,action:{type:'block'},condition:{tabIds:[tabId],regexFilter:'^https?://',resourceTypes:['main_frame','sub_frame']}}];
    let next=2;
    const originPattern=origin=>context.scope.matchMode==='host'?'https?://'+(context.scope.includeSubdomains&&!new URL(origin).hostname.startsWith('[')&&!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(new URL(origin).hostname)?'(?:[^./:]+\\.)*':'')+escape(new URL(origin).hostname)+'(?::[0-9]{1,5})?':escape(origin);
    for(const origin of context.scope.origins)rules.push({id:next++,priority:2,action:{type:'allow'},condition:{tabIds:[tabId],regexFilter:'^'+originPattern(origin)+'(?:/|$)',resourceTypes:['main_frame','sub_frame']}});
    for(const origin of context.scope.origins)for(const path of context.scope.excludePaths||[])rules.push({id:next++,priority:3,action:{type:'block'},condition:{tabIds:[tabId],regexFilter:'^'+originPattern(origin)+pathPattern(path.replace(/\/$/,''))+'(?:/|%2[fF]|[?#]|$)',resourceTypes:['main_frame','sub_frame']}});
    await api.declarativeNetRequest.updateSessionRules({addRules:rules});
    owners.set(tabId,{api,ruleIds:rules.map(x=>x.id),owner:context.owner,runId:context.runId});
  }
  async function release(tabId) {const value=owners.get(tabId);if(!value)return;await value.api.declarativeNetRequest.updateSessionRules({removeRuleIds:value.ruleIds});owners.delete(tabId);}
  async function releaseRun(context) {for(const [tabId,value]of owners)if(value.owner===context.owner&&value.runId===context.runId)await release(tabId);}
  return {admit,release,releaseRun,has:tabId=>owners.has(tabId)};
}

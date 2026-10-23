import test from 'node:test';
import assert from 'node:assert/strict';
import {createNavigationScope} from '../../../security/engine/navigation.mjs';
function harness(){const calls=[],rules=new Map();return {calls,rules,resources:{forOwner:owner=>({declarativeNetRequest:{async updateSessionRules(change){calls.push({owner,...change});for(const id of change.removeRuleIds||[])rules.delete(owner+':'+id);for(const rule of change.addRules||[])rules.set(owner+':'+rule.id,rule);}}})}};}
function action(rules,tabId,url){return [...rules.values()].filter(r=>r.condition.tabIds.includes(tabId)&&new RegExp(r.condition.regexFilter).test(url)).sort((a,b)=>b.priority-a.priority)[0]?.action.type||null;}
test('helper-only navigation blocks other origins and literal/encoded excluded paths',async()=>{const h=harness(),scope=createNavigationScope(h.resources);await scope.admit(7,{owner:'a',runId:'r',scope:{origins:['https://app.example','https://api.example:8443'],excludePaths:['/admin']}});assert.equal(action(h.rules,7,'https://app.example/profile'),'allow');assert.equal(action(h.rules,7,'https://api.example:8443/v1'),'allow');assert.equal(action(h.rules,7,'https://else.example/'),'block');assert.equal(action(h.rules,7,'https://app.example/admin'),'block');assert.equal(action(h.rules,7,'https://app.example/%61dmin%2fusers'),'block');assert.equal(action(h.rules,8,'https://else.example/'),null);await scope.release(7);assert.equal(h.rules.size,0);});
test('releasing a run preserves another run navigation rules',async()=>{const h=harness(),scope=createNavigationScope(h.resources),base={origins:['http://example.test'],excludePaths:[]};await scope.admit(1,{owner:'a',runId:'one',scope:base});await scope.admit(2,{owner:'b',runId:'two',scope:base});await scope.releaseRun({owner:'a',runId:'one'});assert.equal(scope.has(1),false);assert.equal(scope.has(2),true);assert.equal(action(h.rules,2,'http://other.test'),'block');});
test('helper navigation follows selected host mode and keeps exclusions and sibling boundaries',async()=>{
 const h=harness(),scope=createNavigationScope(h.resources);
 await scope.admit(3,{owner:'a',runId:'r',scope:{origins:['https://app.test:8443'],excludePaths:['/private'],matchMode:'host',includeSubdomains:true}});
 for(const target of ['http://app.test:8080/public','https://api.app.test:9443/public'])assert.equal(action(h.rules,3,target),'allow',target);
 for(const target of ['https://badapp.test/public','https://sibling.test/public','http://api.app.test:8080/private/data'])assert.equal(action(h.rules,3,target),'block',target);
 await scope.release(3);
});

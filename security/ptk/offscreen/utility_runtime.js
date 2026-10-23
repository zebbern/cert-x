import { renderSecurityReport } from './report_renderer.js';
import { ptk_portscanner } from '../background/portscanner.js';
const runtime=chrome.runtime;
const jobs=new Map();
runtime.onMessage.addListener((message,sender)=>{
  if(message?.channel!=='CERT_X_SECURITY_DOM')return undefined;
  if(sender.id!==runtime.id||sender.tab||!String(sender.url||'').startsWith(runtime.getURL('background/')))return Promise.resolve({ok:false,error:'untrusted_dom_controller'});
  if(message.action==='report') {try{return Promise.resolve({ok:true,artifact:renderSecurityReport(message.args||{})});}catch(error){return Promise.resolve({ok:false,error:error.message});}}
  if(message.action==='cancel'){jobs.get(message.token)?.abort();return Promise.resolve({ok:true});}
  if(message.action!=='portscan'||typeof message.token!=='string')return Promise.resolve({ok:false,error:'unknown_dom_operation'});
  const controller=new AbortController();jobs.set(message.token,controller);
  return (async()=>{try{
    const args=message.args||{}, results=[];
    for(const port of args.ports||[]){
      const observation=await ptk_portscanner.prototype.isPortOpen.call({},args.host,port,args.samples||30,{
        signal:controller.signal,timeoutMs:args.timeoutMs||5000,baselinePort:args.baselinePort||37857,
        beforeProbe:async url=>{const result=await runtime.sendMessage({channel:'CERT_X_SECURITY_PROBE',token:message.token,url});if(!result?.ok)throw Error(result?.error||'Probe admission failed');}
      });
      results.push({port,observation:observation[0]?'timing_difference':'no_timing_difference',matchingSamples:observation[1],targetTimeMs:observation[2],baselineTimeMs:observation[3],confirmedOpen:false});
    }
    return {ok:true,results,note:'Browser timing is a heuristic, not confirmation of TCP port state.'};
  }catch(error){return {ok:false,error:error.message};}finally{jobs.delete(message.token);}})();
});

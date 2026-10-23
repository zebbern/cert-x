import './ptk/packages/browser-polyfill/browser-polyfill.min.js';
import defaultSettings from './ptk/settings.default.js';
import { scopeAllows } from './config.mjs';
import { createNavigationScope } from './engine/navigation.mjs';
import { buildIastDocumentSource } from './engine/iast-bootstrap.mjs';
import { createIastDocuments } from './engine/iast-documents.mjs';
import { createCookiePolicies } from './engine/cookies.mjs';
import { OPERATION_SCHEMAS } from './engine/operation-arguments.mjs';
import { readProgressResponse } from './engine/progress.mjs';
import { parseSpec, specSummary, describeOperations, createApiOperations } from './engine/openapi.mjs';
import { createCandidateWorkflows } from './engine/candidates.mjs';
import { createSupplementalBackends } from './engine/backends.mjs';
import { ptk_settings } from './ptk/background/settings.js';
import { ptk_proxy } from './ptk/background/proxy.js';
import { ptk_dashboard } from './ptk/background/dashboard.js';
import { ptk_dast } from './ptk/background/dast.js';
import { ptk_request, ptk_request_manager } from './ptk/background/rbuilder.js';
import { ptk_decoder } from './ptk/background/decoder.js';
import { ptk_jwt } from './ptk/background/jwt.js';
import { ptk_sca } from './ptk/background/sca.js';
import { ptk_sast } from './ptk/background/sast.js';
import { ptk_iast, buildIastAgentScriptFiles } from './ptk/background/iast.js';
import { ptk_recorder } from './ptk/background/recorder.js';
import { ptk_importer } from './ptk/background/importer.js';
import { ptk_exporter } from './ptk/background/exporter.js';
import { compileFlow } from './ptk/background/macro/flow.js';
import { ptk_automation } from './ptk/background/automation.js';
import { ptk_utils, ptk_jwtHelper } from './ptk/background/utils.js';
import { ScopedTabSessionCoordinator } from './ptk/background/common/scopedTabSessionCoordinator.js';
import { OffscreenRuntimeManager } from './ptk/background/offscreen/offscreenRuntimeManager.js';
import { BrowserCaptureManager } from './ptk/background/capture/browserCaptureManager.js';
import { ChromiumCaptureAdapter } from './ptk/background/capture/chromiumCaptureAdapter.js';
import * as jose from './ptk/packages/jose/browser/index.js';
import { resultsRegistry } from './ptk/background/resultsRegistry.js';
import { parseUploadedScanFile } from './ptk/background/export/parseUploadedScanFile.js';
import { buildApiExplorer } from './ptk/background/analysis/apiExplorerBuilder.js';

const ACTIVE = new Set(['starting','running','stopping']);
const OPERATIONS = ['startScan','scanStatus','stopScan','getFindings','getEvidence','exportFullReport','capture','listRequests','replay','macro','utility','import','export','candidate','evidencePackage','api','browser','raw','oast','zap'];
const admissionError = message => Object.assign(new Error(message), {admitted:false});
const clone = value => value === undefined ? null : JSON.parse(JSON.stringify(value));
function assertSuccess(value) {
  if(value?.ok === false || value?.success === false || value?.error || value?.status === 'error') throw new Error(typeof value.error==='string'?value.error:value?.message||'Security operation failed');
  return value;
}
function headers(value) {return Array.isArray(value)?value.map(h=>({name:String(h.name),value:String(h.value)})):Object.entries(value||{}).map(([name,value])=>({name,value:String(value)}));}
export function createSecurityRuntime({resources}={}) {
  if(!resources?.chrome) throw new Error('Security runtime requires coordinated browser resources.');
  globalThis.__certXSecurityResources=resources;
  const browser=resources.browser||resources.chrome;
  const helperScopes=createNavigationScope(resources);
  const cookiePolicies=createCookiePolicies({browser});
  globalThis.isFirefox=false;
  const captureOwners=new Map(),manualCaptures=new Map(),captureContexts=new Map(),contexts=new Map(),reservations=new Map(),pendingRecon=new Map();
  let manifest,macroOwner=null;
  const domJobs=new Map(),retainedResults=new Map(),macroRecords=new Map(),interruptedResults=new Map();
  globalThis.__certXSecurityDastContext=null;
  let reconQueue=Promise.resolve();
  const app={version:'10.0.0',devLocalConfig:{automationEnabled:true},updated:false};
  globalThis.ptk_app=app;
  app.settings=new ptk_settings(clone(defaultSettings));
  app.settings.attachSecretProvider({getTokenSync:()=>''});
  app.settings.markReady();
  app.secretStore={getTokenSync:()=>'',getToken:async()=>''};
  app.offscreenRuntimeManager=new OffscreenRuntimeManager({chromeApi:resources.chrome});
  app.browserCaptureManager=new BrowserCaptureManager({adapter:new ChromiumCaptureAdapter({chrome:resources.chrome}),isOwnerActive:identity=>[app.dast,app.sast,app.iast,app.sca,app.recorder].some(x=>x?.isBrowserCaptureOwnerActive?.(identity)===true)});
  app.scopedTabSessions=new ScopedTabSessionCoordinator({browserApi:browser});
  const registerTabSession=app.scopedTabSessions.registerSession.bind(app.scopedTabSessions);
  app.scopedTabSessions.registerSession=(engine,options={})=>{
    const context=captureContexts.get(options.primaryTabId);
    return registerTabSession(engine,{...options,...(context?.scope?.origins?.length?{workspaceScope:clone(context.scope)}:{})});
  };
  app.proxy=new ptk_proxy(app.settings.proxy);
  function isCaptureActive(tabId){return manualCaptures.has(tabId)||helperScopes.has(tabId)||[...(app.automation?.sessions?.values?.()||[])].some(session=>session.tabId===tabId&&ACTIVE.has(session.status));}
  function claimCapture(tabId,context){
    if(captureOwners.has(tabId)&&captureOwners.get(tabId)!==context.owner){if(isCaptureActive(tabId))throw admissionError('The target tab is owned by another security session.');app.proxy.captureStore.clearTab(tabId);}
    captureOwners.set(tabId,context.owner);captureContexts.set(tabId,context);
  }
  // Capture only explicitly owned tabs; content hooks alone never start collection.
  for(const method of ['onBeforeRequest','onSendHeaders','onBeforeRedirect','onCompleted']) {
    const original=app.proxy[method];
    if(typeof original!=='function')continue;
    const event={onBeforeRequest:'onBeforeRequest',onSendHeaders:'onSendHeaders',onBeforeRedirect:'onBeforeRedirect',onCompleted:'onCompleted'}[method];
    browser.webRequest[event].removeListener(original);
    app.proxy[method]=function(details){if(captureOwners.has(details.tabId)&&isCaptureActive(details.tabId)&&scopeAllows(details.url,captureContexts.get(details.tabId)?.scope||{}))return original(details);};
    const extras=method==='onBeforeRequest'?['requestBody']:method==='onSendHeaders'?['requestHeaders','extraHeaders']:['responseHeaders','extraHeaders'];
    browser.webRequest[event].addListener(app.proxy[method],{urls:['<all_urls>']},extras);
  }
  app.request_manager=new ptk_request_manager(app.settings.rbuilder);
  app.dast=new ptk_dast(app.settings.rattacker,{offscreenManager:app.offscreenRuntimeManager});
  app.rattacker=app.dast;
  app.sast=new ptk_sast(undefined,{offscreenManager:app.offscreenRuntimeManager});
  app.iast=new ptk_iast(); app.sca=new ptk_sca();
  app.iast.requestInScope=event=>{
    const tabId=event.tabId??app.iast.scanResult?.tabId,context=captureContexts.get(tabId);
    return !!context&&captureOwners.get(tabId)===captureOwners.get(app.iast.scanResult?.tabId)&&scopeAllows(event.url,context.scope);
  };
  app.iast.getCaptureScope=tabId=>{
    const context=captureContexts.get(tabId);if(!context)throw Error('IAST capture ownership is missing.');
    return {origins:context.scope.origins,excludePaths:context.scope.excludePaths||[],mode:'origin',...(context.scope.matchMode==='host'?{matchMode:'host',includeSubdomains:context.scope.includeSubdomains===true}:{})};
  };
  for(const [id,engine] of [['SAST',app.sast],['SCA',app.sca]])engine.getCaptureScope=tabId=>{
    const context=captureContexts.get(tabId)||captureContexts.get(engine.scanResult?.tabId??engine.activeTabId);
    if(!context||!app.scopedTabSessions.isTrackedTab(id,tabId)&&!captureContexts.has(tabId))return {};
    return {origins:context.scope.origins,excludePaths:context.scope.excludePaths||[],...(context.scope.matchMode==='host'?{matchMode:'host',includeSubdomains:context.scope.includeSubdomains===true}:{})};
  };
  const iastScripts=new Map();
  app.iast.registerScript=async strategy=>{
    await app.iast.unregisterScript();
    const tabId=app.iast.scanResult?.tabId,context=captureContexts.get(tabId);
    if(!context)throw Error('IAST target ownership is missing.');
    const api=resources.forOwner('security-iast-document:'+tabId);
    const files=buildIastAgentScriptFiles(strategy);
    const sources=await Promise.all(files.map(async path=>{const response=await fetch(browser.runtime.getURL(path));if(!response.ok)throw Error('IAST script is missing: '+path);return response.text();}));
    const source=buildIastDocumentSource(sources,context.scope);
    const scan=app.iast.scanResult;
    const hooks=createIastDocuments({api,tabId,source,files,context,onCoverage:value=>{scan.certXDocumentCoverage=value;}});
    try {await hooks.start();iastScripts.set(tabId,hooks);return true;}
    catch(error){await hooks.stop().catch(()=>{});throw error;}
  };
  app.iast.unregisterScript=async()=>{
    const failures=[];for(const [tabId,hooks] of iastScripts){try{await hooks.stop();}catch(error){failures.push(error);}finally{iastScripts.delete(tabId);}}
    if(failures.length)throw new AggregateError(failures,'IAST frame cleanup was incomplete.');
  };
  const nativeTracked=app.iast.isTrackedScanTab.bind(app.iast);
  app.iast.isTrackedScanTab=tabId=>captureOwners.get(tabId)===captureOwners.get(app.iast.scanResult?.tabId)&&captureOwners.has(tabId)&&nativeTracked(tabId);
  const nativeRelated=app.iast.registerRelatedScanTab.bind(app.iast);
  app.iast.registerRelatedScanTab=(tabId,meta)=>captureOwners.has(tabId)&&captureOwners.get(tabId)===captureOwners.get(app.iast.scanResult?.tabId)?nativeRelated(tabId,meta):false;
  app.sca.certXFetch=async url=>{
    if(app.sca.isScanRunning&&app.sca.browserCaptureManager)throw Error('sca_captured_body_required');
    const context=app.sca.certXContext;if(!context)throw Error('SCA request context is unavailable.');
    const schema=ptk_request.parseRawRequest('GET '+url+' HTTP/1.1\r\nHost: '+new URL(url).host+'\r\n\r\n');
    const request=new ptk_request();request.certXContext=context;request.isolatedRedirectSession=true;
    const dispatch=()=>request.sendRequest(schema);
    const result=await(context.withRequest?context.withRequest(schema.request,dispatch):dispatch());
    if(result.response?.errorMessage||!Number(result.response?.statusCode))throw Error(result.response?.errorMessage||'SCA response is unavailable.');
    const status=Number(result.response.statusCode);
    return new Response([204,205,304].includes(status)?null:(result.response.body??''),{status,headers:Object.fromEntries((result.response.headers||[]).map(h=>[h.name,h.value]))});
  };
  app.dashboard=new ptk_dashboard();
  app.jwt=new ptk_jwt();
  app.recorder=new ptk_recorder(app.settings.recorder);
  app.recorder.setBrowserCaptureManager(app.browserCaptureManager);app.recorder.addMessageListeners();
  for(const engine of [app.dast,app.sast,app.iast,app.sca]) {engine.setBrowserCaptureManager?.(app.browserCaptureManager);engine.setScopedTabCoordinator?.(app.scopedTabSessions);}
  app.scopedTabSessions.start();
  app.automation=new ptk_automation();app.automation.init(app);
  app.automation._getContentRuntimeProfile=({tabId})=>isCaptureActive(tabId)?{mode:"manual",script:"manual",reason:"cert_x_owned_target"}:{mode:"pending",script:"none"};
  const recoveredDast=app.dast.runtimeReady.then(async state=>{
    if(!state?.adopted)return;
    // A surviving offscreen executor has no live cert-x permission context after
    // worker restart. Stop/release its exact generation before admitting new work.
    const sessionId=state.status?.executorState?.automationSessionId;
    const coordinator=app.dast.sessionCoordinator.getState();
    coordinator.acceptIncomingRequests=false;coordinator.userInteractionUnlocked=false;
    app.dast.captureAdapter?.removeListeners?.();
    const before=clone(app.dast.engine.scanResult);
    const stopped=await app.dast.engine.stop({interrupted:true});
    const scan=clone(stopped||before);
    if(sessionId&&scan?.scanId)interruptedResults.set(sessionId,{sessionId,engines:[{engine:'DAST',scanId:scan.scanId,scan}],findings:clone(scan.findings||[])});
    coordinator.automationSession=null;coordinator.pendingAutomationSeeds=0;
    app.dast.scopedTabCoordinator?.unregisterSession?.('DAST');
    await app.dast.unregisterScript?.();
    await app.dast._releaseAllBrowserCapture('worker_restart');
    app.proxy.endScanHistory?.();
  });
  app.ready=Promise.all([resources.ready,cookiePolicies.ready,recoveredDast,app.request_manager.initPromise,app.dashboard.ready,fetch(browser.runtime.getURL('security/capabilities.json')).then(r=>{if(!r.ok)throw Error('Security capability inventory is missing');return r.json();}).then(x=>manifest=x)]).then(()=>app);
  app.ready.catch(()=>{});

  // Route document-start instrumentation only for admitted targets. Management stays private.
  browser.runtime.onMessage.addListener((message,sender)=>{
    if(message?.channel==='ptk_content2popup'&&message.type==='init_complete') {
      const pending=pendingRecon.get(sender?.tab?.id);
      if(!pending||message.requestId!==pending.requestId||!ptk_utils.isTrustedContentSender(sender)||sender.frameId!==0||!scopeAllows(sender.url,pending.context.scope))return undefined;
      pending.resolve(message.data);return Promise.resolve({ok:true});
    }
    if(message?.channel==='CERT_X_SECURITY_PROBE') {
      if(sender.id!==browser.runtime.id||sender.url!==browser.runtime.getURL('security/ptk/offscreen/runtime_offscreen.html'))return Promise.resolve({ok:false,error:'Untrusted probe sender'});
      const job=domJobs.get(message.token);if(!job)return Promise.resolve({ok:false,error:'Probe job expired'});
      return Promise.resolve().then(()=>job.checkRequest?.({url:message.url,method:'GET',kind:'port_probe'})).then(()=>({ok:true}),error=>({ok:false,error:error.message}));
    }
    if(message?.channel!=='ptk_content2background_runtime')return undefined;
    if(message.type!=='content_bootstrap_hello')return Promise.resolve({ok:false,error:'native_control_required'});
    if(!ptk_utils.isTrustedContentSender(sender)||!captureOwners.has(sender.tab.id)||!scopeAllows(sender.url,captureContexts.get(sender.tab.id)?.scope||{}))return Promise.resolve({mode:'pending',script:'none'});
    return app.ready.then(()=>app.automation.handleContentBootstrapHello(message,sender));
  });
  const nativeEnqueue=app.dast.engine.enqueue.bind(app.dast.engine);
  app.dast.engine.enqueue=(raw,response)=>{
    const context=globalThis.__certXSecurityDastContext;
    if(context?.account&&raw&&typeof raw==='object')raw={...raw,capturedResponse:null,capturedRequest:null,__certXAccountReplayRequired:true};
    return nativeEnqueue(raw,response);
  };
  const nativePrivileged=app.dast._handleDastPrivilegedOperation.bind(app.dast);
  app.dast._handleDastPrivilegedOperation=async operation=>{
    const context=globalThis.__certXSecurityDastContext;
    if(operation.type==='request_send') {
      if(!context)throw Error('Security scan context is unavailable; restart the interrupted scan.');
      const dastBaseline=operation.schema?.opts?.__certXOriginal===true;
      if(operation.schema?.opts?.__certXOriginal) {
        delete operation.schema.opts.__certXOriginal;
        if(context.account) {
          const schema=operation.schema, accountHeaders=headers(context.account.headers);
          const replaced=new Set(['cookie','authorization',...accountHeaders.map(h=>h.name.toLowerCase())]);
          schema.request.headers=headers(schema.request.headers).filter(h=>!replaced.has(h.name.toLowerCase())).concat(accountHeaders);
          if(context.account.cookie)schema.request.headers.push({name:'Cookie',value:context.account.cookie});
          schema.request.cookies=[];
          ptk_request.updateRawRequest(schema,null,schema.opts);
        }
      }
      const request=new ptk_request();request.useListeners=operation.transport?.useListeners===true;request.trackWithListeners=operation.transport?.trackWithListeners===true;
      request.isolatedRedirectSession=true;request.isolatedPreserveRawHeaders=operation.transport?.isolatedPreserveRawHeaders===true;
      request.certXContext={...context,checkRequest:admitted=>context.checkRequest?.({...admitted,kind:dastBaseline?'dast_baseline':'dast_probe'})};
      if(context.account)operation.schema.opts={...operation.schema.opts,credentials:'omit'};
      const dispatch=()=>request.sendRequest(operation.schema);
      return context.withRequest?context.withRequest(operation.schema.request,dispatch):dispatch();
    }
    if(operation.type==='browser_call') {
      if(!context)throw Error('Security browser context is unavailable.');
      if(operation.method==='tabs.create'&&/^https?:/.test(operation.args?.[0]?.url||'')) {
        const original=operation.args[0];await context.checkRequest?.({url:original.url,method:'GET',kind:'dast_probe'});
        const tab=await nativePrivileged({...operation,args:[{...original,url:'about:blank'}]});
        captureOwners.set(tab.id,context.owner);captureContexts.set(tab.id,context);
        try {await helperScopes.admit(tab.id,context);await browser.tabs.update(tab.id,{url:original.url});return {...tab,url:original.url};}
        catch(error){await browser.tabs.remove(tab.id).catch(()=>{});await helperScopes.release(tab.id).catch(()=>{});throw error;}
      }
      if(operation.method==='windows.create'&&/^https?:/.test(operation.args?.[0]?.url||'')) {
        const original=operation.args[0];await context.checkRequest?.({url:original.url,method:'GET',kind:'dast_probe'});
        const window=await nativePrivileged({...operation,args:[{...original,url:'about:blank'}]});
        for(const tab of window.tabs||[]){captureOwners.set(tab.id,context.owner);captureContexts.set(tab.id,context);await helperScopes.admit(tab.id,context);await browser.tabs.update(tab.id,{url:original.url});}
        return window;
      }
      if(operation.method==='dast.h2.fetch') {
        if(context.account)throw Error('HTTP/2 browser helper cannot represent a saved account snapshot.');
        const request=operation.args?.[0]||{};
        const dispatch=async()=>{await context.checkRequest?.({url:request.url,method:request.method||'GET',kind:'dast_probe'});
          const result=await nativePrivileged({...operation,args:[{...request,followRedirect:false},...(operation.args||[]).slice(1)]});
          if(request.followRedirect!==false&&[301,302,303,307,308].includes(Number(result?.response?.statusCode)))throw Error('HTTP/2 browser helper redirect requires scoped HTTP replay; no redirect was followed.');
          return result;
        };
        return context.withRequest?context.withRequest(request,dispatch):dispatch();
      }
      if(operation.method==='dast.tabs.navigateAndWait')await context.checkRequest?.({url:operation.args?.[1],method:'GET',kind:'dast_probe'});
      if(operation.method==='dast.tabs.reloadAndWait'){const target=await browser.tabs.get(operation.args?.[0]);await context.checkRequest?.({url:target.url,method:'GET',kind:'dast_probe'});}
      const a=operation.args||[],url=operation.method==='tabs.update'?a[1]?.url:operation.method==='tabs.create'?a[0]?.url:null;
      if(url&&/^https?:/.test(url))await context?.checkRequest?.({url,method:'GET',kind:'dast_probe'});
      if(operation.method==='tabs.reload') {const tab=await browser.tabs.get(a[0]);await context?.checkRequest?.({url:tab.url,method:'GET',kind:'dast_probe'});}
      const result=await nativePrivileged(operation);
      if(result?.id&&operation.method==='tabs.create'&&context){captureOwners.set(result.id,context.owner);captureContexts.set(result.id,context);await helperScopes.admit(result.id,context);}
      if(operation.method==='windows.create')for(const tab of result?.tabs||[]){captureOwners.set(tab.id,context.owner);captureContexts.set(tab.id,context);await helperScopes.admit(tab.id,context);}
      return result;
    }
    const result=await nativePrivileged(operation);
    if(operation.type==='browser_cleanup')await helperScopes.releaseRun(context||{});
    return result;
  };
  if(app.dast.candidateRunService)app.dast.candidateRunService.startWorkflowReplay=payload=>app.recorder.msg_replay(payload);
  browser.tabs.onUpdated.addListener((tabId,change,tab)=>{
    const context=captureContexts.get(tabId),url=change.url||tab.url;
    if(!context||!url||url==='about:blank'||scopeAllows(url,context.scope))return;
    captureOwners.delete(tabId);manualCaptures.delete(tabId);captureContexts.delete(tabId);
    for(const session of app.automation.sessions.values())if(session.tabId===tabId&&ACTIVE.has(session.status)){
      session.scopeWarning='Target left the configured scope.';
      app.automation.msg_session_end({options:{sessionId:session.id,sessionScope:'current-tab'},wait:false},senderFor(session)).catch(()=>{});
    }
  });
  browser.tabs.onRemoved.addListener(tabId=>{captureOwners.delete(tabId);captureContexts.delete(tabId);helperScopes.release(tabId).catch(()=>{});});
  function assertIdle() {if(globalThis.certXSecurityCompatibility?.isBusy?.())throw admissionError('A legacy comparison or targeted test is using the security runtime.');}
  function assertOwner(context, allowAborted = false) {if(typeof context?.owner!=='string'||!context.owner)throw Error('Security operations require a chat owner.');if(!allowAborted)context.signal?.throwIfAborted();}
  function sessionFor(args,context) {
    const id=args.sessionId||args.scanId||args.id;
    const value=app.automation.sessions.get(id);
    if(!value||contexts.get(id)?.owner!==context.owner)throw Error('Security scan is unavailable or belongs to another chat.');
    return value;
  }
  function senderFor(session) {return {id:browser.runtime.id,url:session.pageUrl,frameId:0,tab:{id:session.tabId,url:session.pageUrl}};}
  function optionsFor(session,extra={}) {return {sessionId:session.id,sessionScope:'current-tab',...extra};}
  function nativeResults(session) {
    const results=[];
    for(const engine of session.engines) {
      let scanId=session.scanIds?.[engine];
      if(!scanId&&reservations.get(engine)===session.id){scanId=app.automation.engines.getAdapter(engine)?.getScanId?.();if(scanId)session.scanIds[engine]=scanId;}
      const current=scanId?resultsRegistry.get(engine,scanId):null;
      const saved=retainedResults.get(session.id)?.[engine];
      const scan=current||saved;
      if(scan)results.push({engine,scanId,scan});
    }
    return results;
  }
  function snapshotResults(session) {const saved={};for(const value of nativeResults(session))saved[value.engine]=clone(value.scan);retainedResults.set(session.id,saved);}
  function release(session) {
    snapshotResults(session);
    for(const engine of session.engines)if(reservations.get(engine)===session.id)reservations.delete(engine);
    if(globalThis.__certXSecurityDastContext===contexts.get(session.id))globalThis.__certXSecurityDastContext=null;
  }
  async function status(session) {
    const value=readProgressResponse(await app.automation.msg_get_session_progress({options:optionsFor(session)},senderFor(session)));
    const snapshot=app.automation.getSessionProgressSnapshot(session.id);
    if(!ACTIVE.has(snapshot?.status||session.status))release(session);
    const native=nativeResults(session).find(item=>item.engine==='DAST')?.scan;
    await supplementalBackends.offer(session.id,{url:session.pageUrl,requests:native?.requests||[],candidates:native?.analysis?.candidates||[]});
    const supplemental=await supplementalBackends.status(session.id),active=Object.values(supplemental?.backends||{}).some(item=>['monitoring','running','scanning','starting'].includes(item.state||item.status));
    const iastDocuments=nativeResults(session).find(item=>item.engine==='IAST')?.scan?.certXDocumentCoverage;
    const sca=nativeResults(session).find(item=>item.engine==='SCA')?.scan;
    const sast=nativeResults(session).find(item=>item.engine==='SAST')?.scan;
    const sastCoverage=sast?{basis:'Acquired client-side JavaScript and HTML/DOM only; server-side application source is not available through browser SAST.',acquisition:clone(sast.sastAcquisition||null),analysisAcquisition:clone(sast.sastAnalysisAcquisition||null),preloaded:clone(sast.sastPreloadedCoverage||null),preloadedAcquisition:clone(sast.sastPreloadedAcquisition||null),sourceWarnings:clone((sast.sastSourceWarnings||[]).slice(0,50))}:null;
    const scaBodies=sca?{captured:0,analyzed:0,gaps:0,...clone(sca.scaBodyCoverage||{}),basis:'Admitted JavaScript resources observed during this scan; URI detections do not prove body analysis.'}:null;
    const scaSources=sca?{captured:0,analyzed:0,gaps:0,...clone(sca.scaSourceCoverage||{}),basis:'Executable Debugger script text, not a claim of HTTP-byte identity.'}:null;
    const scaAcquisition=sca?{phase:(scaBodies.analyzed+scaSources.analyzed)>0?(scaBodies.gaps+scaSources.gaps>0?'partial':'observed_content_analyzed'):ACTIVE.has(snapshot?.status||session.status)?'waiting_for_resources':'no_content_analyzed',limits:clone(sca.scaAcquisitionLimits||null),drain:clone(sca.scaDrain||null)}:null;
    return {sessionId:session.id,scanId:session.id,...clone(snapshot),...clone(value),...(supplemental?{supplemental}:{}),coverage:{...value.coverage,...(supplemental?{backendGaps:supplemental.gaps}:{}),...(sastCoverage?{sast:sastCoverage}:{}),...(iastDocuments?{iastDocuments:clone(iastDocuments)}:{}),...(scaBodies?{scaBodies,scaSources,scaAcquisition,scaBodyWarnings:clone((sca.coverageWarnings||[]).slice(-50))}:{})},...(active?{status:'running'}:{})};
  }
  async function startScan(args,context) {
    assertIdle();const tab=await browser.tabs.get(args.tabId??context.tabId);
    if(!/^https?:/.test(tab.url||''))throw admissionError('Choose an HTTP or HTTPS target.');
    if(!scopeAllows(tab.url,context.scope))throw admissionError('Target is outside run scope: '+tab.url+'. Review target scope in Workspace settings.');

    const engines=[...new Set((args.engines||['DAST','IAST','SAST','SCA']).map(x=>String(x).toUpperCase()))];
    if(!engines.length||engines.some(x=>!['DAST','IAST','SAST','SCA'].includes(x)))throw admissionError('Unknown security engine.');
    if((args.accountId||context.accountId)&&!context.account)throw admissionError('Account snapshot was not resolved.');
    if(context.account&&engines.some(x=>x!=='DAST'))throw admissionError('Saved account snapshots support request-based DAST only; browser instrumentation needs a prepared matching browser session.');
    if(engines.some(x=>reservations.has(x)))throw admissionError('A selected engine is already running; stop it or wait for it to complete.');
    if(captureOwners.has(tab.id)&&captureOwners.get(tab.id)!==context.owner&&isCaptureActive(tab.id))throw admissionError('The target tab is owned by another security session.');
    const token=Symbol('start');for(const e of engines)reservations.set(e,token);
    claimCapture(tab.id,context);
    const config={...context.config,...args.config,...args.options};
    // Service-resolved acquisition includes inherited defaults and user ceilings.
    // A partial raw options object must never replace that admission decision.
    config.acquisition={...args.options?.acquisition,...args.config?.acquisition,...context.config?.acquisition};
    config.safetyProfile=config.safetyProfile||config.scanControlProfile;
    if(config.safetyProfile)config.scanControls={profile:config.safetyProfile,...config.scanControls};
    if(engines.includes('DAST'))globalThis.__certXSecurityDastContext=context;
    if(engines.includes('SCA'))app.sca.certXContext=context;
    try {
      const perEngine={...config.engineOptions,...args.engineConfigs};
      const engineConfigs={DAST:{...config,...perEngine.DAST,domains:(context.scope?.origins||[]).map(url=>new URL(url).hostname).join(',')},SAST:{...perEngine.SAST,acquisition:clone(config.acquisition||{})},IAST:{...perEngine.IAST},SCA:{...perEngine.SCA,acquisition:clone(config.acquisition||{})}};
      for(const engine of engines) {
        const settings=engineConfigs[engine],selected=settings.moduleIds||settings.modules||config.moduleIds||config.modules,excluded=settings.excludeModules||config.excludeModules||[];
        if(!selected&&!excluded.length)continue;
        if(selected&&!Array.isArray(selected))throw Error('Module selection must be an array of module IDs.');
        if(!['DAST','SAST','IAST'].includes(engine))continue;
        const load=async file=>{const response=await fetch(browser.runtime.getURL('security/ptk/background/'+engine.toLowerCase()+'/modules/'+file));if(!response.ok)throw Error('Module inventory file is missing');return response.json();};
        const select=pack=>({...pack,modules:pack.modules.filter(module=>(!selected||selected.includes(module.id))&&!excluded.includes(module.id))});
        settings.rulepack=select(settings.rulepack||await load('modules.json'));
        if(engine==='DAST')settings.cveRulepack=select(settings.cveRulepack||await load('modules_cve.json'));
      }
      // This private one-use grant follows cert-x permission, scope and resource admission.
      // The imported page-automation listener is not installed or externally callable.
      app.automation._createManualAutomationBootstrapGrant(tab.id,{reason:'cert_x_native_admission',url:tab.url});
      const result=assertSuccess(await app.automation.msg_session_start({pageUrl:tab.url,options:{engines,runCve:config.runCve!==false,policyCode:config.scanStrategy||config.dastScanStrategy||'COMPREHENSIVE',engineConfigs}}, {id:browser.runtime.id,frameId:0,url:tab.url,tab}));
      const session=app.automation.sessions.get(result.sessionId);if(!session)throw Error('Engine did not create a scan session.');
      contexts.set(session.id,context);for(const e of engines)reservations.set(e,session.id);
      const failures=Object.entries(session.engineStates||{}).filter(([,s])=>s.status==='error');
      if(failures.length===engines.length)throw Error(failures.map(([e,s])=>e+': '+s.error).join('; '));
      const native=nativeResults(session).find(item=>item.engine==='DAST')?.scan;
      const supplemental=await supplementalBackends.begin(session.id,args,context,{url:tab.url,requests:native?.requests||args.requests||[],candidates:native?.analysis?.candidates||[]});
      return {...result,scanId:session.id,engineStatus:clone(session.engineStates),supplemental,warnings:failures.map(([e,s])=>e+': '+s.error)};
    } catch(error) {for(const e of engines)if(reservations.get(e)===token)reservations.delete(e);if(globalThis.__certXSecurityDastContext===context)globalThis.__certXSecurityDastContext=null;throw error;}
  }
  async function replay(args,context) {
    assertIdle();const input=args.request||args;
    if(args.accountId&&!args.account&&!context.account)throw admissionError('Account snapshot was not resolved.');
    const account=args.account||context.account;
    const headerList=headers(input.headers);
    if(account){for(const name of ['cookie','authorization']){for(let i=headerList.length-1;i>=0;i--)if(headerList[i].name.toLowerCase()===name)headerList.splice(i,1);}headerList.push(...headers(account.headers));if(account.cookie)headerList.push({name:'Cookie',value:account.cookie});}
    const url=new URL(input.url);const method=String(input.method||'GET').toUpperCase();
    const raw=typeof input.raw==='string'?input.raw:`${method} ${url.href} HTTP/1.1\r\nHost: ${url.host}\r\n${headerList.map(x=>x.name+': '+x.value+'\r\n').join('')}\r\n${input.body??''}`;
    const schema=ptk_request.parseRawRequest(raw,{...app.settings.rbuilder,...args.options});schema.request.url=url.href;
    const request=new ptk_request();request.certXContext=context;request.isolatedRedirectSession=true;
    if(account)schema.opts.credentials='omit';
    const dispatch=()=>request.sendRequest(schema);
    return context.withRequest?context.withRequest(schema.request,dispatch):dispatch();
  }
  const apiOperations=createApiOperations({replay});
  const supplementalBackends=createSupplementalBackends();
  const candidateWorkflows=createCandidateWorkflows({replay,macro:(args,context)=>invoke('macro',args,context)});
  async function invoke(operation,args={},context={}) {
    assertOwner(context,operation==='stopScan'||['stop','close','cleanup','cancelJob'].includes(args.action));await app.ready;
    if(!OPERATIONS.includes(operation))throw Error('Unknown security operation: '+operation);
    if(operation==='api')return apiOperations.invoke(args,context);
    if(operation==='candidate'||operation==='evidencePackage'){
      let primary;try{const session=sessionFor(args,context),results=nativeResults(session);primary=results.find(item=>item.engine==='DAST')||results[0];}catch(error){if(!context.sourceRun?.runId||context.sourceRun.owner!==context.owner)throw error;}
      const recording=macroOwner===context.owner?app.recorder.recording:macroRecords.get(context.owner)?.recording;
      return candidateWorkflows.invoke(operation,args,context,primary?.scan,recording);
    }
    if(['browser','raw','oast','zap'].includes(operation)){
      if(typeof context.localExecute!=='function')throw Error('The local security executor is not connected.');
      const supported={browser:['create','list','status','navigate','inspect','interact','screenshot','login','capture','verify','reopen','close','import','export','readArtifact','runCandidate','getJob','cancelJob'],raw:['http1','http2','websocket','desync','evidence'],oast:['create','status','events','probe','wait','stop','cleanup','export'],zap:['status','start','progress','stop','findings','evidence']};
      if(!supported[operation].includes(args.action))throw Error('Unknown '+operation+' action.');
      const input=operation==='browser'&&args.action==='interact'?{...args,action:args.interaction}:args;
      const dispatch=()=>context.localExecute((operation==='raw'?'transport':operation)+'.'+args.action,input);
      const result=operation==='raw'&&args.action!=='evidence'&&context.withRequest?await context.withRequest({kind:'raw_operation'},dispatch):await dispatch();
      return {...result,...(['monitoring','queued','running','scanning','open'].includes(result?.state||result?.status)?{persistent:true}:{})};
    }
    if(operation==='startScan')return startScan(args,context);
    if(['scanStatus','stopScan','getFindings','getEvidence','exportFullReport','export'].includes(operation)) {
      const session=sessionFor(args,context);
      if(operation==='scanStatus')return status(session);
      if(operation==='stopScan') {const supplemental=await supplementalBackends.stop(session.id,context);const value=assertSuccess(await app.automation.msg_session_end({options:optionsFor(session,args.options),wait:args.wait!==false},senderFor(session)));if(!ACTIVE.has(session.status))release(session);const pending=Object.values(supplemental?.backends||{}).some(item=>['monitoring','running','scanning','starting'].includes(item.state||item.status));return {...clone(value),supplemental,sessionId:session.id,status:pending?'stopping':session.status};}
      if(operation==='getFindings'||operation==='getEvidence') {
        const all=[];
        for(const {engine,scanId,scan} of nativeResults(session))for(const finding of scan.findings||[]) {
          all.push({...clone(finding),...(finding.evidence?.dast?.meta?.executed===false&&finding.evidence?.dast?.meta?.reflected===true?{classification:'observation',executionObserved:false}:finding.evidence?.dast?.meta?.executed===true?{classification:'execution_observed',executionObserved:true}:{}),id:finding.id||finding.findingId,title:finding.title||finding.name||finding.ruleName||finding.moduleName||finding.ruleId||finding.moduleId,engine,scanId});
        }
        const supplemental=await supplementalBackends.evidence(session.id);
        for(const event of Array.isArray(supplemental?.backends?.oast?.events)?supplemental.backends.oast.events:[])if(event.confirmation==='callback_observed')all.push({id:'oast:'+String(event.id||event.eventId),engine:'OAST',classification:'callback_observed',title:'Out-of-band callback observed',evidence:clone(event),impactConfirmed:false});
        const zap=supplemental?.backends?.zap?.findings;for(const finding of zap?.findings||zap?.alerts||[])all.push({...clone(finding),id:'zap:'+String(finding.id||finding.pluginId),engine:'ZAP'});
        const evidenceId=args.evidenceId||args.findingId;
        const selected=evidenceId?all.filter(f=>f.id===evidenceId):all;
        if(evidenceId&&!selected.length)throw Error('Evidence identifier was not found in this scan.');
        const offset=Math.max(0,Number(args.offset)||0),limit=Math.max(1,Math.min(1000,Number(args.limit)||100));
        const iastDocuments=nativeResults(session).find(item=>item.engine==='IAST')?.scan?.certXDocumentCoverage;
        return {sessionId:session.id,...(evidenceId?{finding:selected[0]}:{}),findings:selected.slice(offset,offset+limit),total:selected.length,nextOffset:offset+limit<selected.length?offset+limit:null,truncated:false,...(iastDocuments?{iastDocuments:clone(iastDocuments)}:{}),...(operation==='getEvidence'?{supplemental}:{})};
      }
      // Session IDs are fixed; never substitute the latest scan from another owner.
      const reports=[];for(const engine of session.engines){const id=session.scanIds?.[engine];if(!id)continue;const result=await app.automation._buildEngineExport(engine,id,session,args.options||{});reports.push({engine,data:result.scan,truncated:result.truncated});}
      if(args.format&&args.format!=='json'){
        if(!['pdf','markdown'].includes(args.format))throw Error('Unsupported report format.');
        await app.offscreenRuntimeManager.ensureDocument();
        const report={sessionId:session.id,reports,run:clone(context.reportRun)};
        const safeReport=context.transformReport?await context.transformReport(report):report;
        const rendered=assertSuccess(await browser.runtime.sendMessage({channel:'CERT_X_SECURITY_DOM',action:'report',args:{reports:safeReport.reports,format:args.format,options:args.options||{},meta:{run:safeReport.run,host:session.host,generatedAt:new Date().toISOString(),startTime:session.startedAt,endTime:session.finishedAt,scope:context.scope?.origins?.join(', ')||session.host,version:'PTK 10.0.0 / cert-x maintained runtime'}}}));
        return {sessionId:session.id,reports,artifact:rendered.artifact};
      }
      return {sessionId:session.id,reports,supplemental:await supplementalBackends.evidence(session.id)};
    }
    if(operation==='capture'||operation==='listRequests') {
      const tabId=args.tabId??context.tabId;
      if(!Number.isInteger(tabId))throw Error('Choose a target tab.');
      if(captureOwners.has(tabId)&&captureOwners.get(tabId)!==context.owner&&!(operation==='capture'&&args.action==='start'&&!isCaptureActive(tabId)))throw Error('Captured requests belong to another chat.');
      if(operation==='capture'){if(args.action==='status')return {active:manualCaptures.get(tabId)===context.owner,tabId};if(args.action==='stop'){manualCaptures.delete(tabId);return {active:false,tabId};}const target=await browser.tabs.get(tabId);if(!scopeAllows(target.url,context.scope))throw Error('Capture target is outside run scope: '+target.url+'. Review target scope in Workspace settings.');claimCapture(tabId,context);manualCaptures.set(tabId,context.owner);await app.proxy.ensureActiveTabContext({tabId});return {active:true,tabId};}
      if(!captureOwners.has(tabId))throw Error('Start capture for this tab first.');
      const tab=app.proxy.getTab(tabId),requests=[];for(const [frameId,frame] of tab?.frames||[])for(const [requestId]of frame){const value=app.proxy.getRequestDetails(tab,frameId,requestId);requests.push({requestId,frameId,...clone(value)});}
      const offset=Math.max(0,Number(args.offset)||0),limit=Math.max(1,Math.min(1000,Number(args.limit)||100));return {requests:requests.slice(offset,offset+limit),total:requests.length,nextOffset:offset+limit<requests.length?offset+limit:null};
    }
    if(operation==='replay')return replay(args,context);
    if(operation==='macro'||operation==='import') {
      const action=operation==='import'?'import':args.action;
      if(macroOwner&&macroOwner!==context.owner&&action!=='import'){
        if(app.recorder.mode)throw Error('The recorder is owned by another chat.');
        if(['record','replay'].includes(action))app.recorder.reset();
        else if(action==='list'||action==='status')return clone(macroRecords.get(context.owner)||{mode:null,recording:null,replayResult:null});
        else if(action==='export'){const saved=macroRecords.get(context.owner)?.recording;if(!saved)throw Error('No recording belongs to this chat.');return {success:true,result:new ptk_exporter(saved,{...app.settings.macro,...args.options,format:args.format||'xml',export_format:args.format||'xml'}).render()};}
        else throw Error('No active recorder belongs to this chat.');
      }
      if(action==='import') {
        if(['ptk-report','ptk-report-gzip'].includes(args.format)) {
          const bytes=args.bytes||Array.from(new TextEncoder().encode(typeof args.data==='string'?args.data:JSON.stringify(args.data)));
          const parsed=await parseUploadedScanFile({bytes,name:args.fileName||(args.format==='ptk-report-gzip'?'scan.json.gz':'scan.json')},args.options);
          if(parsed.ok!==true)throw Error(parsed.parseError||'Report data could not be parsed.');
          return clone(parsed);
        }
        return clone(new ptk_importer(app.settings.macro).parseDocument(args.data||args.text,{format:args.format,fileName:args.fileName}));
      }
      if(action==='record'){
        assertIdle();await context.checkRequest?.({url:args.url,method:'GET',kind:'navigation'});macroOwner=context.owner;
        const tabId=args.tabId??context.tabId;
        const result=assertSuccess(await app.recorder.msg_start_recording({url:args.url,clean_cookie:false,bootstrap:{certXAdmitted:true,targetTabId:tabId}}));
        const deadline=Date.now()+15000;
        try {
          while(Date.now()<deadline){context.signal?.throwIfAborted();const tab=await browser.tabs.get(tabId);
            if(tab.status==='complete') {
              const readiness=await browser.scripting.executeScript({target:{tabId},world:'ISOLATED',func:sessionId=>window.ptk_recorder?.sessionId===sessionId&&window.ptk_recorder?.certXReady===true,args:[app.recorder.sessionId]}).catch(()=>[]);
              if(readiness.some(item=>item.result===true))return {...result,ready:true,tabId,recordingSessionId:app.recorder.sessionId};
            }
            await new Promise(resolve=>setTimeout(resolve,50));
          }
          throw Error('Recording listeners did not become ready.');
        }catch(error){await app.recorder.msg_stop_recording({}).catch(()=>{});throw error;}
      }
      if(action==='stop'){
        if(app.recorder.mode==='recording'&&Number.isInteger(app.recorder.openerTabId))await browser.scripting.executeScript({target:{tabId:app.recorder.openerTabId,allFrames:true},world:'ISOLATED',func:async()=>{
          const recorder=window.ptk_recorder;if(!recorder)return;
          recorder.certXReady=false;recorder.stop();
          for(const key of recorder._pendingScrolls?.keys?.()||[])recorder.flushScroll(key);
          await recorder.testcase?.pendingWrite;
          await recorder.testcase?.sync();
        }}).catch(()=>{});
        const result=app.recorder.mode==='replay'?await app.recorder.msg_stop_replay({}):await app.recorder.msg_stop_recording({});const record={mode:app.recorder.mode,recording:clone(app.recorder.recording),replayResult:clone(app.recorder.replayResult)};macroRecords.set(context.owner,record);return {...assertSuccess(result),...record};}
      if(action==='list'||action==='status')return {mode:app.recorder.mode,replayResult:clone(app.recorder.replayResult),recording:clone(app.recorder.recording)};
      if(action==='export')return assertSuccess(await app.recorder.msg_export_recording({settings:{...app.settings.macro,...args.options,format:args.format||'xml',export_format:args.format||'xml'}}));
      if(action==='replay'){
        assertIdle();let events=args.events,url=args.url;
        let flow=args.flow;
        if(args.data)flow=new ptk_importer(app.settings.macro).parseDocument(args.data,{format:args.format||'auto'}).flow;
        if(flow){const compiled=compileFlow(flow,{secrets:args.secrets||{},variables:args.variables||{},elementPath:'css'});events=compiled.events;url=url||compiled.startUrl;}
        if(!Array.isArray(events))throw Error('Provide a flow, imported macro data, or compiled replay events.');
        await context.checkRequest?.({url,method:'GET',kind:'navigation'});macroOwner=context.owner;
        return assertSuccess(await app.recorder.msg_replay({...args,url,events,clean_cookie:false,target_tab_id:args.tabId??context.tabId,scope_origin:new URL(url).origin,suppress_confirmation:true,scan_owned:true,source:'cert-x'}));
      }
      throw Error('Unknown macro action.');
    }
    if(operation==='utility') {
      if(args.tool==='decoder'||args.tool==='encode'||args.tool==='decode'){const decoder=new ptk_decoder(),action=args.action||args.tool,method=String(args.method||'base64')+'_'+action;if(!['encode','decode'].includes(action)||typeof decoder[method]!=='function')throw Error('Unsupported codec operation.');return {result:decoder[method](String(args.text??''))};}
      if(args.tool==='cookies'||args.tool==='session')return cookiePolicies.invoke(args,context);
      if(args.tool==='openapi'){if(args.action&&args.action!=='parse')throw Error('OpenAPI supports parse; use scoped request replay to execute selected operations.');const spec=parseSpec(args.data||args.text,args.fileName||'',args.contentType||'');return {spec,summary:specSummary(spec),operations:describeOperations(spec),note:'External references are retained as references and are not fetched automatically.'};}
      if(args.tool==='api_explorer'){const session=sessionFor(args,context);return {engines:nativeResults(session).map(({engine,scan})=>({engine,explorer:buildApiExplorer(scan)}))};}
      if(args.tool==='jwt'){if(args.action==='decode'||!args.action)return {header:jose.decodeProtectedHeader(args.token),claims:jose.decodeJwt(args.token)};if(args.action==='verify')return jose.jwtVerify(args.token,new TextEncoder().encode(args.secret||''),args.options);if(args.action==='confusion')return {tokens:await new ptk_jwtHelper().generateConfusionAttacks(args.header,args.payload,args.secret||'')};if(args.action==='sign')return {token:await new ptk_jwtHelper().signToken(typeof args.header==='string'?args.header:JSON.stringify(args.header||{alg:'HS256',typ:'JWT'}),typeof args.payload==='string'?args.payload:JSON.stringify(args.payload||{}),args.secret||'',args.keys||{})};if(args.action==='bruteforce')return app.jwt.bruteforce(args.token,{words:args.words,signal:context.signal,notify:false});throw Error('Unsupported JWT operation.');}
      if(args.tool==='recon') {
        const tabId=args.tabId??context.tabId;if(captureOwners.get(tabId)!==context.owner)throw Error('Start capture before reconnaissance.');
        const target=await browser.tabs.get(tabId),tab=app.proxy.getTab(tabId);
        if(!tab)return {tabId,url:target.url,technologies:[],findings:[],coverage:{capturedRequests:0}};
        const view=Object.create(app.dashboard);view.activeTab={tabId,url:target.url};view.tab={tabId,url:target.url};view.headerAnalysisCache=new Map();view.tabAnalysisCache=new Map();
        const capture=await tab.analyze(),analysis=await view.runHeaderAnalysis(tab);
        view.tab={...capture,tabId,url:target.url};view.certXPrivateResult=true;
        let domComplete=false,domError=null;
        const analyze=async()=>{
          await app.automation._executeContentRuntimeFiles({tabId,frameId:0,files:['security/ptk/content_manual.js']});
          await browser.scripting.executeScript({target:{tabId},world:'MAIN',files:['security/ptk/inject.js']});
          await browser.scripting.executeScript({target:{tabId},world:'ISOLATED',func:()=>{window.__CERT_X_TECH_BRIDGE_INSTALLED__=true;}});
          await app.dashboard.ensureAnalysisRulesReady();
          const requestId=crypto.randomUUID();let timer;
          const observed=new Promise((resolve,reject)=>{pendingRecon.set(tabId,{requestId,context,resolve});timer=setTimeout(()=>reject(Error('DOM technology capture timed out')),5000);});
          try {
            await browser.tabs.sendMessage(tabId,{channel:'ptk_background2content',type:'init',requestId,dom:app.dashboard.wappalyzerDomRules||[],js:[...(app.dashboard.wappalyzerJsRules||[]),...(app.dashboard.cveJsRules||[])],css:app.dashboard.wappalyzerCssRules||[],html:{technologies:app.dashboard.wappalyzerHtmlPlan||[],waf:app.dashboard.wappalyzerWafHtmlPlan||[],cve:app.dashboard.cveHtmlPlan||[]}});
            const info=await observed;await view.analyzeTab({info});domComplete=true;
          }finally{clearTimeout(timer);pendingRecon.delete(tabId);observed.catch(()=>{});}
        };
        const analysisTask=reconQueue.catch(()=>{}).then(analyze);reconQueue=analysisTask;
        try{await analysisTask;}catch(error){domError=error.message;}
        return {tabId,url:target.url,domains:clone(capture.domains||[]),technologies:clone(view.tab.technologies||analysis.techHeaderMatches||[]),waf:clone(view.tab.waf||[]),cves:clone(view.tab.cves||analysis.cveHeaderMatches||[]),findings:clone(analysis.securityFindings||[]),evidence:clone(analysis.evidence),coverage:{source:domComplete?'headers_dom_javascript':'captured_headers',domComplete,...(domError?{warning:domError}:{})}};
      }
      if(args.tool==='portscan') {
        if(typeof args.host!=='string'||!args.host||/[\s\/\\@?#]/.test(args.host)||!Array.isArray(args.ports)||!args.ports.length||args.ports.some(p=>!Number.isInteger(p)||p<1||p>65535))throw Error('Provide a hostname and valid TCP port numbers.');
        if(args.samples!=null&&(!Number.isSafeInteger(args.samples)||args.samples<1))throw Error('Samples must be a positive integer.');
        const token=crypto.randomUUID();domJobs.set(token,context);
        const abort=()=>browser.runtime.sendMessage({channel:'CERT_X_SECURITY_DOM',action:'cancel',token}).catch(()=>{});
        context.signal?.addEventListener('abort',abort,{once:true});
        try {const dispatch=async()=>{await app.offscreenRuntimeManager.ensureDocument();context.signal?.throwIfAborted();return assertSuccess(await browser.runtime.sendMessage({channel:'CERT_X_SECURITY_DOM',action:'portscan',token,args}));};return await (context.withRequest?context.withRequest({kind:'port_probe'},dispatch):dispatch());}
        finally{domJobs.delete(token);context.signal?.removeEventListener('abort',abort);}
      }
      throw Error('Unknown security utility.');
    }
  }
  return {app,cookiePolicies,ready:app.ready,recoverInterrupted:async({sessionId},context)=>{assertOwner(context,true);await app.ready;return clone(interruptedResults.get(sessionId)||null);},describe:()=>({version:'10.0.0',operations:OPERATIONS.slice(),operationArguments:OPERATION_SCHEMAS,...clone(manifest),accountReferences:{DAST:true,replay:true,browserInstrumentation:false},transport:{backend:'browser',http:true,rawHttp:false,http2HelperRedirects:false,webSocketFrames:false,serverSideOast:false,managed:{requires:'enabled local access and host security_raw_v2',rawHttp:true,http2:{structured:true,frames:true,structuredBodyWindow:65535,dynamicFlowControl:false},webSocketFrames:true,validatedUpgrade:true,desync:{explicitOptIn:true,pairedControls:true,modes:['backend_observation','response_queue']},evidencePagination:true,unsupported:['opaque HTTP/1 routing','bare-LF boundaries','HTTP/2 CONNECT','PUSH_PROMISE','unknown HTTP/2 extension frames']}},engineConcurrency:'One active instance per engine; independent utilities and replay use their own contexts.'}),invoke,isBusy:()=>reservations.size>0||!!app.recorder.mode};
}

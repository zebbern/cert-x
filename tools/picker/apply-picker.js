const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..", "..");
const original = path.join(__dirname, "original");
const jsName = "chunks/sidepanel-CUbsl7eV.js";
const cssName = "assets/sidepanel-DD7JAQkM.css";
const kiTools = require("./src/ki-tools");
const kiProviderCompat = fs.readFileSync(path.join(__dirname,'src/ki-provider-compat.js'),'utf8');
const securityBuildFingerprint = require('node:crypto').createHash('sha256').update(['tools/picker/src/ki-security.js','tools/picker/src/ki-context.js','tools/picker/src/ki-provider-compat.js','tools/picker/src/ki-upload.js','security/config.mjs','security/service.mjs','security/runtime.mjs','security/engine/coverage.mjs','security/engine/operation-arguments.mjs','security/ptk/background/automation.js','security/ptk/background/dast/dastEngine.js','security/ptk/background/sast.js','security/skills/security-testing.md'].map(file => fs.readFileSync(path.join(root,file),'utf8')).join('\n')).digest('hex');
require('node:child_process').execFileSync(process.execPath, [path.join(root, 'tools/security/validate.mjs')], { stdio: 'inherit', windowsHide: true });

function once(src, needle) {
  const first = src.indexOf(needle);
  if (first < 0) throw new Error("anchor not found: " + needle.slice(0, 80));
  if (src.indexOf(needle, first + 1) >= 0) throw new Error("anchor not unique: " + needle.slice(0, 80));
  return first;
}

function swap(src, needle, replacement) {
  const at = once(src, needle);
  return src.slice(0, at) + replacement + src.slice(at + needle.length);
}

// A name bound twice in a bundle's top scope silently replaces the other binding
// (scope-check.mjs); refuse to write such a bundle.
function checkScope(src, name, ...flags) {
  try { require("node:child_process").execFileSync(process.execPath, [path.join(__dirname, "scope-check.mjs"), ...flags], { input: src, stdio: ["pipe", "inherit", "inherit"], windowsHide: true }); }
  catch (e) {
    if (e.status === 1) throw new Error(name + ": a name is bound twice in its top scope (listed above); rename the added binding");
    throw new Error(name + ": the scope check did not run (" + (e.status === 2 ? "parse failure, above" : e.message) + ")");
  }
}

let js = fs.readFileSync(path.join(original, path.basename(jsName)), "utf8");
const components = ["ki-vendor-icons.js", "ki-components.js", "ki-live.js", "ki-settings.js", "ki-context-ui.js", "ki-csp-ui.js", "ki-ptk-ui.js", "ki-dast-ui.js", "ki-outputs.js"].map((f) => fs.readFileSync(path.join(__dirname, "src", f), "utf8").trim()).join("\n");

js = swap(js, "function PI(){", components + "\nfunction PI(){");
js = swap(js, "function PI(){", "function PI(){const[kiSettingsSection,kiSetSettingsSection]=(0,_.useState)(`home`);");

// Dedicated settings destinations; preserve the existing provider editor route.
const modelsGroupStart = once(js, '(0,A.jsxs)(`div`,{className:`wb-set-group`,children:[(0,A.jsx)(`div`,{className:`wb-set-group-label`,children:n===`zh-CN`?`你的模型`:`Your models`})');
const daemonGroupStart = once(js, '(0,A.jsxs)(`div`,{className:`wb-set-group`,children:[(0,A.jsx)(`div`,{className:`wb-set-group-label`,children:v(`settings.groupDaemon`)})');
if (daemonGroupStart <= modelsGroupStart || daemonGroupStart - modelsGroupStart > 1800) throw Error("Unexpected settings group span");
js = js.slice(0, modelsGroupStart) + '(0,A.jsx)(KiContextSettingsEntry,{onOpen:T}),(0,A.jsx)(KiConnectionsSettings,{lang:n,onOpen:T,connected:c}),(0,A.jsx)(KiToolsSettingsEntry,{lang:n,onOpen:T}),' + js.slice(daemonGroupStart);
js = swap(js, 'w===`models`?n===`zh-CN`?`你的模型`:`Your models`:v(`settings.dev.rowLabel`)', 'w===`models`?n===`zh-CN`?`模型`:`Models`:w===`mcp`?n===`zh-CN`?`MCP 服务器`:`MCP servers`:w===`local`?n===`zh-CN`?`本机`:`Local computer`:v(`settings.dev.rowLabel`)');
js = swap(js, 'w===`models`&&(0,A.jsx)(`iframe`,{className:`wb-models-frame`,title:n===`zh-CN`?`你的模型`:`Your models`', '[`models`,`mcp`,`local`].includes(w)&&(0,A.jsx)(`iframe`,{className:`wb-models-frame`,title:He');
js = swap(js, 'providers/providers.html?embed=1&theme=${i===`dark`||i===`light`?i:`system`}', 'providers/providers.html?section=${w}&embed=1&session=${encodeURIComponent(kiSession||``)}&theme=${i===`dark`||i===`light`?i:`system`}');
js = swap(js, 'function wk({connections:e,agentgwMeta:t,language:n,', 'function wk({kiSession,initialSection,connections:e,agentgwMeta:t,language:n,');
js = swap(js, '[w,T]=(0,_.useState)(`home`)', '[w,T]=(0,_.useState)(initialSection||`home`)');
js = swap(js, '(0,A.jsx)(wk,{connections:Gn,', '(0,A.jsx)(wk,{kiSession:Hr,initialSection:kiSettingsSection,connections:Gn,');
js = swap(js, 'Nn=(0,_.useCallback)(()=>{Ht({kind:`composer`}),Ge(!1),An(!1)}', 'Nn=(0,_.useCallback)(()=>{kiSetSettingsSection(`home`);Ht({kind:`composer`}),Ge(!1),An(!1)}');
js = swap(js, ':v(`settings.dev.rowLabel`);return(0,A.jsxs)(`section`', ':v(`settings.dev.rowLabel`);(0,_.useEffect)(()=>{const handler=ev=>{const frame=document.querySelector(`.wb-models-frame`);if(ev.source===frame?.contentWindow&&ev.data?.type===`settings-section`&&[`models`,`mcp`,`local`].includes(ev.data.section))T(ev.data.section)};window.addEventListener(`message`,handler);return()=>window.removeEventListener(`message`,handler)},[T]);return(0,A.jsxs)(`section`');
// Move the old connection/address card out of the settings home entirely.
const oldRemoteStart = once(js, '(0,A.jsxs)(`div`,{className:`wb-set-group`,children:[(0,A.jsx)(`div`,{className:`wb-set-group-label`,children:v(`settings.groupDaemon`)})');
const quickActionsStart = once(js, '(0,A.jsxs)(`div`,{className:`wb-set-group`,children:[(0,A.jsx)(`div`,{className:`wb-set-group-label`,children:v(`settings.groupQuickActions`)})');
if (quickActionsStart <= oldRemoteStart || quickActionsStart - oldRemoteStart > 5000) throw Error("Unexpected remote-control settings span");
js = js.slice(0, oldRemoteStart) + js.slice(quickActionsStart);
js = swap(js, 'w===`local`?n===`zh-CN`?`本机`:`Local computer`:v(`settings.dev.rowLabel`)', 'w===`local`?n===`zh-CN`?`本机`:`Local computer`:w===`browser`?n===`zh-CN`?`浏览器控制`:`Browser control`:v(`settings.dev.rowLabel`)');
js = js.replaceAll('[`models`,`mcp`,`local`]', '[`models`,`mcp`,`local`,`browser`,`tools`,`health`]');
js = swap(js, ':v(`settings.dev.rowLabel`);(0,_.useEffect)', ':w===`tools`?n===`zh-CN`?`工具与权限`:`Tools & permissions`:v(`settings.dev.rowLabel`);(0,_.useEffect)');
js = swap(js, ':v(`settings.dev.rowLabel`);(0,_.useEffect)', ':w===`health`?n===`zh-CN`?`功能状态`:`Capability health`:v(`settings.dev.rowLabel`);(0,_.useEffect)');
js = js.replaceAll('[`models`,`mcp`,`local`,`browser`,`tools`,`health`]', '[`models`,`mcp`,`local`,`browser`,`tools`,`health`,`profiles`,`workspaces`]');
js = swap(js, ':v(`settings.dev.rowLabel`);(0,_.useEffect)', ':w===`profiles`?`Profiles`:w===`workspaces`?`Workspaces`:v(`settings.dev.rowLabel`);(0,_.useEffect)');
js = js.replaceAll('[`models`,`mcp`,`local`,`browser`,`tools`,`health`,`profiles`,`workspaces`]', '[`models`,`mcp`,`local`,`browser`,`tools`,`health`,`profiles`,`workspaces`,`ptk`]');
js = swap(js, ':v(`settings.dev.rowLabel`);(0,_.useEffect)', ':w===`ptk`?`PTK analysis`:v(`settings.dev.rowLabel`);(0,_.useEffect)');
js = js.replaceAll('[`models`,`mcp`,`local`,`browser`,`tools`,`health`,`profiles`,`workspaces`,`ptk`]', '[`models`,`mcp`,`local`,`browser`,`tools`,`health`,`profiles`,`workspaces`,`ptk`,`dast`]');
js = swap(js, ':v(`settings.dev.rowLabel`);(0,_.useEffect)', ':w===`dast`?`Targeted DAST`:v(`settings.dev.rowLabel`);(0,_.useEffect)');
js = js.replaceAll('[`models`,`mcp`,`local`,`browser`,`tools`,`health`,`profiles`,`workspaces`,`ptk`,`dast`]', '[`models`,`mcp`,`local`,`browser`,`tools`,`health`,`profiles`,`workspaces`,`ptk`,`dast`,`authz`]');
js = swap(js, ':v(`settings.dev.rowLabel`);(0,_.useEffect)', ':w===`authz`?`Compare accounts`:v(`settings.dev.rowLabel`);(0,_.useEffect)');
js = js.replaceAll('[`models`,`mcp`,`local`,`browser`,`tools`,`health`,`profiles`,`workspaces`,`ptk`,`dast`,`authz`]', '[`models`,`mcp`,`local`,`browser`,`tools`,`health`,`profiles`,`workspaces`,`ptk`,`dast`,`authz`,`security`]');
js = swap(js, ':v(`settings.dev.rowLabel`);(0,_.useEffect)', ':w===`security`?`Security testing`:v(`settings.dev.rowLabel`);(0,_.useEffect)');

// Keep explicit task configuration beside existing model/session controls.
js = swap(js, '[Wr,Gr]=(0,_.useState)(null);', '[Wr,Gr]=(0,_.useState)(null);let kiTaskContext=KiUseContextState(Hr);');
js = swap(js, 'let u=(await OM(i)).items;', 'await KiInitializeChat(i,r&&!a?l:null);let u=(await OM(i)).items;');
js = swap(js, 'let r=await Hj(e,Yn);', 'let r=await KiResolveChatModel(e,Yn);');
js = swap(js, 'return n(),()=>{t=!0}},[Hr,Yn,ht,byokShowProvider,Gn])', 'return n().catch(e=>{if(!t){rr(null);k(e.message)}}),()=>{t=!0}},[Hr,Yn,ht,byokShowProvider,Gn,kiTaskContext.revision])');
js = swap(js, 'yt.current=null,await EA(e,{connectionId:n.model.connectionId,modelId:n.model.modelId})', 'yt.current=null,await KiRememberModel(e,n.model),await EA(e,{connectionId:n.model.connectionId,modelId:n.model.modelId})');
js = swap(js, 'Ri=(0,_.useCallback)(e=>{Hr&&(rr({connectionId:e.connectionId,modelId:e.modelId,route:e.route,...e.maxContextTokens===void 0?{}:{maxContextTokens:e.maxContextTokens}}),Wn(byokTitle(e)),Xe(!1),et(null),EA(Hr,{connectionId:e.connectionId,modelId:e.modelId}).then(()=>gt(e=>e+1)))},[Hr])',
  'Ri=(0,_.useCallback)(async e=>{if(!Hr)return;try{await KiRememberModel(Hr,e);rr({connectionId:e.connectionId,modelId:e.modelId,route:e.route,...e.maxContextTokens===void 0?{}:{maxContextTokens:e.maxContextTokens}});Wn(byokTitle(e));Xe(!1);et(null);await EA(Hr,{connectionId:e.connectionId,modelId:e.modelId});gt(e=>e+1)}catch(e){k(e.message)}},[Hr])');
js = swap(js, 'if(nr?.connectionId===e.connectionId&&nr.modelId===e.modelId){Xe(!1);return}', 'if(nr?.connectionId===e.connectionId&&nr.modelId===e.modelId){KiRememberModel(Hr,e).catch(e=>k(e.message));Xe(!1);return}');
// Filter existing history without moving transcripts or altering tab groups.
js = swap(js, '},[s]),m=Date.now(),h=t=>{let n=gn', '},[s]),kiHistory=KiUseHistoryFilter(a),kiEntries=kiHistory.entries,m=Date.now(),h=t=>{let n=gn');
const historyStart = once(js, 'function Un({language:e,currentChatId:t,onOpen:n,onClose:r})');
const historyEnd = js.indexOf('function Wn(e)', historyStart);
let history = js.slice(historyStart, historyEnd).replaceAll('a!==null&&a.length', 'kiEntries!==null&&kiEntries.length').replace('children:a.map(e=>', 'children:kiEntries.map(e=>');
history = history.replace('className:`wb-settings-body wb-history-body`,children:[', 'className:`wb-settings-body wb-history-body`,children:[(0,A.jsx)(KiHistoryFilter,{value:kiHistory}),');
js = js.slice(0, historyStart) + history + js.slice(historyEnd);

const ooStart = once(js, "Oo=(0,A.jsxs)(`div`,{ref:Ze");
const ooEnd = js.indexOf(";", js.indexOf("},e.tier)})})]})]})]})", ooStart)) + 1;
const oo = js.slice(ooStart, ooEnd);

const menuStart = "Ye&&(0,A.jsxs)(`div`,{role:`menu`,className:`wb-popover wb-model-popover`,children:[";
const capStart = "lo&&so!==void 0&&(0,A.jsxs)(`div`,{className:`wb-model-sub`";
const tail = "]})]});";
if (!oo.endsWith(tail)) throw new Error("unexpected picker tail");
const capacity = oo.slice(oo.indexOf(capStart), oo.length - tail.length);
const head = oo.slice(0, oo.indexOf(menuStart));

const oldName = "(0,A.jsx)(`span`,{className:`wb-model-name`,children:Yn.length===0&&Zn?P(`model.none`):Pn||P(`model.choose`)})";
const newName = "kiAo&&(0,A.jsx)(KiGlyph,{vendor:kiAo.vendor,size:14}),(0,A.jsx)(`span`,{className:`wb-model-name`,children:Yn.length===0&&Zn?P(`model.none`):kiAo?kiAo.name:Pn||P(`model.choose`)})";

const newOo =
  "kiAo=ao?kiSplit(ao,byokTitle(ao,!1),Gn.find(e=>e.id===ao.connectionId)?.label):null," +
  "kiEffortFor=e=>{let t=e.route===`zebbern`&&e.reasoningEffortOptions?.length?e.reasoningEffortOptions:void 0;return t?{options:t,current:$A(t,it[e.modelId],e.defaultThinkingLevel),label:ho}:null}," +
  swap(head, oldName, newName) +
  "Ye&&(0,A.jsx)(KiModelMenu,{models:Yn,connections:Gn,selected:nr,onSelect:Ki,titleOf:e=>byokTitle(e,!1),lang:C,effortFor:kiEffortFor,onEffort:(e,t)=>{HA(e.modelId,t.effort)},footer:(0,A.jsxs)(A.Fragment,{children:[(0,A.jsx)(KiFastBrowse,{lang:C})," +
  capacity +
  "]})})]});";

js = js.slice(0, ooStart) + newOo + js.slice(ooEnd);

js = swap(
  js,
  ",Oo,de?",
  ",(0,A.jsx)(KiProfileSelector,{session:Hr,state:kiTaskContext,busy:de}),Oo,oo!==void 0&&ao&&(0,A.jsx)(KiEffortPill,{options:oo,current:po,label:ho,onPick:To,lang:C}),de?"
);

js = swap(
  js,
  "return(0,A.jsxs)(`div`,{className:`wb-livebar`,role:`status`,\"aria-live\":`polite`,children:[(0,A.jsx)(`span`,{className:`wb-livebar-mark`,\"aria-hidden\":!0}),(0,A.jsx)(`span`,{className:`wb-livebar-label`,children:l}),s>0&&(0,A.jsx)(`span`,{className:`wb-livebar-step`,children:String(s)})]})}",
  "return(0,A.jsx)(KiLivebar,{label:l,steps:s,lang:i,items:e,session:kiS})}"
);
js = swap(js, "function lO({items:e,running:t,language:n}){", "function lO({items:e,running:t,language:n,kiSession:kiS}){");
js = swap(
  js,
  "xi.open&&(0,A.jsx)(EO,{language:C,active:Qr&&jn.kind===`composer`&&!We&&!Ve})",
  "(xi.open||Oa)&&(0,A.jsx)(EO,{language:C,active:Qr&&jn.kind===`composer`&&!We&&!Ve})"
);
js = swap(js, "className:xi.open?`wb-empty wb-empty--welcome`:`wb-empty`", "className:xi.open||Oa?`wb-empty wb-empty--welcome`:`wb-empty`");
js = swap(js, "className:xi.open?`wb-welcome-prompts`:`wb-prompt-chips`", "className:xi.open||Oa?`wb-welcome-prompts`:`wb-prompt-chips`");
js = swap(js, "className:xi.open?`wb-welcome-prompt`:`wb-prompt-chip`", "className:xi.open||Oa?`wb-welcome-prompt`:`wb-prompt-chip`");
js = swap(js, "xi.open&&(0,A.jsx)(Te,{className:`wb-welcome-prompt-arrow`", "(xi.open||Oa)&&(0,A.jsx)(Te,{className:`wb-welcome-prompt-arrow`");

js = swap(
  js,
  "(0,A.jsx)(lO,{items:e,running:de===!0,language:C})",
  "za.length===0&&da.length===0&&(de===!0?(0,A.jsx)(lO,{items:e,running:!0,language:C,kiSession:Hr}):(0,A.jsx)(KiRunSummary,{items:e,lang:C}))"
);

const toolDone = "r[n]={...i,status:a?`error`:`success`,output:o,images:s,isError:a},r}";
const toolDoneAt = "r[n]={...i,status:a?`error`:`success`,output:o,images:s,isError:a,endedAt:i.endedAt??Date.now()},r}";
js = swap(js, toolDone, toolDoneAt);

let bg = fs.readFileSync(path.join(original, "background.js"), "utf8");
bg = swap(bg, 'let e=Array.isArray(a.attachments),t=Array.isArray(a.files);if(e===t)', 'let e=Array.isArray(a.attachments),t=Array.isArray(a.files),g=a.generated!==void 0;if(Number(e)+Number(t)+Number(g)!==1)');
bg = swap(bg, 'if(Number(e)+Number(t)+Number(g)!==1)return{output:t?"upload: give either `attachments` or `files`, not both — the two sources cannot be combined in one call.":"upload: give `attachments` (attachment_ids from the <context> block) or `files` (absolute local paths).",isError:!0}', 'if(Number(e)+Number(t)+Number(g)!==1)return{output:"upload: choose exactly one source: attachments, files, or generated.",isError:!0}');
bg = swap(bg, 'var mP={navigate:new Kt,', fs.readFileSync(path.join(__dirname, 'src/ki-upload.js'), 'utf8').trim() + '\nvar mP={navigate:new Kt,');
// Subagent stream deaths lose the final summary but not the work: graph_write
// calls persist in the workspace graph. Teach that recovery at the failure
// point so the orchestrator resumes via digest instead of re-delegating recon.
bg = swap(bg, 'catch(e){if(r.signal.aborted)throw e;return{output:`Subagent failed: ${e instanceof Error?e.message:String(e)}`,isError:!0}',
  'catch(e){if(r.signal.aborted)throw e;return{output:`Subagent interrupted: ${e instanceof Error?e.message:String(e)}. Recovery: its graph_write calls persist in the workspace graph. Do not repeat the same enumeration from scratch: delegate a resume brief ("a previous subagent already mapped the surface with graph_write; read graph_digest and graph_find, fill only visible gaps, then produce the final summary"). If the subagent wrote no graph, re-delegate the original task.`,isError:!0}');
// Deeper resume: oP retries the subagent once itself. Durable work (graph
// writes, files, runs) survived the stream death, so the retry turn re-reads
// state and answers instead of redoing recon — the orchestrator never sees
// the failure. The envelope above stays as the fallback if the retry dies too.
const kiOpResumeNeedle = 'function oP(e){let t=crypto.randomUUID(),n=n=>{e.onChildEvent?.({parentToolCallId:e.parentToolCallId,agentId:t,event:n})};n({type:`subagent.started`}),Ot(t,e.parentConversationId);let r=new AbortController,i=()=>{r.abort(e.parentSignal.reason)};e.parentSignal.aborted?r.abort(e.parentSignal.reason):e.parentSignal.addEventListener(`abort`,i,{once:!0});try{let{result:i,messages:a}=await eF({initialMessages:[{role:`user`,content:[{type:`text`,text:e.prompt}],toolCalls:[]}],conversationId:t,llm:e.llm,signal:r.signal,onEvent:n,profile:`subagent`});if(i.stopReason===`aborted`)throw r.signal.reason??new DOMException(`Subagent aborted`,`AbortError`);return{text:sP(a).trim()||`(subagent produced no text)`,tabId:Tt(t)?.primaryTabId}}finally{e.parentSignal.removeEventListener(`abort`,i),kt(t)}}';
const kiOpResumeReplacement = 'function oP(e){let t=crypto.randomUUID(),n=n=>{e.onChildEvent?.({parentToolCallId:e.parentToolCallId,agentId:t,event:n})};n({type:"subagent.started"}),Ot(t,e.parentConversationId);let r=new AbortController,i=()=>{r.abort(e.parentSignal.reason)};e.parentSignal.aborted?r.abort(e.parentSignal.reason):e.parentSignal.addEventListener("abort",i,{once:!0});let go=async resume=>{let o=resume?[{role:"user",content:[{type:"text",text:e.prompt+resume}],toolCalls:[]}]:[{role:"user",content:[{type:"text",text:e.prompt}],toolCalls:[]}],{result:i,messages:a}=await eF({initialMessages:o,conversationId:t,llm:e.llm,signal:r.signal,onEvent:n,profile:"subagent"});if(i.stopReason==="aborted")throw r.signal.reason??new DOMException("Subagent aborted","AbortError");return{text:sP(a).trim()||"(subagent produced no text)",tabId:Tt(t)?.primaryTabId}};try{return await go()}catch(x){if(r.signal.aborted)throw x;return await go("\\n\\n[resume] Your previous attempt was interrupted mid-run. Work you already persisted (knowledge-graph writes, saved files, runs) survived. Re-read the durable state (graph_digest/graph_find where relevant), verify only what is missing, and produce the final answer immediately. Do not redo completed work.")}finally{e.parentSignal.removeEventListener("abort",i),kt(t)}}';
bg = swap(bg, kiOpResumeNeedle, kiOpResumeReplacement);
// Network-level download failures must name the URL. HTTP-level failures are
// not failures: an error response body (DB error text, stack trace) is exactly
// what a probing agent needs, so non-2xx flows through the normal body-return
// path with its status instead of throwing the body away (observed live on
// BugStore: 10 wasted re-probe turns recovering bodies the fetch already had).
bg = swap(bg, 'let n=Math.min(Math.max(e.max_bytes??2e6,1),8e6),r=await fetch(t);if(!r.ok)throw Error(`download: HTTP ${r.status} for ${t}`);',
  'let n=Math.min(Math.max(e.max_bytes??2e6,1),8e6),r;try{r=await fetch(t)}catch(x){throw Error(`download: network error fetching ${t}: ${x&&x.message||x}`)}');
// read_file misuse teaches at the failure point: URLs belong to download, and
// with no directory listing, path-guessing must stop after one error (observed
// live: a subagent burned five calls guessing Downloads paths, then three more
// feeding URLs to read_file).
bg = swap(bg, 'let max=Math.min(Math.max(e.max_chars??2e5,1),1e6),tab=await chrome.tabs.create({url:`about:blank`,active:!1});',
  'if(/^https?:\\/\\//i.test(path))throw Error(`read_file: local files only — for http(s) URLs use download (returns the body inline, any status)`);let max=Math.min(Math.max(e.max_chars??2e5,1),1e6),tab=await chrome.tabs.create({url:`about:blank`,active:!1});');
bg = swap(bg, 'catch(err){throw Error(`read_file: could not read ${raw}. (${err instanceof Error?err.message:String(err)})`)}',
  'catch(err){throw Error(`read_file: could not read ${raw}. (${err instanceof Error?err.message:String(err)}) If a tool call produced this file, use the exact saved path from that call result; there is no directory listing, so do not guess paths.`)}');
// The favicon/cursor marker is cosmetic. On a second file selection after a
// download it can leave a Runtime.evaluate pending and block upload CDP work.
bg = swap(bg, 'await Da(n,u)}try{let o={', 'if(e!==`upload`)await Da(n,u)}try{let o={');
// Saving a local artifact does not interact with the page; do not start a
// concurrent cursor-marker debugger call that can hold the next file upload.
bg = swap(bg, '&&e!==`close_session`&&(await T(r),Fa(i,r))', '&&e!==`close_session`&&e!==`save_file`&&(await T(r),Fa(i,r))');
const securitySkill = { name: "security-testing", source: "builtin", description: "Investigate applications with the integrated security engines, verified accounts, evidence, and coordinated subagents.", whenToUse: "Bug bounty testing, application security assessment, or reproducing scanner findings.", content: fs.readFileSync(path.join(root, "security/skills/security-testing.md"), "utf8") };
bg = swap(bg, 'var lj=[{name:`web-skill-creator`', 'var lj=[' + JSON.stringify(securitySkill) + ',{name:`web-skill-creator`');
const dastInputs = fs.readFileSync(path.join(root, "security/compat/dast-inputs.js"), "utf8").trim();
bg = swap(bg, "var background=(function(){", "var background=(function(){\nvar kiBrowserChrome=globalThis.certXBrowserChrome||chrome;\nglobalThis.certXSecurityBuild=" + JSON.stringify({contract:'agent-security-v2',fingerprint:securityBuildFingerprint}) + ";\n" + kiProviderCompat + '\n' + dastInputs + "\n" + ["ki-context.js", "ki-telemetry.js", "ki-graph.js", "ki-csp.js", "ki-security.js", "ki-ptk.js", "ki-dast-transport.js", "ki-dast.js", "ki-authz.js", "ki-permissions.js", "ki-background.js", "ki-browse.js", "ki-browser-results.js", "ki-native.js", "ki-browser-control.js", "ki-workspace.js"].map(file => fs.readFileSync(path.join(__dirname, "src", file), "utf8").trim()).join("\n") + "\n");
bg = swap(bg, 't.length>0&&(c.tools=t.map(e=>Ey(e)))', 't.length>0&&(c.tools=t.map(e=>Ey(e))),kiProviderToolOptions(c)');
// The vendor bundle's hand-added tools reused names the minifier had already given
// to other bindings in the same scope, and the later `var` wins at load: read_file's
// class replaced the retryable-error check Rd (every failed model call then threw
// "Class constructor Rd cannot be invoked without 'new'", live in BugStore run 2),
// expand_disclosures replaced the incomplete-response error Ed, download replaced
// the media-error list Fd, and the expand script string replaced recording's XD.
// Rename the hand-added side; checkScope below keeps it from coming back.
bg = swap(bg, 'var Fd=class{name=`download`;', 'var kiDownloadTool=class{name=`download`;');
bg = swap(bg, 'var Rd=class{name=`read_file`;', 'var kiReadFileTool=class{name=`read_file`;');
bg = swap(bg, 'var Ed=class{name=`expand_disclosures`;', 'var kiExpandDisclosuresTool=class{name=`expand_disclosures`;');
bg = swap(bg, 'download:new Fd,read_file:new Rd,expand_disclosures:new Ed}', 'download:new kiDownloadTool,read_file:new kiReadFileTool,expand_disclosures:new kiExpandDisclosuresTool}');
bg = swap(bg, 'var XD=`(${wbExpandClosed.toString()})()`;', 'var kiExpandClosedJs=`(${wbExpandClosed.toString()})()`;');
bg = swap(bg, '{expression:XD,awaitPromise:!0,returnByValue:!0}).catch(()=>{})', '{expression:kiExpandClosedJs,awaitPromise:!0,returnByValue:!0}).catch(()=>{})');
bg = swap(bg, '{expression:XD,awaitPromise:!0,returnByValue:!0});if(r.exceptionDetails)', '{expression:kiExpandClosedJs,awaitPromise:!0,returnByValue:!0});if(r.exceptionDetails)');
bg = swap(bg, 'await ${XD};', 'await ${kiExpandClosedJs};');
// The 90 s stall timer (Xd) restarts only on a parsed part, and the parser reads
// reasoning only from delta.reasoning_content. OpenRouter streams it as
// delta.reasoning / reasoning_details (captured from xiaomi/mimo-v2.6-pro), so a
// model thinking for 90 s looked dead and was cut, three tries per run (13 cuts,
// ~20 of 60 min in BugStore run 2). A reasoning chunk now counts as liveness; it is
// not kept, so nothing new is shown or echoed back in the history.
bg = swap(bg, 'i.content&&(yield{type:`text`,text:i.content});for(let e of i.tool_calls??[])', 'i.content&&(yield{type:`text`,text:i.content}),!a&&!i.content&&!i.tool_calls?.length&&(i.reasoning||i.reasoning_details?.length)&&(yield{type:`ki_alive`});for(let e of i.tool_calls??[])');
bg = swap(bg, 'if(e.done===!0){f=!0;break}let t=e.value;', 'if(e.done===!0){f=!0;break}let t=e.value;if(t.type===`ki_alive`)continue;');
// Resolve preferences before model construction, never silently substitute a missing preferred model.
bg = swap(bg, 'async function OF(e){let t=', 'async function OF(e){if(!GP(e.profile)){let context=await kiContextPrepare(e.conversationId),preferred=context.model||await Vl(),catalog=(await pu()).models,selected=catalog.find(m=>m.connectionId===preferred?.connectionId&&m.modelId===preferred?.modelId)||(!context.model?catalog[0]:null);if(!selected)throw Error(`Preferred model unavailable. Choose an available model to continue.`);e={...e,selection:await cu(selected,ou(selected,await iu()))}}let t=');
bg = swap(bg, 'systemPrompt:r===`quick-translate`?await SF(i):r===`quick-explain`?await ZP():mF(c.getModelSkillListing())', 'systemPrompt:r===`quick-translate`?await SF(i):r===`quick-explain`?await ZP():mF(c.getModelSkillListing())+kiContextPrompt(t)+(await kiBrowseLoad(),kiBrowseReady()?KI_BROWSE_PROMPT:``)');
// Same rule when the provider answers 404 mid-turn: the vendor's recovery clears the
// saved default and resends the conversation to the first other model, on any
// connection. It never ran here (the Rd clash threw first); keep it off so the
// provider's own error reaches the user.
bg = swap(bg, 'i=async n=>{let r=await yu(e.conversationId,{connectionId:n.connectionId,modelId:n.modelId});return r?{...await DF(r,e.conversationId,t,e.profile,e.quickTranslateFormat,e.observeRequest),selection:r}:null}', 'i=async()=>null');
// Assigned workspace chats must survive the legacy ten-unassigned-chat history sweep.
bg = swap(bg, 'async function Vk(e,t){let n=(await Ek()).filter(t=>t.lastActiveAt!==void 0&&Pk(t)===e),r=n.length-10;', 'async function Vk(e,t){let context=await kiContextLoad(),n=(await Ek()).filter(t=>t.lastActiveAt!==void 0&&Pk(t)===e&&!context.chats[t.chatId]?.workspaceId),r=n.length-10;');
js = swap(js, 'className:`wb-history-foot`,children:i(`history.limit`,{n:10})', 'className:`wb-history-foot`,children:`Workspace chats are kept until deleted. Other chats keep the latest 10.`');
const browserClientStart = once(bg, "var RB=class");
const browserClientEnd = bg.indexOf(",zB=", browserClientStart);
if (browserClientEnd < 0 || browserClientEnd - browserClientStart > 10000) throw Error("Unexpected WebBridge client span");
bg = bg.slice(0, browserClientStart) + "var RB=KiBrowserControl" + bg.slice(browserClientEnd);
bg = swap(bg, 'try{switch(e.type){case`GET_STATUS`:', 'try{if([`CONNECT`,`DISCONNECT`,`TEST_CONNECTION`,`RECONCILE_NOW`,`UPGRADE_DAEMON`,`GENERATE_CONNECTION`].includes(e.type)&&(t.id!==chrome.runtime.id||!t.url?.startsWith(chrome.runtime.getURL(``)))){n({error:`forbidden`});return}switch(e.type){case`GET_STATUS`:');
bg = swap(bg, 'await n(WF(e))', 'await n(WF(e),{signal:AbortSignal.timeout(3000),redirect:`error`})');
bg = swap(bg, 'function Ot(e,t){let n=Xe.get(t);', 'function Ot(e,t){kiWorkspaceParents.set(e,kiWorkspaceOwner(t));let n=Xe.get(t);');
bg = swap(bg, 'function kt(e){Xe.delete(e)}', 'function kt(e){Xe.delete(e),kiWorkspaceParents.delete(e),kiContextTurns.delete(e)}');
bg = swap(bg, "maxRetryAttempts:h}=e,g=sf()", "maxRetryAttempts:h,kiBefore:kiB}=e,g=sf()");
bg = swap(bg, "try{for(;;){if(n.throwIfAborted(),_>=m)throw kE(m);", "try{for(;;){if(await kiB?.(),n.throwIfAborted(),_>=m)throw kE(m);");
bg = swap(
  bg,
  "return{result:await _N({turnId:m,signal:e.signal,",
  "return{result:await _N({kiBefore:async()=>{await kiGate(e.conversationId,e.signal),kiDrainSteer(e.conversationId,n,e.onContextMessage)},turnId:m,signal:e.signal,"
);
bg = swap(
  bg,
  "async function tN(e,t,n,r,i){let{dispatchEvent:a,signal:o,turnId:s}=e;return o.throwIfAborted(),nN(t.execute({turnId:s,toolCallId:n.id,metadata:i,signal:o,onUpdate:e=>{o.aborted||a({type:`tool.progress`,toolCallId:n.id,update:e})}}),o,r)}",
  "async function tN(e,t,n,r,i){let{dispatchEvent:a,signal:kiO,turnId:s}=e,kiS=GI.get(n.id);kiS&&await kiGate(kiS,kiO);kiO.throwIfAborted();let kiC=new AbortController,o=AbortSignal.any([kiO,kiC.signal]);kiSkips.set(n.id,kiC);try{let x=await nN(t.execute({turnId:s,toolCallId:n.id,metadata:i,signal:o,onUpdate:e=>{o.aborted||a({type:`tool.progress`,toolCallId:n.id,update:e})}}),o,r);return kiC.signal.aborted&&!kiO.aborted?kiSkipped(r):x}catch(x){if(kiC.signal.aborted&&!kiO.aborted)return kiSkipped(r);throw x}finally{kiSkips.delete(n.id)}}"
);
bg = swap(bg, "c=iN(await tN(e,i,o,s,r),s)", "c=iN((await kiMark(s,n),await tN(e,i,o,s,r)),s)");
// Refs resolve through mr; mutating tools check the element still matches what was read
// (kiRefGuard). inspect_region names refs from the DOM, not the accessibility tree, so
// its refs are flagged and skipped rather than compared against a different naming; it never
// overwrites a node's existing accessibility-named entry, so inspecting cannot unguard a ref.
bg = swap(bg, 'is no longer on the page. Read the page again.`);return a.objectId}', 'is no longer on the page. Read the page again.`);return await kiRefGuard(e,t,n,r),a.objectId}');
bg = swap(bg, 'function fe(e,t,n,r){let i=oe(e),a=i.byBackendNode.get(t);if(a!==void 0)return i.refs.set(a,{backendDOMNodeId:t,role:n,name:r,documentKey:i.documentKey}),a;let o=`e${re()}`;return i.refs.set(o,{backendDOMNodeId:t,role:n,name:r,documentKey:i.documentKey}),',
  'function fe(e,t,n,r,x){let i=oe(e),a=i.byBackendNode.get(t);if(a!==void 0){let old=i.refs.get(a);return x&&old&&!old.dom||i.refs.set(a,{backendDOMNodeId:t,role:n,name:r,documentKey:i.documentKey,...x?{dom:!0}:{}}),a}let o=`e${re()}`;return i.refs.set(o,{backendDOMNodeId:t,role:n,name:r,documentKey:i.documentKey,...x?{dom:!0}:{}}),');
bg = swap(bg, 'fe(e,c.backendNodeId,s.role||s.tag,s.label||s.text.slice(0,160))', 'fe(e,c.backendNodeId,s.role||s.tag,s.label||s.text.slice(0,160),!0)');
// hr (mouse_click/hover geometry) reads the box right after scrolling; on pages with
// scroll-behavior:smooth that is mid-animation, so the pointer lands off-target or out of view.
bg = swap(bg, "async function hr(e,t,n,r=``){await E(e,`Runtime.callFunctionOn`,{objectId:t,functionDeclaration:`function() {\n      this.scrollIntoView({ block: 'center', inline: 'center' });",
  "async function hr(e,t,n,r=``){await E(e,`Runtime.callFunctionOn`,{objectId:t,functionDeclaration:`function() {\n      this.scrollIntoView({ block: 'center', inline: 'center', behavior: 'instant' });");
// set_checked re-reads its target to verify after clicking; only the first read (before any
// click) is a guarded resolution, so a toggle that already happened is never reported as refused.
bg = swap(bg, "let i=async()=>gr(r,await mr(r,t,`set_checked`),Gi,`set_checked`),a=await i();",
  "let i=async g=>gr(r,await mr(r,t,g?`set_checked`:`set_checked (verify)`),Gi,`set_checked`),a=await i(!0);");
bg = swap(bg, "function Q(e,t){e.timeline=$a(e.timeline,t),", "function Q(e,t){kiWatch(e,t),e.timeline=$a(e.timeline,t),");
bg = swap(bg, "QI(e)}}async function xL(", "QI(e),kiTurnEnd(e,u,l)}}async function xL(");
bg = swap(bg, toolDone, toolDoneAt);

// Expose background daemon tools to the model: add each to the schema table (pP)
// and the executor map (mP). Verify the minified class ids still map to the
// expected tool names first, so a bundle rename fails the build loudly.
for (const [id, name] of Object.entries(kiTools.classMap)) {
  const at = bg.indexOf(id + "=class");
  const m = at < 0 ? null : /name=`([a-z_]+)`/.exec(bg.slice(at, at + 600));
  if (!m || m[1] !== name) throw new Error(`ki-tools: class ${id} no longer maps to "${name}" (found ${m ? m[1] : "nothing"}) — update classMap`);
}
bg = swap(bg, "pP={navigate:{description:", "pP={" + kiTools.specEntries + "navigate:{description:");
bg = swap(bg, "mP={navigate:new Kt,", "mP={" + kiTools.mpEntries + "navigate:new Kt,");
// attach_tab runs via mP[e].execute (not Ba), so it must also bind primaryTabId
// in kP like navigate/find_tab, otherwise the attached tab is not the working tab.
bg = swap(bg, "Let zebbern handle your browser tasks", "Let cert-x handle your browser tasks");
bg = swap(bg, "if(e===`navigate`||e===`find_tab`){let e=c?.tabId;", "if(e===`navigate`||e===`find_tab`||e===`attach_tab`){let e=c?.tabId;");
bg = swap(
  bg,
  "return Object.entries(pP).filter(([e])=>i===`main`||e!==`agent`).map(([i,a])=>i===`agent`?AP(e,t,r?.onChildEvent):i===`await_user_action`?PP(e):i===`skill`?FP(n):i===`save_skill`?IP():i===`delete_skill`?LP():i===`run_saved_skill`?zP(e):kP(i,a,e))}",
  "return kiPolicyTools([...Object.entries(pP).filter(([e])=>(i===`main`||e!==`agent`)&&(e!==`browse`||kiBrowseReady())).map(([i,a])=>i===`agent`?AP(e,t,r?.onChildEvent):i===`await_user_action`?PP(e):i===`skill`?FP(n):i===`save_skill`?IP():i===`delete_skill`?LP():i===`run_saved_skill`?zP(e):kP(i,a,e)),...kiMcpToolDefs(e),...kiNativeToolDefs(e),...kiProductTools(i,e),...kiGraphToolDefs(e),...kiSecurityToolDefs(e)],e)}"
);
bg = swap(bg, 'async function TP(e,t){if(QN(e)||await FN(e.domain,e.action))return null;let n=await KN.request(e,t);return n===`deny`?{output:`Permission denied by user.`,isError:!0}:(n===`allow_for_domain`&&await IN(e.domain,e.action),null)}',
  'async function TP(e,t){if(e.policyLease){await kiPolicyRecheck(e.policyLease);if(e.policyLease.authorized||await FN(e.domain,e.action))return null}else if(QN(e)||await FN(e.domain,e.action))return null;let{policyLease:kiLease,...kiRequest}=e;let n=await KN.request(kiRequest,t);if(n===`deny`)return{output:`Permission denied by user.`,isError:!0};if(e.policyLease){e.policyLease.approved=!0;e.policyLease.authorized=!0}if(n===`allow_for_domain`)await IN(e.domain,e.action);return null}');
// browse with a url acts on that url's site, so approval names that domain and URL, as for navigate.
bg = swap(bg, 'case`key_type`:return typeof t.text==`string`?{text:t.text.slice(0,80)}:void 0;', 'case`browse`:return typeof t.url==`string`&&t.url?{url:t.url}:typeof t.goal==`string`?{text:t.goal.slice(0,120)}:void 0;case`key_type`:return typeof t.text==`string`?{text:t.text.slice(0,80)}:void 0;');
bg = swap(bg, 'd=wP(e===`navigate`||e===`find_tab`?a.url:l?.url)', 'd=wP(e===`navigate`||e===`find_tab`||e===`browse`&&typeof a.url==`string`&&a.url?a.url:l?.url)');
bg = swap(bg, 'toolName:e,session:n,preview:f===void 0?', 'toolName:e,policyLease:i[KI_POLICY_CONTEXT],session:n,preview:f===void 0?');
// browse runs a multi-step loop, so it needs the turn's abort signal (Stop/Skip) and the
// user's chat for pause and steer: GI maps a tool call to that chat, which differs from n
// inside a subagent. Model args starting with _ are stripped above, so they cannot spoof these.
bg = swap(bg, 'let c=await r.execute(o);', 'await kiPolicyRecheck(i[KI_POLICY_CONTEXT]);let c=await kiBrowserAgentResult(e,o,await r.execute(e===`browse`?{...o,_signal:i.signal,_conversation:GI.get(i.toolCallId)??n,_main:(GI.get(i.toolCallId)??n)===n}:o),n);');
bg = swap(bg, 'a=e.tools?.find(e=>e.name===n);if(a===void 0)', 'a=e.tools?.find(e=>e.name===n)||kiSecurityLegacyLookup(e.tools,n);if(a===void 0)');
// Saved workflows have their own browser approval entry point.
bg = swap(bg, 'toolName:`run_saved_skill`,session:e,preview:', 'toolName:`run_saved_skill`,policyLease:n[KI_POLICY_CONTEXT],session:e,preview:');
bg = swap(bg, ",d=u(e.llm),f=t=>new cM", ",d=(GP(e.turnProfile)?[]:(kiContextTurns.has(kiContextOwner(e.conversationId))||await kiContextPrepare(e.conversationId),await kiMcpRefresh(e.conversationId),await kiPtkLoad(),await kiDastLoad(),await kiAuthzLoad(),await kiBrowseLoad(),u(e.llm))),f=t=>new cM");
bg = swap(bg, "loopTools:BP(e.conversationId,t,i)", "loopTools:(await kiContextPrepare(e.conversationId),await kiMcpRefresh(e.conversationId),await kiPtkLoad(),await kiDastLoad(),await kiAuthzLoad(),await kiBrowseLoad(),BP(e.conversationId,t,i))");
bg = swap(bg, "default:n({error:`unknown type: ${e.type}`})", "default:(typeof e.channel===`string`&&(e.channel.startsWith(`ptk_`)||e.channel.startsWith(`CERT_X_SECURITY_`)))||e.type===`KI_MCP`||e.type===`KI_NATIVE`||e.type===`KI_BROWSER_CONTROL`||e.type===`KI_PERMISSIONS`||e.type===`KI_WORKSPACE`||e.type===`KI_CONTEXT`||e.type===`KI_CSP`||e.type===`KI_PTK`||e.type===`KI_DAST`||e.type===`KI_AUTHZ`||e.type===`KI_SECURITY`||e.type===`KI_BROWSE`||n({error:`unknown type: ${e.type}`})");
bg = swap(bg, 'return{mimeType:`application/pdf`,dataLength:o.data.length', 'return{...await kiWorkspaceSavePdf(o.data,e.file_name),mimeType:`application/pdf`,dataLength:o.data.length');
bg = swap(bg, 'PDF generated (${o.data.length} base64 chars) and not inlined, so it does not flood the transcript.', 'PDF download started; see its returned state. Added to task outputs.');
js = swap(js, 'ref:Pt,className:`wb-composer`,children:[', 'ref:Pt,className:`wb-composer`,children:[(0,A.jsx)(KiWorkspaceSelector,{session:Hr,state:kiTaskContext,busy:de,models:Yn,modelsReady:Zn}),(0,A.jsx)(KiPtkPanel,{session:Hr,state:kiTaskContext,onOpen:section=>{kiSetSettingsSection(section);Li()}}),(0,A.jsx)(KiDastPanel,{session:Hr,state:kiTaskContext}),(0,A.jsx)(KiDastPanel,{session:Hr,kind:`authz`}),(0,A.jsx)(KiCspIndicator,{session:Hr}),(0,A.jsx)(KiTaskOutputs,{session:Hr,onAttach:va,workspaceId:kiTaskContext.chats[Hr]?.workspaceId}),');
// Let the page/working-tab tools accept the optional `tab` arg like the built-in
// interaction tools. Two lists must agree: the schema-augmentation loop (adds the
// `tab` property) and the kP execution guard (accepts it at call time). The three
// tab-management tools are intentionally left out.
bg = swap(
  bg,
  "`expand_disclosures`]){let t=pP[e]?.parameters;",
  "`expand_disclosures`" + kiTools.tabListSuffix + "]){let t=pP[e]?.parameters;"
);
bg = swap(
  bg,
  "`expand_disclosures`].includes(e))return{output:`Tool ${e} failed: this tool does not take a tab argument.",
  "`expand_disclosures`" + kiTools.tabListSuffix + "].includes(e))return{output:`Tool ${e} failed: this tool does not take a tab argument."
);

// read_file: add encoding:"base64" (consistency with download, which returns
// base64 for binary). Default stays text. Three coordinated edits: schema param,
// a b64 flag in the executor, the in-page reader, and the result passthrough.
bg = swap(
  bg,
  "max_chars:{type:`number`,description:`Maximum characters to return. Defaults to 200000.`}},required:[`path`]",
  "max_chars:{type:`number`,description:`Maximum characters to return (text only). Defaults to 200000.`},encoding:{type:`string`,enum:[`text`,`base64`],description:`Output format. \"text\" (default) returns decoded text; \"base64\" returns the raw bytes base64-encoded (like download) — use for binary files such as images or archives.`}},required:[`path`]"
);
bg = swap(
  bg,
  "let max=Math.min(Math.max(e.max_chars??2e5,1),1e6),tab=await chrome.tabs.create(",
  "let max=Math.min(Math.max(e.max_chars??2e5,1),1e6),b64=e.encoding===`base64`,tab=await chrome.tabs.create("
);
bg = swap(
  bg,
  "let max=${max};let text=await f.text();el.remove();return{name:f.name,size:f.size,totalChars:text.length,truncated:text.length>max,text:text.length>max?text.slice(0,max):text}",
  "let max=${max};if(${b64}){let all=new Uint8Array(await f.arrayBuffer());let cap=6000000;let bytes=all.subarray(0,Math.min(all.length,cap));let bin='';for(let i=0;i<bytes.length;i++)bin+=String.fromCharCode(bytes[i]);el.remove();return{name:f.name,size:f.size,encoding:'base64',totalBytes:all.length,truncated:all.length>cap,base64:btoa(bin)}}let text=await f.text();el.remove();return{name:f.name,size:f.size,totalChars:text.length,truncated:text.length>max,text:text.length>max?text.slice(0,max):text}"
);
bg = swap(
  bg,
  "return{path:raw,name:v.name,size:v.size,totalChars:v.totalChars,truncated:v.truncated,text:v.text}",
  "return v.encoding===`base64`?{path:raw,name:v.name,size:v.size,encoding:`base64`,totalBytes:v.totalBytes,truncated:v.truncated,base64:v.base64}:{path:raw,name:v.name,size:v.size,totalChars:v.totalChars,truncated:v.truncated,text:v.text}"
);
for (const n of kiTools.toolNames) {
  if (!bg.includes(n + ":{") || !bg.includes(n + ":new ")) throw new Error("tool exposure self-check failed for " + n);
}
{
  const tabMark = "`expand_disclosures`" + kiTools.tabListSuffix + "]";
  const n = bg.split(tabMark).length - 1;
  if (n !== 2) throw new Error("tab-arg self-check: expected 2 patched lists, found " + n);
}
if (process.env.KI_TEST_HOOKS) {
  bg = swap(bg, "var dV={debug:", "globalThis.kiTest={kiMark,setTab:je,kiNotify,kiIcon,kiFocus,refs:le,get tools(){return mP},setBrowseDecide(f){kiBrowseDecide=f},browseRun:kiBrowseRun,async browseReady(){await kiBrowseLoad();return kiBrowseReady()},setStreamIdle(ms){Xd=ms}};var dV={debug:");
  console.log("TEST BUILD: background test hooks exposed");
}
for (const need of ["function wbExpandClosed(", "__wb_read_file", "func:Fr", "wbAssertContained", "function kiGate", "kiSaveFileTool=class", "var kiBrowseTool = class", "async function sn(e,t){await te();", "function jn(e,t){", "function Mn(e,t){", "function kiMcpToolDefs", "function kiMcpRefresh", "function kiTelemetryRecord", "function kiErrorEnvelope", "function kiGraphToolDefs", "try { kiTelemetryRecord(executionMeta"]) {
  if (!bg.includes(need)) throw new Error("background rebuild missing " + need + " — the picker snapshot is older than the working tools");
}
if (bg.includes("frame-read.js")) throw new Error("background rebuild still injects frame-read.js, which is not in the extension");
bg = bg.replaceAll('chrome.debugger', 'kiBrowserChrome.debugger').replaceAll('chrome.runtime.lastError', 'kiBrowserChrome.runtime.lastError');
checkScope(bg, "background.js");
fs.writeFileSync(path.join(root, "background/background.js"), bg);
console.log("patched background.js", bg.length, "bytes");

js = swap(js, "za=[...Ra,...La]", "kiAdd=Ia===null?[]:kiAddItems({query:Ia.query,P,lang:C,tabs:h.length,full:D.length>=6}),za=[...kiAdd,...Ra,...La]");

js = swap(
  js,
  "Ra.length>0&&(0,A.jsx)(`div`,{className:`wb-command-skills`,children:Ra.map((e,t)=>qa(e,t))}),La.length>0&&(0,A.jsx)(`div`,{className:`wb-command-actions`,children:La.map((e,t)=>qa(e,Ra.length+t))})",
  "kiAdd.length>0&&(0,A.jsx)(`div`,{className:`wb-command-actions ki-command-add`,children:kiAdd.map((e,t)=>qa(e,t))}),Ra.length>0&&(0,A.jsx)(`div`,{className:`wb-command-skills`,children:Ra.map((e,t)=>qa(e,kiAdd.length+t))}),La.length>0&&(0,A.jsx)(`div`,{className:`wb-command-actions`,children:La.map((e,t)=>qa(e,kiAdd.length+Ra.length+t))})"
);

js = swap(
  js,
  "e.kind!==`action`&&(t===0||za[t-1]?.kind===`action`)&&(0,A.jsx)(`div`,{className:`wb-command-label`,children:P(`command.skills`)}),e.kind===`action`&&za[t-1]?.kind!==`action`&&(0,A.jsx)(`div`,{className:`wb-command-label wb-command-label-actions`,children:P(`command.actions`)}),",
  "kiCmdHead(e,za[t-1],P,C),"
);

js = swap(
  js,
  "\"aria-hidden\":!0,children:e.kind===`action`?e.action===`record`",
  "\"aria-hidden\":!0,children:e.ki?(0,A.jsx)(`span`,{className:`wb-composer-glyph wb-composer-glyph--`+e.ki}):e.kind===`action`?e.action===`record`"
);

js = swap(
  js,
  "Ga=e=>{if(e.kind===`action`){",
  "Ga=e=>{if(e.ki){if(e.disabled)return;let r=qF(n,Ia)??{next:n,caret:o};if(e.ki===`clip`){ha(r.next,r.caret),Dr.current?.click();return}let t=r.next.slice(0,r.caret),u=t.length>0&&!/\\s$/u.test(t)?` @`:`@`,i=r.caret+u.length;ha(`${t}${u}${r.next.slice(r.caret)}`,i),requestAnimationFrame(()=>{Er.current?.setCaret(i),Er.current?.focus()});return}if(e.kind===`action`){"
);

js = swap(
  js,
  "}).catch(()=>{t||On(!1)}),()=>{t=!0}},[n]);",
  "}).catch(()=>{t||On(!1)}),()=>{t=!0}},[n]);(0,_.useEffect)(()=>{let dead=!1,check=cb=>{let r=Or.current;if(r==null){dead||On(!1),cb?.(!1);return}chrome.tabs.get(r).then(e=>{let ok=!!(eM(e?.url)||tM(e?.url));dead||On(ok),cb?.(ok)}).catch(()=>{dead||On(!1),cb?.(!1)})},act=()=>setTimeout(()=>check(),50),upd=(id,info)=>{id===Or.current&&(info.url||info.status===`complete`)&&check()},foc=()=>check(),later=setTimeout(()=>check(),600);kiRecCheck=check,check(),chrome.tabs.onActivated.addListener(act),chrome.tabs.onUpdated.addListener(upd),window.addEventListener(`focus`,foc);return()=>{dead=!0,clearTimeout(later),kiRecCheck===check&&(kiRecCheck=null),chrome.tabs.onActivated.removeListener(act),chrome.tabs.onUpdated.removeListener(upd),window.removeEventListener(`focus`,foc)}},[]);"
);

js = swap(
  js,
  "role:`tooltip`,children:P(`header.history`)})]})",
  "role:`tooltip`,children:P(`header.history`)})]}),(0,A.jsxs)(`button`,{type:`button`,className:`wb-topnav-circle wb-sk-tip-anchor ki-topnav-record`,onMouseEnter:()=>kiRecCheck?.(),onClick:()=>Aa.disabled&&Dn?void 0:Dn?Ga({kind:`action`,action:`record`,disabled:!1}):kiRecCheck?.(ok=>{ok&&!kP(!0,Zn,Yn.length).disabled&&Ga({kind:`action`,action:`record`,disabled:!1})}),\"aria-disabled\":Aa.disabled||void 0,\"aria-label\":P(`slash.recordNew`),children:[(0,A.jsx)(ze,{className:`h-5 w-5`}),(0,A.jsx)(`span`,{className:`wb-sk-tip is-down is-start`,role:`tooltip`,children:Aa.disabled&&Aa.titleKey?P(Aa.titleKey):P(`slash.recordNew`)})]})"
);

const leftStart = once(js, "(0,A.jsxs)(`button`,{type:`button`,className:ua?`wb-icon-button is-active wb-sk-tip-anchor`");
const leftEndNeedle = "children:P(`composer.addFile`)})]}),";
const leftEnd = js.indexOf(leftEndNeedle, leftStart) + leftEndNeedle.length;
if (leftEnd - leftStart > 2000) throw new Error("composer buttons span looks wrong");
js = js.slice(0, leftStart) +
  "(0,A.jsxs)(`button`,{type:`button`,className:za.length>0?`wb-icon-button ki-plus is-active wb-sk-tip-anchor`:`wb-icon-button ki-plus wb-sk-tip-anchor`,onClick:()=>{let r=za.length>0&&la?qF(n,la):null;if(!r){_a();return}ha(r.next,r.caret),requestAnimationFrame(()=>{Er.current?.setCaret(r.caret),Er.current?.focus()})},\"aria-label\":(kiAddCopy[C]||kiAddCopy.en).plus,\"aria-haspopup\":`listbox`,\"aria-expanded\":za.length>0,disabled:!Oa||!!yn,children:[kiSvg(`M7 2v10M2 7h10`,15),(0,A.jsx)(`span`,{className:`wb-sk-tip is-start`,role:`tooltip`,children:(kiAddCopy[C]||kiAddCopy.en).plus})]})," +
  js.slice(leftEnd);

if (process.env.KI_FAKE_EFFORT) {
  const fake = "[{effort:`low`},{effort:`medium`},{effort:`high`,description:`Thinks longer on hard steps`},{effort:`max`}]";
  js = swap(js, "oo=ao?.route===`zebbern`&&ao.reasoningEffortOptions?.length?ao.reasoningEffortOptions:void 0", "oo=ao?" + fake + ":void 0");
  js = swap(js, "let t=e.route===`zebbern`&&e.reasoningEffortOptions?.length?e.reasoningEffortOptions:void 0;", "let t=" + fake + ";");
  console.log("TEST BUILD: fake effort options on every model");
}

// Outside Full access, native approvals show the full payload and offer
// once/deny only. Browser domain grants do not authorize OS operations.
js = swap(js, "description:f(e,`approval.fullDesc`)", "description:f(e,`approval.fullDesc`)+(e===`en`?` Also applies to local computer tools when enabled. Tool rules still apply.`:` 启用本机工具后也适用于本机操作。`)");
js = swap(js, "description:P(`approval.fullConfirmBody`)", "description:P(`approval.fullConfirmBody`)+(C===`en`?` When local computer access is enabled, local commands, file operations and local MCP tools also run without approval prompts. Custom tool rules still apply.`:` 启用本机访问后，本机命令、文件操作和本机 MCP 工具也会直接执行，无需逐次批准。`)");
js = swap(js, "l=gT(e.action,i),u=e.preview?.url", "l=e.policyPrompt?(i===`en`?`use this tool`:`使用此工具`):e.local?(i===`en`?`access your local computer`:`访问本机`):gT(e.action,i),u=e.preview?.url");
js = swap(js, "children:a(`perm.subtitle`)", "children:e.policyPrompt?(i===`en`?`Review this tool call. Approval applies once.`:`请检查工具调用。批准仅限本次。`):e.local?(i===`en`?`Review this local operation. Approval applies once.`:`请检查本机操作。批准仅限本次。`):a(`perm.subtitle`)");
js = swap(js, "children:_T(u,60)", "style:e.local?{whiteSpace:`pre-wrap`,maxHeight:`320px`,overflow:`auto`,overflowWrap:`anywhere`}:void 0,children:e.local?u:_T(u,60)");
js = swap(js, "(0,A.jsx)(`button`,{type:`button`,className:`wb-btn wb-btn--primary`,onClick:o,children:a(`perm.remember`)})", "!e.local&&(0,A.jsx)(`button`,{type:`button`,className:`wb-btn wb-btn--primary`,onClick:o,children:a(`perm.remember`)})");
js = swap(js, 'for(let e of dT.listPending())dT.resolve(e.toolCallId,`allow_once`)', 'for(let e of dT.listPending())if(!e.policyExplicit)dT.resolve(e.toolCallId,`allow_once`)');
js = swap(js, 'children:Ea.label', 'children:(0,A.jsxs)(A.Fragment,{children:[Ea.label,(0,A.jsx)(KiPolicyIndicator,{lang:C})]})');

const css = fs.readFileSync(path.join(original, path.basename(cssName)), "utf8") +
  "\n" + fs.readFileSync(path.join(__dirname, "src", "ki-picker.css"), "utf8") +
  "\n" + fs.readFileSync(path.join(root, "providers/security.css"), "utf8");

checkScope(js, jsName, "--module");
fs.writeFileSync(path.join(root, jsName), js);
fs.writeFileSync(path.join(root, cssName), css);
console.log("patched", jsName, js.length, "bytes;", cssName, css.length, "bytes");

// Build-time guard: every file path the manifest references must exist on disk.
// This catches the class of hard load failures (e.g. a deleted service worker or
// content script) before Chrome does.
(function validateManifest() {
  const man = JSON.parse(fs.readFileSync(path.join(root, "manifest.json"), "utf8"));
  const refs = [];
  const add = (p) => { if (typeof p === "string" && p) refs.push(p); };
  add(man.background && man.background.service_worker);
  add(man.side_panel && man.side_panel.default_path);
  add(man.options_ui && man.options_ui.page);
  add(man.options_page);
  add(man.action && man.action.default_popup);
  if (man.icons) for (const k of Object.keys(man.icons)) add(man.icons[k]);
  if (man.action && man.action.default_icon) for (const k of Object.keys(man.action.default_icon)) add(man.action.default_icon[k]);
  for (const cs of man.content_scripts || []) {
    for (const f of cs.js || []) add(f);
    for (const f of cs.css || []) add(f);
  }
  for (const war of man.web_accessible_resources || []) for (const r of war.resources || []) if (!r.includes("*")) add(r);
  const missing = refs.filter((p) => !fs.existsSync(path.join(root, p)));
  if (missing.length) throw new Error("manifest references missing files: " + missing.join(", "));
  if (!(man.permissions || []).includes("downloads")) throw new Error("save_file requires the downloads permission in manifest.json");
  console.log("manifest file references OK (" + refs.length + " checked)");
})();

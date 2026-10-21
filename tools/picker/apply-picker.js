const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..", "..");
const original = path.join(__dirname, "original");
const jsName = "chunks/sidepanel-CUbsl7eV.js";
const cssName = "assets/sidepanel-DD7JAQkM.css";
const kiTools = require("./src/ki-tools");

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

let js = fs.readFileSync(path.join(original, path.basename(jsName)), "utf8");
const components = ["ki-vendor-icons.js", "ki-components.js", "ki-live.js"].map((f) => fs.readFileSync(path.join(__dirname, "src", f), "utf8").trim()).join("\n");

js = swap(js, "function PI(){", components + "\nfunction PI(){");

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
  "Ye&&(0,A.jsx)(KiModelMenu,{models:Yn,connections:Gn,selected:nr,onSelect:Ki,titleOf:e=>byokTitle(e,!1),lang:C,effortFor:kiEffortFor,onEffort:(e,t)=>{HA(e.modelId,t.effort)},footer:" +
  capacity +
  "})]});";

js = js.slice(0, ooStart) + newOo + js.slice(ooEnd);

js = swap(
  js,
  ",Oo,de?",
  ",Oo,oo!==void 0&&ao&&(0,A.jsx)(KiEffortPill,{options:oo,current:po,label:ho,onPick:To,lang:C}),de?"
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
bg = swap(bg, "var background=(function(){", "var background=(function(){\n" + fs.readFileSync(path.join(__dirname, "src", "ki-background.js"), "utf8").trim() + "\n");
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
  "return[...Object.entries(pP).filter(([e])=>i===`main`||e!==`agent`).map(([i,a])=>i===`agent`?AP(e,t,r?.onChildEvent):i===`await_user_action`?PP(e):i===`skill`?FP(n):i===`save_skill`?IP():i===`delete_skill`?LP():i===`run_saved_skill`?zP(e):kP(i,a,e)),...kiMcpToolDefs()]}"
);
bg = swap(bg, ",d=u(e.llm),f=t=>new cM", ",d=(await kiMcpRefresh(),u(e.llm)),f=t=>new cM");
bg = swap(bg, "loopTools:BP(e.conversationId,t,i)", "loopTools:(await kiMcpRefresh(),BP(e.conversationId,t,i))");
bg = swap(bg, "default:n({error:`unknown type: ${e.type}`})", "default:e.type===`KI_MCP`||n({error:`unknown type: ${e.type}`})");
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
  bg = swap(bg, "var dV={debug:", "globalThis.kiTest={kiMark,setTab:je,kiNotify,kiIcon,kiFocus};var dV={debug:");
  console.log("TEST BUILD: background test hooks exposed");
}
for (const need of ["function wbExpandClosed(", "__wb_read_file", "func:Fr", "wbAssertContained", "function kiGate", "kiSaveFileTool=class", "function kiMcpToolDefs", "function kiMcpRefresh"]) {
  if (!bg.includes(need)) throw new Error("background rebuild missing " + need + " — the picker snapshot is older than the working tools");
}
if (bg.includes("frame-read.js")) throw new Error("background rebuild still injects frame-read.js, which is not in the extension");
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

const css = fs.readFileSync(path.join(original, path.basename(cssName)), "utf8") +
  "\n" + fs.readFileSync(path.join(__dirname, "src", "ki-picker.css"), "utf8");

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

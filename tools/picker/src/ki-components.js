var kiVendorSlugs={openai:"OpenAI",anthropic:"Anthropic",google:"Google","meta-llama":"Meta",mistralai:"Mistral",deepseek:"DeepSeek",minimax:"MiniMax",moonshotai:"Moonshot",qwen:"Qwen","x-ai":"xAI","z-ai":"Z.ai",cohere:"Cohere",nvidia:"NVIDIA",microsoft:"Microsoft",amazon:"Amazon",perplexity:"Perplexity"};
var kiVendorTints=[[/anthropic|claude/i,"#d97757"],[/openai|codex|gpt/i,"#10a37f"],[/google|gemini|gemma/i,"#4285f4"],[/deepseek/i,"#4d6bfe"],[/minimax/i,"#e5484d"],[/mistral/i,"#fa520f"],[/meta|llama/i,"#0081fb"],[/qwen|alibaba/i,"#7c5cff"],[/moonshot|kimi/i,"#0ea5e9"],[/groq/i,"#f55036"],[/x-?ai|grok/i,"#a1a1aa"],[/local|ollama|lm studio/i,"#16a34a"]];
var kiPalette=["#f472b6","#a78bfa","#38bdf8","#34d399","#fbbf24","#fb7185"];
var kiCopy={
en:{search:"Search models…",back:"Back to providers",none:q=>"No models match “"+q+"”",models:n=>n+(n===1?" model":" models"),via:"via",context:"Context window",id:"Model ID",unknown:"Not reported by provider",tokens:"tokens",effort:"Reasoning effort",faster:"Faster",smarter:"Smarter"},
"zh-CN":{search:"搜索模型…",back:"返回提供方",none:q=>"没有匹配“"+q+"”的模型",models:n=>n+" 个模型",via:"通过",context:"上下文窗口",id:"模型 ID",unknown:"提供方未提供",tokens:"tokens",effort:"推理强度",faster:"更快",smarter:"更聪明"}};
function kiTint(v){for(let[r,c]of kiVendorTints)if(r.test(v))return c;let h=0;for(let i=0;i<v.length;i++)h=h*31+v.charCodeAt(i)|0;return kiPalette[Math.abs(h)%kiPalette.length]}
function kiSplit(m,title,conn){let t=(title||m.modelId||"").trim(),x=/^([^:\u00b7]{1,32}?)\s*[:\u00b7]\s+(.+)$/.exec(t);if(x)return{vendor:x[1].trim(),name:x[2].trim()};let id=m.modelId||"";if(id.includes("/")){let s=id.split("/")[0];return{vendor:kiVendorSlugs[s.toLowerCase()]||s.charAt(0).toUpperCase()+s.slice(1),name:t===id?id.slice(s.length+1):t}}return{vendor:conn||"Other",name:t}}
function kiTokens(n){return n>=1e6?+(n/1e6).toFixed(n%1e6?1:0)+"M":n>=1e3?Math.round(n/1e3)+"K":String(n)}
var kiAddCopy={en:{plus:"Add files, tabs and more",add:"Add",clip:"Images, PDFs or text files",at:"Point the agent at another open tab",noTabs:"No other tabs are open"},"zh-CN":{plus:"添加文件、标签页等",add:"添加",clip:"图片、PDF 或文本文件",at:"让智能体参考另一个已打开的标签页",noTabs:"没有其他打开的标签页"}};
function kiAddItems({query,P,lang,tabs,full}){let L=kiAddCopy[lang]||kiAddCopy.en,q=query.toLowerCase();
return[{kind:"action",action:"ki_clip",ki:"clip",label:P("composer.addFile"),description:L.clip,disabled:full},{kind:"action",action:"ki_at",ki:"at",label:P("composer.addTabMention"),description:L.at,disabled:tabs===0,hint:tabs===0?L.noTabs:void 0}].filter(e=>q===""||e.label.toLowerCase().includes(q))}
function kiCmdGroup(e){return e?e.ki?"add":e.kind==="action"?"action":"skill":null}
function kiCmdHead(e,prev,P,lang){let g=kiCmdGroup(e);if(g===kiCmdGroup(prev))return null;return(0,A.jsx)("div",{className:g==="action"?"wb-command-label wb-command-label-actions":"wb-command-label",children:g==="add"?(kiAddCopy[lang]||kiAddCopy.en).add:P(g==="action"?"command.actions":"command.skills")})}
function kiSvg(d,size,extra){return(0,A.jsx)("svg",{width:size,height:size,viewBox:"0 0 14 14",fill:"none","aria-hidden":!0,className:extra,children:(0,A.jsx)("path",{d,stroke:"currentColor",strokeWidth:1.75,strokeLinecap:"round",strokeLinejoin:"round"})})}
var kiRecCheck=null;
function kiVendorIcon(v){return kiVendorIcons[String(v||"").toLowerCase().replace(/[^a-z0-9]+/g,"")]||null}
function KiGlyph({vendor,size}){let ic=kiVendorIcon(vendor),[bad,setBad]=(0,_.useState)(!1);if(ic&&!bad){let url=chrome.runtime.getURL("icon/vendors/"+ic.f);return(0,A.jsx)("span",{className:"ki-glyph ki-glyph-logo","aria-hidden":!0,style:{width:size,height:size},children:ic.mono?(0,A.jsx)("span",{className:"ki-logo-mask",style:{WebkitMaskImage:`url("${url}")`,maskImage:`url("${url}")`}}):(0,A.jsx)("img",{className:ic.img?"ki-logo-img is-avatar":"ki-logo-img",src:url,alt:"",draggable:!1,onError:()=>setBad(!0)})})}return(0,A.jsx)("span",{className:"ki-glyph","aria-hidden":!0,style:{"--ki-tint":kiTint(vendor||""),width:size,height:size,fontSize:Math.round(size*.62)},children:(vendor||"?").charAt(0).toUpperCase()})}
function KiEffortBars({level}){return(0,A.jsx)("svg",{width:12,height:12,viewBox:"0 0 14 14",fill:"none","aria-hidden":!0,children:[[1.5,8,4.5],[5.75,5,7.5],[10,2,10.5]].map(([x,y,h],i)=>(0,A.jsx)("rect",{x,y,width:2.5,height:h,rx:1,fill:"currentColor",opacity:i<level?1:.3},i))})}
function kiUseEdgeShift(ref){let[s,setS]=(0,_.useState)(0);(0,_.useLayoutEffect)(()=>{let el=ref.current;if(!el)return;let r=el.getBoundingClientRect();if(!r.width)return;let k=el.offsetWidth/r.width,cur=s/k,left=r.left-cur,right=r.right-cur,need=Math.min(Math.max(0,8-left),Math.max(0,window.innerWidth-8-right)),n=Math.round(need*k);n!==s&&setS(n)});return s}
function kiEffortLevel(options,current){let n=options.length,i=Math.max(0,options.findIndex(o=>o.effort===current));return n<2?3:1+Math.round(i/(n-1)*2)}

function KiModelCard({r,L,effort,onEffort}){
let idx=effort?Math.max(0,effort.options.findIndex(o=>o.effort===effort.current)):0,max=effort?effort.options.length-1:0,pct=max?idx/max*100:100;
return(0,A.jsxs)("div",{className:"ki-pop ki-mm-card",children:[
(0,A.jsx)("div",{className:"ki-card-name",children:r.name}),
(0,A.jsxs)("div",{className:"ki-card-vendor",children:[(0,A.jsx)(KiGlyph,{vendor:r.vendor,size:14}),(0,A.jsx)("span",{children:r.vendor}),r.conn&&r.conn!==r.vendor&&(0,A.jsx)("span",{className:"ki-card-via",children:"· "+L.via+" "+r.conn})]}),
(0,A.jsxs)("div",{className:"ki-card-facts",children:[
(0,A.jsxs)("div",{children:[(0,A.jsx)("div",{className:"ki-fact-k",children:L.context}),(0,A.jsx)("div",{className:r.m.maxContextTokens?"ki-fact-v":"ki-fact-v is-muted",children:r.m.maxContextTokens?kiTokens(r.m.maxContextTokens)+" "+L.tokens:L.unknown})]}),
(0,A.jsxs)("div",{children:[(0,A.jsx)("div",{className:"ki-fact-k",children:L.id}),(0,A.jsx)("div",{className:"ki-fact-v is-mono",children:r.m.modelId})]})]}),
effort&&(0,A.jsxs)("div",{className:"ki-card-config",children:[
(0,A.jsx)("div",{className:"ki-fact-k",children:L.effort}),
(0,A.jsxs)("div",{className:"ki-range-ends",children:[(0,A.jsx)("span",{children:L.faster}),(0,A.jsx)("span",{children:L.smarter})]}),
(0,A.jsx)("input",{type:"range",min:0,max,step:1,value:idx,className:"ki-range","aria-label":L.effort,style:{"--ki-pct":pct+"%"},onChange:e=>{let o=effort.options[+e.target.value];o&&onEffort(r.m,o)}}),
(0,A.jsx)("div",{className:"ki-range-val",children:effort.label(effort.options[idx])})]})]})}

function KiModelMenu({models,connections,selected,onSelect,titleOf,lang,footer,effortFor,onEffort}){
let L=kiCopy[lang]||kiCopy.en,
rows=models.map(m=>{let conn=connections.find(c=>c.id===m.connectionId)?.label||"",s=kiSplit(m,titleOf(m),conn);return{m,key:m.connectionId+"::"+m.modelId,conn,vendor:s.vendor,name:s.name}}),
groups=[];for(let r of rows){let g=groups.find(g=>g.vendor===r.vendor);g?g.rows.push(r):groups.push({vendor:r.vendor,rows:[r]})}
let isSel=r=>selected?.connectionId===r.m.connectionId&&selected.modelId===r.m.modelId,
flat=rows.length<=8||groups.length<=1,
[q,setQ]=(0,_.useState)(""),[view,setView]=(0,_.useState)("prov"),[prov,setProv]=(0,_.useState)(null),
[hi,setHi]=(0,_.useState)(()=>flat?Math.max(0,rows.findIndex(isSel)):Math.max(0,groups.findIndex(g=>g.rows.some(isSel)))),
inp=(0,_.useRef)(null),list=(0,_.useRef)(null),box=(0,_.useRef)(null),shift=kiUseEdgeShift(box),
query=q.trim().toLowerCase(),searching=query.length>0,items;
if(searching)items=rows.filter(r=>(r.name+" "+r.vendor+" "+r.conn+" "+r.m.modelId).toLowerCase().includes(query)).map(r=>({kind:"model",r,showVendor:!0}));
else if(flat)items=groups.flatMap(g=>[...(groups.length>1?[{kind:"label",text:g.vendor}]:[]),...g.rows.map(r=>({kind:"model",r}))]);
else if(view==="models"&&prov)items=(groups.find(g=>g.vendor===prov)?.rows||[]).map(r=>({kind:"model",r}));
else items=groups.map(g=>({kind:"prov",g}));
let nav=items.filter(i=>i.kind!=="label"),cur=Math.min(hi,nav.length-1),showBack=!searching&&!flat&&view==="models",
openItem=i=>{if(!i)return;if(i.kind==="prov"){setView("models"),setProv(i.g.vendor),setHi(Math.max(0,i.g.rows.findIndex(isSel)));return}onSelect(i.r.m)},
back=()=>{setView("prov"),setHi(Math.max(0,groups.findIndex(g=>g.vendor===prov)))},
onKey=e=>{let k=e.key;if(k==="ArrowDown"||k==="ArrowUp"){e.preventDefault();let n=nav.length;n&&setHi((cur+(k==="ArrowDown"?1:-1)+n)%n)}else if(k==="Enter"){e.preventDefault(),openItem(nav[cur])}else if(k==="ArrowRight"&&!q&&nav[cur]?.kind==="prov"){e.preventDefault(),openItem(nav[cur])}else if((k==="ArrowLeft"||k==="Backspace")&&!q&&showBack){e.preventDefault(),back()}else if(k==="Escape"&&(q||showBack)){e.preventDefault(),e.stopPropagation(),q?(setQ(""),setHi(0)):back()}};
(0,_.useEffect)(()=>{inp.current?.focus()},[view]);
(0,_.useEffect)(()=>{list.current?.querySelector(".ki-mm-row.is-hi")?.scrollIntoView({block:"nearest"})},[cur,view,q]);
let n=-1,card=nav[cur]?.kind==="model"?nav[cur].r:null;
return(0,A.jsxs)("div",{ref:box,className:"ki-mm",style:shift?{right:-shift}:void 0,children:[
card&&(0,A.jsx)(KiModelCard,{r:card,L,effort:effortFor(card.m),onEffort}),
(0,A.jsxs)("div",{role:"menu",className:"ki-pop ki-mm-menu",children:[
(0,A.jsxs)("div",{className:"ki-mm-head",children:[
showBack&&(0,A.jsx)("button",{type:"button",className:"ki-mm-back","aria-label":L.back,title:L.back,onClick:back,children:kiSvg("M8.5 3 4.5 7l4 4",10)}),
(0,A.jsx)("input",{ref:inp,className:"ki-mm-search",value:q,placeholder:showBack?prov:L.search,"aria-label":L.search,spellCheck:!1,autoComplete:"off",onChange:e=>{setQ(e.target.value),setHi(0)},onKeyDown:onKey}),
(0,A.jsx)("svg",{width:12,height:12,viewBox:"0 0 14 14",fill:"none","aria-hidden":!0,className:"ki-mm-glass",children:[(0,A.jsx)("circle",{cx:6.2,cy:6.2,r:4.2,stroke:"currentColor",strokeWidth:1.4}),(0,A.jsx)("path",{d:"M9.4 9.4 12.5 12.5",stroke:"currentColor",strokeWidth:1.4,strokeLinecap:"round"})]})]}),
(0,A.jsxs)("div",{ref:list,className:"ki-mm-list",children:[items.map(i=>{
if(i.kind==="label")return(0,A.jsx)("div",{className:"ki-mm-label",children:i.text},"l:"+i.text);
let at=++n,h=at===cur?" is-hi":"";
if(i.kind==="prov")return(0,A.jsxs)("button",{type:"button",role:"menuitem",className:"ki-mm-row"+h,onMouseEnter:()=>setHi(at),onClick:()=>openItem(i),children:[(0,A.jsx)(KiGlyph,{vendor:i.g.vendor,size:18}),(0,A.jsx)("span",{className:"ki-mm-name",children:i.g.vendor}),i.g.rows.some(isSel)&&(0,A.jsx)("span",{className:"ki-mm-dot","aria-hidden":!0}),(0,A.jsx)("span",{className:"ki-mm-count",children:L.models(i.g.rows.length)}),kiSvg("M5.5 3 9.5 7l-4 4",9,"ki-mm-chev")]},"p:"+i.g.vendor);
let s=isSel(i.r);
return(0,A.jsxs)("button",{type:"button",role:"menuitemradio","aria-checked":s,title:i.r.name,className:"ki-mm-row"+h,onMouseEnter:()=>setHi(at),onClick:()=>openItem(i),children:[(0,A.jsx)(KiGlyph,{vendor:i.r.vendor,size:18}),(0,A.jsxs)("span",{className:"ki-mm-copy",children:[(0,A.jsx)("span",{className:"ki-mm-name",children:i.r.name}),i.showVendor&&(0,A.jsx)("span",{className:"ki-mm-sub",children:i.r.conn&&i.r.conn!==i.r.vendor?i.r.vendor+" · "+i.r.conn:i.r.vendor})]}),s&&kiSvg("M2.5 7.5 5.5 10.5 11.5 3.5",12,"ki-mm-check")]},i.r.key)}),
items.length===0&&(0,A.jsx)("div",{className:"ki-mm-empty",children:L.none(q.trim())})]}),
footer&&(0,A.jsx)("div",{className:"ki-mm-foot",children:footer})]})]})}

// Fast browse switch in the model menu. The worker owns the setting and checks a
// pasted key before keeping it; with no key and no OpenRouter provider the switch
// opens the key box instead. Busy controls ignore clicks rather than going
// disabled, which would drop keyboard focus to the page.
var kiFastCopy={en:{name:"Fast browse",tip:"The agent finishes page tasks like signing in or reaching a form in one step, using a fast model.",off:"Off",add:"Add a key to turn on",key:"TypeSafe or OpenRouter key",on:"Turn on",checking:"Checking…",get:"Get a key:",fastest:"fastest"},
"zh-CN":{name:"快速浏览",tip:"智能体使用快速模型一步完成登录、打开表单等页面任务。",off:"已关闭",add:"添加密钥以开启",key:"TypeSafe 或 OpenRouter 密钥",on:"开启",checking:"正在检查…",get:"获取密钥：",fastest:"最快"}};
function kiFastAsk(op,extra){return chrome.runtime.sendMessage({type:"KI_BROWSE",op,...extra}).then(r=>{if(r?.ok!==!0)throw Error(r?.error||"The extension did not respond.");return r.result})}
function KiFastBrowse({lang}){
let L=kiFastCopy[lang]||kiFastCopy.en,[st,setSt]=(0,_.useState)(null),[open,setOpen]=(0,_.useState)(!1),[key,setKey]=(0,_.useState)(""),[busy,setBusy]=(0,_.useState)(!1),[err,setErr]=(0,_.useState)(""),inp=(0,_.useRef)(null),sw=(0,_.useRef)(null);
(0,_.useEffect)(()=>{let live=!0;kiFastAsk("status").then(s=>{if(!live)return;setSt(s);s.error&&(setErr(s.error),s.available||setOpen(!0))},e=>{live&&setErr(e.message)});return()=>{live=!1}},[]);
(0,_.useEffect)(()=>{open&&inp.current?.focus()},[open]);
let on=!!st?.ready,
save=async change=>{setBusy(!0),setErr("");try{let s=await kiFastAsk("save",change);setSt(s);s.ready&&open&&(sw.current?.focus(),setOpen(!1),setKey(""))}catch(e){setErr(e.message)}finally{setBusy(!1)}},
flip=()=>{if(!st||busy)return;st.ready||st.available?save({on:!st.ready}):setOpen(o=>!o)};
return(0,A.jsxs)("div",{className:"ki-fb",children:[
(0,A.jsxs)("button",{ref:sw,type:"button",role:"switch","aria-checked":on,"aria-expanded":st&&!st.available?open:void 0,"aria-busy":busy||void 0,title:L.tip,className:"ki-mm-row ki-fb-row",onClick:flip,children:[
(0,A.jsx)("span",{className:"ki-fb-glyph",children:kiSvg("M8 1.5 3 8h4l-1 4.5L11 6H7l1-4.5Z",13)}),
(0,A.jsxs)("span",{className:"ki-mm-copy",children:[(0,A.jsx)("span",{className:"ki-mm-name",children:L.name}),(0,A.jsx)("span",{className:"ki-mm-sub",children:!st?"…":on?st.label:st.available?L.off:L.add})]}),
(0,A.jsx)("span",{className:"wb-toggle wb-toggle--sm"+(on?" is-on":""),"aria-hidden":!0,children:(0,A.jsx)("span",{className:"wb-toggle-thumb"})})]}),
open&&(0,A.jsxs)("form",{className:"ki-fb-form",onSubmit:e=>{e.preventDefault(),key.trim()&&!busy&&save({key:key.trim()})},children:[
(0,A.jsxs)("div",{className:"ki-fb-line",children:[
(0,A.jsx)("input",{ref:inp,type:"password",className:"ki-fb-key",value:key,placeholder:L.key,"aria-label":L.key,spellCheck:!1,autoComplete:"off",onChange:e=>setKey(e.target.value)}),
(0,A.jsx)("button",{type:"submit",className:"ki-fb-go","aria-disabled":busy||!key.trim(),children:busy?L.checking:L.on})]}),
(0,A.jsxs)("div",{className:"ki-fb-hint",children:[L.get," ",(0,A.jsx)("a",{href:"https://console.typesafe.ai/keys",target:"_blank",rel:"noopener",children:"TypeSafe"})," (",L.fastest,") · ",(0,A.jsx)("a",{href:"https://openrouter.ai/settings/keys",target:"_blank",rel:"noopener",children:"OpenRouter"})]})]}),
err&&(0,A.jsx)("div",{className:"ki-fb-err",role:"alert",children:err})]})}

function kiStepText(n,lang){return lang==="zh-CN"?n+" 步":n+(n===1?" step":" steps")}
function KiEffortPill({options,current,label,onPick,lang}){
let L=kiCopy[lang]||kiCopy.en,[open,setOpen]=(0,_.useState)(!1),ref=(0,_.useRef)(null),menu=(0,_.useRef)(null),shift=kiUseEdgeShift(menu),sel=options.find(o=>o.effort===current)||options[0];
(0,_.useEffect)(()=>{if(!open)return;let d=e=>{ref.current&&!ref.current.contains(e.target)&&setOpen(!1)},k=e=>{e.key==="Escape"&&setOpen(!1)};return window.addEventListener("mousedown",d),window.addEventListener("keydown",k),()=>{window.removeEventListener("mousedown",d),window.removeEventListener("keydown",k)}},[open]);
return(0,A.jsxs)("div",{ref,className:"wb-pop-anchor ki-effort",children:[
(0,A.jsxs)("button",{type:"button",className:"wb-mode-toggle ki-effort-toggle","aria-haspopup":"menu","aria-expanded":open,title:L.effort,onClick:()=>setOpen(e=>!e),children:[(0,A.jsx)(KiEffortBars,{level:kiEffortLevel(options,current)}),(0,A.jsx)("span",{className:"ki-effort-label",children:label(sel)}),kiSvg("M3 5.5 7 9.5l4-4",9)]}),
open&&(0,A.jsxs)("div",{ref:menu,role:"menu",className:"ki-pop ki-effort-menu",style:shift?{right:-shift}:void 0,children:[(0,A.jsx)("div",{className:"ki-mm-label",children:L.effort}),options.map(o=>{let s=o.effort===current;return(0,A.jsxs)("button",{type:"button",role:"menuitemradio","aria-checked":s,className:"ki-mm-row",onClick:()=>{setOpen(!1),onPick(o)},children:[(0,A.jsxs)("span",{className:"ki-mm-copy",children:[(0,A.jsx)("span",{className:"ki-mm-name",children:label(o)}),o.description&&(0,A.jsx)("span",{className:"ki-mm-sub is-wrap",children:o.description})]}),s&&kiSvg("M2.5 7.5 5.5 10.5 11.5 3.5",12,"ki-mm-check")]},o.effort)})]})]})}

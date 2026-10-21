var kiLiveCopy={
en:{jump:"Jump to this step",slow:"Taking longer than usual",approve:"Waiting for your approval",handoff:"Waiting for you",review:"Review",thinking:"Thinking…",writing:"Writing the reply…",loading:"Loading page",paused:"Paused",pausing:"Pausing after this step…",pause:"Pause",resume:"Resume",skip:"Skip step",steps:"Steps",close:"Close",open:"Show steps",steerPh:"Tell it something without stopping…",send:"Send",sent:"Sent. It will read this before its next step.",done:"Done",stopped:"Stopped",failed:"Failed",dismiss:"Dismiss",none:"No steps yet",skipped:"skipped",pages:n=>n+(n===1?" page":" pages"),failedN:n=>n+" failed"},
"zh-CN":{jump:"跳到这一步",slow:"耗时比平时长",approve:"等待你的批准",handoff:"等待你操作",review:"查看",thinking:"思考中…",writing:"正在写回复…",loading:"正在加载页面",paused:"已暂停",pausing:"这一步结束后暂停…",pause:"暂停",resume:"继续",skip:"跳过这一步",steps:"步骤",close:"关闭",open:"查看步骤",steerPh:"不中断地告诉它一些事…",send:"发送",sent:"已发送，它会在下一步之前看到。",done:"已完成",stopped:"已停止",failed:"失败",dismiss:"关闭",none:"还没有步骤",skipped:"已跳过",pages:n=>n+" 个页面",failedN:n=>n+" 个失败"}};
var kiSession=null,kiSeenRun=null;
function kiSend(op,extra){if(!kiSession)return Promise.resolve(null);try{return chrome.runtime.sendMessage({type:"KI_CTL",session:kiSession,op,...extra}).catch(()=>null)}catch{return Promise.resolve(null)}}
function kiReportFocus(){kiSend("focus",{visible:document.visibilityState==="visible"})}
typeof document<"u"&&(document.addEventListener("visibilitychange",kiReportFocus),window.addEventListener("pagehide",()=>kiSend("focus",{visible:!1})));
function kiClock(s){return s<60?s+"s":Math.floor(s/60)+":"+String(s%60).padStart(2,"0")}
function kiJumpTo(id){let rows=[...document.querySelectorAll(".wb-stream [data-wb-item]")],el=(id&&rows.find(r=>r.getAttribute("data-wb-item")===id))||rows[rows.length-1];if(!el)return;el.scrollIntoView({block:"center",behavior:"smooth"});el.classList.remove("ki-flash");void el.offsetWidth;el.classList.add("ki-flash");setTimeout(()=>el.classList.remove("ki-flash"),1400)}
function kiSpin(n){return(0,A.jsxs)("svg",{width:n,height:n,viewBox:"0 0 14 14",fill:"none",children:[(0,A.jsx)("circle",{cx:7,cy:7,r:5.5,stroke:"currentColor",strokeOpacity:.2,strokeWidth:1.75}),(0,A.jsx)("path",{d:"M12.5 7a5.5 5.5 0 0 0-5.5-5.5",stroke:"currentColor",strokeWidth:1.75,strokeLinecap:"round"})]})}
function kiRunOf(items){let uid=null,tools=[],notices=[],ask=null,run=null,last=null;for(let t=items.length-1;t>=0;--t){let n=items[t];if(!n)continue;if(n.kind==="user"){uid=n.id;break}last||=n;n.kind==="tool"&&(tools.unshift(n),!run&&n.status==="running"&&(run=n));n.kind==="notice"&&notices.push(n);!ask&&(n.kind==="permission"||n.kind==="handoff")&&(ask=n)}return{uid,tools,notices,ask,run,last}}
function kiUseOutside(ref,open,close){(0,_.useEffect)(()=>{if(!open)return;let down=e=>{ref.current&&!ref.current.contains(e.target)&&close()},key=e=>{e.key==="Escape"&&close()};document.addEventListener("mousedown",down),document.addEventListener("keydown",key);return()=>{document.removeEventListener("mousedown",down),document.removeEventListener("keydown",key)}},[open])}
function kiStepState(s){return s.status==="running"?"running":typeof s.output=="string"&&s.output.startsWith("The user skipped")?"skipped":s.status==="error"||s.isError?"error":"ok"}
var kiDetailCopy={en:{params:"Parameters",result:"Result",running:"Still running…",noParams:"No parameters",noResult:"No output",showInChat:"Show in chat",copy:"Copy result",copied:"Copied",more:"Show details"},"zh-CN":{params:"参数",result:"结果",running:"仍在运行…",noParams:"无参数",noResult:"无输出",showInChat:"在对话中查看",copy:"复制结果",copied:"已复制",more:"查看详情"}};
function kiPretty(v,max){let t;if(typeof v=="string"){t=v;try{let j=JSON.parse(v);j&&typeof j=="object"&&(t=JSON.stringify(j,null,2))}catch{}}else try{t=JSON.stringify(v,(k,x)=>k.startsWith("_")?void 0:x,2)}catch{t=String(v)}t=t??"";return t.length>max?t.slice(0,max)+"\n…":t}
function kiImgSrc(x){return typeof x=="string"?x:x?.url||x?.dataUrl||x?.imageUrl||(x?.data&&x?.mimeType?"data:"+x.mimeType+";base64,"+x.data:null)}
function KiStepDetail({s,st,lang}){
let L=kiDetailCopy[lang]||kiDetailCopy.en,[copied,setCopied]=(0,_.useState)(!1),args=kiPretty(s.args??{},2e3),out=st==="running"?"":kiPretty(s.output??"",6e3),imgs=(s.images??[]).map(kiImgSrc).filter(Boolean).slice(0,3);
return(0,A.jsxs)("div",{className:"ki-step-detail",children:[
(0,A.jsx)("div",{className:"ki-detail-k",children:L.params}),
(0,A.jsx)("pre",{className:"ki-detail-v",children:args==="{}"?L.noParams:args}),
(0,A.jsx)("div",{className:"ki-detail-k",children:L.result}),
(0,A.jsx)("pre",{className:st==="error"?"ki-detail-v is-error":"ki-detail-v",children:st==="running"?L.running:out||L.noResult}),
imgs.length>0&&(0,A.jsx)("div",{className:"ki-detail-imgs",children:imgs.map((src,i)=>(0,A.jsx)("img",{src,alt:"",className:"ki-detail-img"},i))}),
(0,A.jsxs)("div",{className:"ki-detail-actions",children:[
out&&(0,A.jsxs)("button",{type:"button",className:"ki-chip",onClick:()=>{navigator.clipboard?.writeText(s.output??"").then(()=>{setCopied(!0),setTimeout(()=>setCopied(!1),1500)},()=>{})},children:[kiSvg(copied?"M2.5 7.5 5.5 10.5 11.5 3.5":"M5 5h6v6H5zM3 9V3h6",11),copied?L.copied:L.copy]}),
(0,A.jsxs)("button",{type:"button",className:"ki-chip",onClick:()=>kiJumpTo(s.id),children:[kiSvg("M7 2.5v9M3 7.5l4 4 4-4",11),L.showInChat]})]})]})}
function KiStepList({steps,lang,now}){
let L=kiLiveCopy[lang]||kiLiveCopy.en,D=kiDetailCopy[lang]||kiDetailCopy.en,ref=(0,_.useRef)(null),[open,setOpen]=(0,_.useState)(()=>new Set);
(0,_.useEffect)(()=>{let el=ref.current;el&&(el.scrollTop=el.scrollHeight)},[steps.length]);
if(steps.length===0)return(0,A.jsx)("div",{className:"ki-steps-empty",children:L.none});
let toggle=id=>setOpen(o=>{let n=new Set(o);return n.has(id)?n.delete(id):n.add(id),n});
return(0,A.jsx)("ol",{ref,className:"ki-steps-list",children:steps.map((s,i)=>{let end=s.endedAt??(s.status==="running"?now:null),dur=s.startedAt&&end!=null?Math.max(0,Math.round((end-s.startedAt)/1e3)):null,t=er(s.name,s.args),st=kiStepState(s),isOpen=open.has(s.id);
return(0,A.jsxs)("li",{className:isOpen?"is-open":void 0,children:[(0,A.jsxs)("button",{type:"button",className:"ki-step is-"+st,title:D.more,"aria-expanded":isOpen,onClick:()=>toggle(s.id),children:[
(0,A.jsx)("span",{className:"ki-step-n",children:i+1}),
st==="running"?(0,A.jsx)("span",{className:"wb-livebar-spin ki-step-icon",children:kiSpin(11)}):kiSvg(st==="error"?"M4 4l6 6M10 4l-6 6":st==="skipped"?"M3.5 3.5 8 7l-4.5 3.5zM10.5 3.5v7":"M2.5 7.5 5.5 10.5 11.5 3.5",11,"ki-step-icon"),
(0,A.jsx)("span",{className:"ki-step-name",children:tr(s.name,lang)}),
t&&(0,A.jsx)("span",{className:"ki-step-target",children:t}),
st==="skipped"&&(0,A.jsx)("span",{className:"ki-step-tag",children:L.skipped}),
(0,A.jsx)("span",{className:"ki-step-time",children:dur==null?"":kiClock(dur)}),
kiSvg(isOpen?"M3 8.5 7 4.5l4 4":"M3 5.5 7 9.5l4-4",9,"ki-step-chev")]}),
isOpen&&(0,A.jsx)(KiStepDetail,{s,st,lang})]},s.id)})})}
function KiLivebar({label,steps,lang,items,session}){
session&&(kiSession=session);
let L=kiLiveCopy[lang]||kiLiveCopy.en,{uid,tools,ask,run,last}=kiRunOf(items);
kiSeenRun=uid;
let[open,setOpen]=(0,_.useState)(!1),[paused,setPaused]=(0,_.useState)(!1),[held,setHeld]=(0,_.useState)(!1),[steer,setSteer]=(0,_.useState)(""),[note,setNote]=(0,_.useState)(""),box=(0,_.useRef)(null);
kiUseOutside(box,open,()=>setOpen(!1));
(0,_.useEffect)(()=>{kiReportFocus(),kiSend("state").then(r=>{r&&(setPaused(!!r.paused),setHeld(!!r.held))})},[session]);
(0,_.useEffect)(()=>{if(!paused){setHeld(!1);return}let t=setInterval(()=>kiSend("state").then(r=>{r&&setHeld(!!r.held)}),700);return()=>clearInterval(t)},[paused]);
let still=paused&&held,key=ask?"ask:"+ask.id:still?"paused":run?run.id:"wait:"+steps,[mark,setMark]=(0,_.useState)(()=>({key,at:Date.now()})),[now,setNow]=(0,_.useState)(()=>Date.now());
(0,_.useEffect)(()=>{mark.key!==key&&setMark({key,at:Date.now()})},[key]);
(0,_.useEffect)(()=>{let t=setInterval(()=>setNow(Date.now()),1e3);return()=>clearInterval(t)},[]);
let at=mark.key===key?mark.at:now,start=ask||still?at:run?.startedAt??at,secs=Math.max(0,Math.floor((now-start)/1e3)),slow=!ask&&!paused&&secs>=30,step=run?er(run.name,run.args):"",
text=ask?ask.kind==="permission"?L.approve:L.handoff:paused?still?L.paused:L.pausing:run?/^(browser_)?navigate$/.test(run.name)?L.loading:label:last?.kind==="assistant"&&last.streaming?L.writing:L.thinking,
target=ask&&run?(label+" "+step).trim():step,
mode=ask?" is-asking":paused?" is-paused":"",
togglePause=()=>{let p=!paused;setPaused(p),kiSend("pause",{paused:p}).then(r=>{r&&setPaused(!!r.paused)})},
send=e=>{e.preventDefault();let t=steer.trim();t&&kiSend("steer",{text:t}).then(r=>{r?.ok&&(setSteer(""),setNote(L.sent),setTimeout(()=>setNote(""),4e3))})};
return(0,A.jsxs)("div",{ref:box,className:"wb-livebar"+mode+(open?" is-open":""),role:"status","aria-live":"polite",children:[
open&&(0,A.jsxs)("div",{className:"ki-pop ki-steps",role:"dialog","aria-label":L.steps,children:[
(0,A.jsxs)("div",{className:"ki-steps-head",children:[
(0,A.jsx)("span",{className:"ki-steps-title",children:L.steps}),
(0,A.jsx)("span",{className:"ki-steps-count",children:tools.length}),
(0,A.jsx)("span",{className:"ki-steps-grow"}),
(0,A.jsxs)("button",{type:"button",className:"ki-chip"+(paused?" is-on":""),onClick:togglePause,children:[kiSvg(paused?"M4.5 3 11 7l-6.5 4z":"M5 3.5v7M9 3.5v7",11),paused?L.resume:L.pause]}),
(0,A.jsxs)("button",{type:"button",className:"ki-chip",disabled:!run||!!ask,onClick:()=>run&&kiSend("skip",{toolCallId:run.toolCallId}),children:[kiSvg("M3.5 3.5 8 7l-4.5 3.5zM10.5 3.5v7",11),L.skip]}),
(0,A.jsx)("button",{type:"button",className:"ki-icon-x","aria-label":L.close,onClick:()=>setOpen(!1),children:kiSvg("M4 4l6 6M10 4l-6 6",10)})]}),
(0,A.jsx)(KiStepList,{steps:tools,lang,now}),
(0,A.jsxs)("form",{className:"ki-steer",onSubmit:send,children:[
(0,A.jsx)("input",{className:"ki-steer-input",value:steer,placeholder:L.steerPh,"aria-label":L.steerPh,onChange:e=>setSteer(e.target.value),autoFocus:!0}),
(0,A.jsx)("button",{type:"submit",className:"ki-steer-send",disabled:!steer.trim(),"aria-label":L.send,children:kiSvg("M7 11.5v-9M3 6.5l4-4 4 4",12)})]}),
note&&(0,A.jsx)("div",{className:"ki-steer-note",children:note})]}),
(0,A.jsxs)("button",{type:"button",className:"ki-live-row","aria-expanded":ask?void 0:open,title:ask?L.review:L.open,"aria-label":text+(target?" "+target:"")+" · "+(ask?L.review:L.open),onClick:()=>ask?kiJumpTo(ask.id):setOpen(o=>!o),children:[
ask?(0,A.jsx)("span",{className:"ki-live-ask","aria-hidden":!0}):still?kiSvg("M5 3.5v7M9 3.5v7",13,"ki-live-pause"):(0,A.jsx)("span",{className:"wb-livebar-spin","aria-hidden":!0,children:kiSpin(13)}),
(0,A.jsx)("span",{className:"wb-livebar-label",children:text}),
target&&(0,A.jsx)("span",{className:"ki-live-target",children:target}),
(0,A.jsxs)("span",{className:"ki-live-meta",children:[steps>0&&(0,A.jsx)("span",{children:kiStepText(steps,lang)}),(0,A.jsx)("span",{className:slow?"ki-live-time is-slow":"ki-live-time",title:slow?L.slow:void 0,children:kiClock(secs)})]}),
ask?(0,A.jsx)("span",{className:"ki-live-review",children:L.review}):kiSvg(open?"M3 8.5 7 4.5l4 4":"M3 5.5 7 9.5l4-4",9,"ki-live-jump")]})]})}
function KiRunSummary({items,lang}){
let L=kiLiveCopy[lang]||kiLiveCopy.en,{uid,tools,notices}=kiRunOf(items),[hidden,setHidden]=(0,_.useState)(null),[open,setOpen]=(0,_.useState)(!1),box=(0,_.useRef)(null);
kiUseOutside(box,open,()=>setOpen(!1));
if(!uid||uid!==kiSeenRun||hidden===uid||tools.length===0)return null;
let failed=tools.filter(s=>kiStepState(s)==="error").length,
status=notices.some(n=>n.level==="error")?"failed":notices.some(n=>n.variant==="status")?"stopped":"done",
starts=tools.map(s=>s.startedAt).filter(Boolean),ends=tools.map(s=>s.endedAt??s.startedAt).filter(Boolean),
secs=starts.length?Math.max(0,Math.round((Math.max(...ends)-Math.min(...starts))/1e3)):null,
pages=new Set(tools.filter(s=>/^(browser_)?(navigate|create_tab)$/.test(s.name)&&typeof s.args?.url=="string").map(s=>{try{return new URL(s.args.url).hostname.replace(/^www\./,"")}catch{return null}}).filter(Boolean)).size,
meta=[kiStepText(tools.length,lang),secs!=null&&kiClock(secs),pages>0&&L.pages(pages)].filter(Boolean);
return(0,A.jsxs)("div",{ref:box,className:"wb-livebar is-summary is-"+status+(open?" is-open":""),role:"status",children:[
open&&(0,A.jsxs)("div",{className:"ki-pop ki-steps",role:"dialog","aria-label":L.steps,children:[
(0,A.jsxs)("div",{className:"ki-steps-head",children:[(0,A.jsx)("span",{className:"ki-steps-title",children:L.steps}),(0,A.jsx)("span",{className:"ki-steps-count",children:tools.length}),(0,A.jsx)("span",{className:"ki-steps-grow"}),(0,A.jsx)("button",{type:"button",className:"ki-icon-x","aria-label":L.close,onClick:()=>setOpen(!1),children:kiSvg("M4 4l6 6M10 4l-6 6",10)})]}),
(0,A.jsx)(KiStepList,{steps:tools,lang,now:Date.now()})]}),
(0,A.jsxs)("button",{type:"button",className:"ki-live-row","aria-expanded":open,title:L.open,onClick:()=>setOpen(o=>!o),children:[
kiSvg(status==="done"?"M2.5 7.5 5.5 10.5 11.5 3.5":status==="stopped"?"M4 4h6v6H4z":"M4 4l6 6M10 4l-6 6",13,"ki-sum-icon"),
(0,A.jsx)("span",{className:"wb-livebar-label",children:L[status]}),
(0,A.jsxs)("span",{className:"ki-live-meta",children:[...meta.map((m,i)=>(0,A.jsx)("span",{children:m},i)),failed>0&&(0,A.jsx)("span",{className:"ki-sum-failed",children:L.failedN(failed)})]}),
kiSvg(open?"M3 8.5 7 4.5l4 4":"M3 5.5 7 9.5l4-4",9,"ki-live-jump")]}),
(0,A.jsx)("button",{type:"button",className:"ki-icon-x ki-sum-x","aria-label":L.dismiss,onClick:()=>setHidden(uid),children:kiSvg("M4 4l6 6M10 4l-6 6",10)})]})}

import '../compat/dast-inputs.js';
const inputs=globalThis.CertXDastInputs;
const clone=value=>structuredClone(value);
function fields(request,location){
 if(location==='query')return inputs.parseEncoded(new URL(request.url).search.slice(1));
 if(location==='form')return inputs.parseEncoded(request.body||'');
 if(location==='json')return inputs.parseJson(request.body||'');
 return [];
}
function replaceJsonInput(request,selector,value){
 const field=fields(request,'json').find(item=>item.name===selector.name&&item.index===selector.index);
 if(!field)throw Error('Selected JSON input no longer exists.');
 const body=request.body.slice(0,field.start)+JSON.stringify(String(value))+request.body.slice(field.end);
 inputs.parseJson(body);return {...request,body};
}
function resolve(request,mutation,selected){
 if(selected){if(selected.location==='json'){if(!fields(request,'json').some(field=>field.name===selected.name&&field.index===selected.index))throw Error('Selected JSON input no longer exists.');}else inputs.getRequestInput(request,selected);return selected;}
 let location=String(mutation.location||'param').toLowerCase(),name=String(mutation.paramKey||'');
 const prefix=/^(param|query|form|body|json|header):/.exec(name);if(prefix){name=name.slice(prefix[0].length);if(location==='param'&&prefix[1]!=='param')location=prefix[1];}
 const headers=Object.fromEntries(Object.entries(request.headers||{}).map(([key,value])=>[key.toLowerCase(),value]));
 if(location==='header'){
  if(/^(cookie|authorization|proxy-authorization|host|content-length)$/i.test(name))throw Error('This header cannot be mutated by the isolated-browser transport; use an explicit account or raw request workflow.');
  const keys=Object.keys(request.headers||{}).filter(key=>key.toLowerCase()===name.toLowerCase());if(keys.length!==1)throw Error('Candidate header is missing or ambiguous.');
  return {location:'header',name:keys[0],index:0};
 }
 const json=String(headers['content-type']||'').toLowerCase().includes('json');
 if(location==='body')location=json?'json':'form';
 const locations=location==='param'?['query',...(['GET','HEAD'].includes(String(request.method||'GET').toUpperCase())?[]:[json?'json':'form'])]:[location];
 const matches=[];
 for(const kind of locations){
  if(!['query','form','json'].includes(kind))throw Error('Use a supported query, form, or JSON input for candidate mutation.');
  const escape=part=>part.replaceAll('~','~0').replaceAll('/','~1');
  const pointers=name.startsWith('/')?[name]:['/'+escape(name),'/'+name.replace(/^\$(?:\.|(?=\[))/,'').replace(/\[(\d+)\]/g,'.$1').replace(/^\./,'').split('.').map(escape).join('/')];
  for(const field of fields(request,kind))if((kind==='json'?pointers.includes(field.name):field.name===name)&&(mutation.index==null||field.index===mutation.index))matches.push({location:kind,name:field.name,index:field.index});
 }
 if(matches.length!==1)throw Error(matches.length?'Candidate input is ambiguous; provide an exact selector.':'Candidate input is missing from the captured request.');
 return matches[0];
}
export function prepareCandidateJob(job,selector){
 const result=clone(job);result.certXPreparedMutations=true;
 result.playbook.mutations=(result.playbook.mutations||[]).map(mutation=>{
  try{const selected=resolve(result.requestSeed,mutation,selector);return {...mutation,selector:selected,prepared:(mutation.values||[]).map(value=>({value,request:selected.location==='header'?{...result.requestSeed,headers:{...result.requestSeed.headers,[selected.name]:String(value)}}:selected.location==='json'?replaceJsonInput(result.requestSeed,selected,value):inputs.replaceRequestInput(result.requestSeed,selected,String(value))}))};}
  catch(error){return {...mutation,prepared:(mutation.values||[]).map(value=>({value,error:error.message}))};}
 });
 return result;
}

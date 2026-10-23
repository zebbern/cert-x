// PTK v10 OpenAPI parsing, extracted from its standalone Swagger UI.
import '../ptk/packages/js-yaml/js-yaml.min.js';
import {scopeAllows} from '../config.mjs';
import {sensitiveArtifactStorage} from '../ptk/background/sensitiveArtifactStore.js';
function getYamlParser() {
    const parser = globalThis.jsyaml
    if (!parser || typeof parser.load !== "function") {
        throw new Error("YAML parser is unavailable.")
    }
    return parser
}

function parseJson(text) {
    try {
        return JSON.parse(text)
    } catch (error) {
        throw new Error(`Invalid JSON: ${error.message}`)
    }
}

function parseYaml(text) {
    try {
        return getYamlParser().load(text)
    } catch (error) {
        throw new Error(`Invalid YAML: ${error.message}`)
    }
}

function parseSpec(text, sourceName = "", contentType = "") {
    const trimmed = (text || "").trim()
    if (!trimmed) {
        throw new Error("Spec content is empty.")
    }

    const source = sourceName.toLowerCase()
    const ct = contentType.toLowerCase()
    const looksLikeJson = trimmed.startsWith("{") || trimmed.startsWith("[")
    const preferJson = source.endsWith(".json") || ct.includes("json") || looksLikeJson

    let parsed
    let jsonError = null
    let yamlError = null

    if (preferJson) {
        try {
            parsed = parseJson(trimmed)
        } catch (error) {
            jsonError = error
        }
        if (parsed === undefined) {
            try {
                parsed = parseYaml(trimmed)
            } catch (error) {
                yamlError = error
            }
        }
    } else {
        try {
            parsed = parseYaml(trimmed)
        } catch (error) {
            yamlError = error
        }
        if (parsed === undefined) {
            try {
                parsed = parseJson(trimmed)
            } catch (error) {
                jsonError = error
            }
        }
    }

    if (parsed === undefined) {
        const parseHints = [jsonError?.message, yamlError?.message].filter(Boolean).join(" | ")
        throw new Error(parseHints || "Unable to parse spec as JSON or YAML.")
    }

    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("Spec root must be a JSON/YAML object.")
    }

    if (!parsed.openapi && !parsed.swagger) {
        throw new Error("Spec must include `openapi` or `swagger` at the root.")
    }

    return parsed
}

function specSummary(specObj) {
    const title = specObj?.info?.title || "Untitled API"
    const version = specObj?.info?.version || specObj?.openapi || specObj?.swagger || "unknown"
    return { title, version }
}
export { parseSpec, specSummary };
export function describeOperations(spec) {
  const methods=new Set(['get','put','post','delete','options','head','patch','trace']);
  return Object.entries(spec.paths||{}).flatMap(([path,item])=>Object.entries(item||{}).filter(([method,value])=>methods.has(method)&&value&&typeof value==='object').map(([method,operation])=>({path,method:method.toUpperCase(),operationId:operation.operationId||null,summary:operation.summary||'',parameters:[...(Array.isArray(item.parameters)?item.parameters:[]),...(Array.isArray(operation.parameters)?operation.parameters:[])],requestBody:operation.requestBody||null,security:operation.security??spec.security??[],responses:operation.responses||{}})));
}

export function resolveApiRefs(document, {documents={},baseUrl='',scope}={}) {
  const pointer=(root,fragment)=>fragment.split('/').slice(1).reduce((value,key)=>value?.[decodeURIComponent(key).replace(/~1/g,'/').replace(/~0/g,'~')],root);
  function walk(value,root,base,seen=new Set()) {
    if(Array.isArray(value))return value.map(item=>walk(item,root,base,seen));
    if(!value||typeof value!=='object')return value;
    if(value.$ref){
      const ref=String(value.$ref),[path,fragment='']=ref.split('#');let target=root,nextBase=base;
      if(path){nextBase=new URL(path,base||undefined).href;if(!scopeAllows(nextBase,scope||{}))throw Error('External API reference is outside scope: '+nextBase);if(!Object.hasOwn(documents,nextBase))throw Error('Supply the external reference explicitly in documents: '+nextBase);target=documents[nextBase];}
      const identity=nextBase+'#'+fragment;if(seen.has(identity))return {$ref:ref};
      const resolved=pointer(target,fragment);if(resolved===undefined)throw Error('Unresolved API reference: '+ref);
      return walk({...resolved,...Object.fromEntries(Object.entries(value).filter(([key])=>key!=='$ref'))},target,nextBase,new Set([...seen,identity]));
    }
    return Object.fromEntries(Object.entries(value).map(([key,item])=>[key,walk(item,root,base,seen)]));
  }
  return walk(document,document,baseUrl);
}
function requireSchema(value,schema,path='body') {
  if(schema?.$ref)throw Error('Supply a finite value/schema for recursive reference at '+path);
  for(const child of schema?.allOf||[])requireSchema(value,child,path);
  if(value&&typeof value==='object'&&!Array.isArray(value))for(const name of schema?.required||[])if(value[name]===undefined)throw Error('Required API value missing: '+path+'.'+name);
  if(value&&typeof value==='object')for(const [name,child]of Object.entries(schema?.properties||{}))if(value[name]!==undefined)requireSchema(value[name],child,path+'.'+name);
  if(Array.isArray(value))value.forEach((item,index)=>requireSchema(item,schema?.items,path+'['+index+']'));
}
export function prepareApiRequest(spec,args={},scope={}) {
  const operation=describeOperations(spec).find(item=>args.operationId?item.operationId===args.operationId:item.path===args.path&&item.method===String(args.method||'GET').toUpperCase());
  if(!operation)throw Error('Choose an operation from the imported specification.');
  const pathItem=spec.paths[operation.path],native=pathItem[operation.method.toLowerCase()];
  let base=args.baseUrl||native.servers?.[0]?.url||pathItem.servers?.[0]?.url||spec.servers?.[0]?.url||(spec.host?`${spec.schemes?.[0]||'https'}://${spec.host}${spec.basePath||''}`:null);
  if(!base)throw Error('Supply an absolute API base URL.');
  const server=native.servers?.[0]||pathItem.servers?.[0]||spec.servers?.[0];
  base=base.replace(/\{([^}]+)\}/g,(_,name)=>{const value=args.serverVariables?.[name]??server?.variables?.[name]?.default;if(value==null)throw Error('Required server variable missing: '+name);return String(value);});
  let path=operation.path;const headers={},query=new URLSearchParams(),cookies=[],values=args.values||{};
  const parameters=new Map(operation.parameters.map(parameter=>[parameter.in+':'+parameter.name,parameter]));
  let body=args.body,contentType=args.contentType;
  const scalar=value=>value&&typeof value==='object'?JSON.stringify(value):String(value);
  for(const parameter of parameters.values()){
    const location=parameter.in,name=parameter.name,value=values[location]?.[name]??(location==='body'?body:undefined);
    if(value===undefined){if(parameter.required)throw Error('Required API value missing: '+location+'.'+name);continue;}
    requireSchema(value,parameter.schema||parameter,location+'.'+name);
    const items=Array.isArray(value)?value.map(scalar):[scalar(value)];
    if(location==='path')path=path.replaceAll('{'+name+'}',items.map(encodeURIComponent).join(','));
    else if(location==='query'){
      if(parameter.style==='deepObject'&&value&&typeof value==='object'&&!Array.isArray(value))for(const [key,item]of Object.entries(value))query.append(name+'['+key+']',scalar(item));
      else if(Array.isArray(value)&&(parameter.explode!==false&&parameter.collectionFormat!=='csv'||parameter.collectionFormat==='multi'))for(const item of items)query.append(name,item);
      else query.append(name,items.join(parameter.collectionFormat==='ssv'?' ':parameter.collectionFormat==='pipes'?'|':','));
    }else if(location==='header')headers[name]=items.join(',');
    else if(location==='cookie')cookies.push(encodeURIComponent(name)+'='+encodeURIComponent(items.join(',')));
    else if(location==='body')body=value;
  }
  if(/\{[^}]+\}/.test(path))throw Error('Unresolved required API path value.');
  const url=new URL(base.replace(/\/$/,'')+'/'+path.replace(/^\//,''));for(const [name,value]of query)url.searchParams.append(name,value);
  if(!scopeAllows(url.href,scope))throw Error('API operation target is outside scope: '+url.href);
  const requestBody=native.requestBody,formParams=operation.parameters.filter(p=>p.in==='formData');
  contentType=contentType||Object.keys(requestBody?.content||{})[0]||native.consumes?.[0]||spec.consumes?.[0]||(formParams.length?'application/x-www-form-urlencoded':body!==undefined?'application/json':null);
  if(requestBody?.required&&body===undefined)throw Error('Required API value missing: body');
  if(body!==undefined)requireSchema(body,requestBody?.content?.[contentType]?.schema);
  if(formParams.length){body={...(body||{}),...(values.formData||{})};for(const parameter of formParams)if(parameter.required&&body[parameter.name]===undefined)throw Error('Required API value missing: formData.'+parameter.name);}
  if(contentType?.startsWith('multipart/form-data')){
    const boundary='certx-'+crypto.randomUUID();let output='';
    for(const [name,value]of Object.entries(body||{})){if(/[\r\n"]/.test(name))throw Error('Invalid multipart field name.');const file=value&&typeof value==='object'&&Object.hasOwn(value,'content');if(file&&/[\r\n"]/.test(value.filename||''))throw Error('Invalid multipart filename.');output+=`--${boundary}\r\nContent-Disposition: form-data; name="${name}"${file?`; filename="${value.filename||'file'}"`:''}\r\n${file?'Content-Type: '+(value.contentType||'application/octet-stream')+'\r\n':''}\r\n${file?value.content:scalar(value)}\r\n`;}
    body=output+`--${boundary}--\r\n`;contentType='multipart/form-data; boundary='+boundary;
  }else if(contentType==='application/x-www-form-urlencoded')body=new URLSearchParams(Object.entries(body||{}).map(([name,value])=>[name,scalar(value)])).toString();
  else if(body!==undefined&&typeof body!=='string')body=JSON.stringify(body);
  if(contentType)headers['Content-Type']=contentType;if(cookies.length)headers.Cookie=cookies.join('; ');
  return {operationId:operation.operationId,path:operation.path,request:{url:url.href,method:operation.method,headers,body:body??''},security:operation.security};
}
export function createApiOperations({privateStore=sensitiveArtifactStorage,replay}={}) {
  const key=id=>'cert_x_api:'+id;
  async function get(id,context){const record=await privateStore.getItem(key(id));if(!record||record.owner!==context.owner)throw Error('API reference is unavailable or belongs to another chat.');return record;}
  return {async invoke(args,context){
    await context.recheck?.();
    if(args.action==='import'){
      const spec=resolveApiRefs(parseSpec(args.data,args.fileName,args.contentType),{documents:args.documents,baseUrl:args.baseUrl,scope:context.scope});const specRef=crypto.randomUUID();await privateStore.setItem(key(specRef),{owner:context.owner,spec});return {specRef,summary:specSummary(spec),operations:describeOperations(spec),externalReferencesFetched:false};
    }
    if(args.action==='list'||args.action==='describe'){const record=await get(args.specRef,context);return {specRef:args.specRef,summary:specSummary(record.spec),operations:describeOperations(record.spec)};}
    if(args.action==='prepare'){
      const record=await get(args.specRef,context),plan=prepareApiRequest(record.spec,args,context.scope),planRef=crypto.randomUUID();await privateStore.setItem(key(planRef),{owner:context.owner,plan,specRef:args.specRef});return {planRef,...plan};
    }
    if(args.action==='execute'||args.action==='batch'){
      const refs=args.action==='batch'?args.planRefs:[args.planRef];if(!Array.isArray(refs)||!refs.length)throw Error('Provide prepared plan references.');
      const plans=await Promise.all(refs.map(id=>get(id,context)));if(plans.some(record=>!record.plan))throw Error('Expected a prepared API plan.');
      const results=[];for(let index=0;index<plans.length;index++){context.signal?.throwIfAborted();await context.recheck?.();const result=await replay({request:plans[index].plan.request,options:args.options,accountId:args.accountId},context);results.push({planRef:refs[index],...result});if(result.response?.errorMessage||Number(result.response?.statusCode)===0)return {success:false,error:'API operation failed.',results,completed:results.length,total:plans.length};}
      return {results,completed:results.length,total:plans.length};
    }
    throw Error('Unknown API operation.');
  }};
}

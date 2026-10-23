const test = require('node:test'), assert = require('node:assert/strict');
require('./dast-inputs.js');
const { parseJson, replaceJson } = globalThis.CertXDastInputs;
const { parseEncoded, replaceEncoded, getRequestInput, replaceRequestInput } = globalThis.CertXDastInputs;
test('JSON Pointer fields preserve exact untouched bytes, types and large numeric values', () => {
  const text = '{ "items": [{"a/b~c":"original", "count":90071992547409931234}], "on":true, "none":null, "escaped":"\\u0041" }';
  const fields = parseJson(text);
  assert.deepEqual(fields.map(({ name, valueType }) => ({ name, valueType })), [
    { name: '/items/0/a~1b~0c', valueType: 'string' }, { name: '/items/0/count', valueType: 'number' },
    { name: '/on', valueType: 'boolean' }, { name: '/none', valueType: 'null' }, { name: '/escaped', valueType: 'string' },
  ]);
  const updated = replaceJson(text, fields[0], 'probe"\\\n雪');
  assert.equal(updated, text.replace('"original"', JSON.stringify('probe"\\\n雪')));
  assert.equal(parseJson(updated)[0].value, 'probe"\\\n雪');
  assert.equal(fields[1].value, '90071992547409931234');
  for (const field of fields.slice(1, 4)) assert.throws(() => replaceJson(text, field, 'probe'), /string field/);
});
test('malformed, duplicate, deeply nested and oversized JSON fails before selection', () => {
  for (const text of ['{"a":1,"\\u0061":2}', '{"a":1,}', '[1,]', '01', 'NaN', '{"x":"\\x20"}', '{"x":"\n"}', 'true false', '{"x":}', '']) assert.throws(() => parseJson(text), undefined, text);
  assert.throws(() => parseJson('['.repeat(34) + '"x"' + ']'.repeat(34)), /depth/);
  assert.throws(() => parseJson(JSON.stringify('x'.repeat(65536))), /64 KiB/);
  assert.throws(() => parseJson(JSON.stringify(Array(201).fill('x'))), /200-leaf/);
});
test('empty keys and root strings have exact pointer identities without prototype pollution', () => {
  const text = '{"":"zero","__proto__":{"x":"one"},"constructor":"two"}';
  assert.deepEqual(parseJson(text).map(field => field.name), ['/', '/__proto__/x', '/constructor']);
  assert.equal(replaceJson(' "root" ', { name: '', index: 0 }, 'new'), ' "new" ');
  assert.equal({}.x, undefined);
  assert.throws(() => replaceJson(text, { name: '/', index: 1 }, 'probe'), /existing JSON string/);
});

test('duplicate decoded names retain exact occurrence and every other encoded byte', () => {
  const text = '&q=a+b&&%71=a%20b&flag&keep=%2f%2F&';
  const fields = parseEncoded(text); assert.deepEqual(fields.map(({name,index,value}) => ({name,index,value})), [{name:'q',index:0,value:'a b'},{name:'q',index:1,value:'a b'},{name:'flag',index:2,value:''},{name:'keep',index:3,value:'//'}]);
  assert.equal(replaceEncoded(text,{name:'q',index:1},'probe + 雪'),'&q=a+b&&%71=probe%20%2B%20%E9%9B%AA&flag&keep=%2f%2F&');
  assert.equal(replaceEncoded(text,{name:'flag',index:2},'yes'),'&q=a+b&&%71=a%20b&flag=yes&keep=%2f%2F&');
  assert.throws(()=>replaceEncoded(text,{name:'q',index:2},'x'),/occurrence/);
  const quoted=replaceRequestInput({url:'https://target.test/?q=first&%71=second&keep=%2b',body:''},{location:'query',name:'q',index:1},"'second!*()");
  assert.equal(quoted.url,'https://target.test/?q=first&%71=%27second%21%2A%28%29&keep=%2b');
  assert.equal(new URL(quoted.url).href,quoted.url,'The browser wire URL must match the credential-rule URL');
  for(const bad of ['q=%','q=%GG','q=%E0%A4'])assert.throws(()=>parseEncoded(bad),/encoding/);
});

test('request helpers distinguish query/form collisions and never mutate the input snapshot', () => {
  const request={url:'https://target.test/a?q=first&q=second&keep=%2b',body:'q=form+first&q=form%20second'};
  assert.equal(getRequestInput(request,{location:'query',name:'q',index:1}).value,'second');
  const changed=replaceRequestInput(request,{location:'form',name:'q',index:1},'new');
  assert.equal(changed.url,request.url);assert.equal(changed.body,'q=form+first&q=new');assert.equal(request.body,'q=form+first&q=form%20second');
  const json={url:request.url,body:'{ "q":"original", "n":90071992547409931234 }'};
  assert.equal(replaceRequestInput(json,{location:'query',name:'q',index:1},'new').body,json.body);
  assert.equal(replaceRequestInput(json,{location:'json',name:'/q',index:0},'new').body,'{ "q":"new", "n":90071992547409931234 }');
});

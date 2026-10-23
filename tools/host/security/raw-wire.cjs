'use strict';
const crypto = require('node:crypto');
const { inScope } = require('./oast.cjs');
const PREFACE = Buffer.from('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n');

function bytes(value, label = 'bytes') {
  if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw Error(label + ' must be canonical base64');
  const result = Buffer.from(value, 'base64');
  if (result.toString('base64') !== value) throw Error(label + ' must be canonical base64');
  return result;
}
function frame({ type = 0, flags = 0, streamId = 0, payloadBase64 = '' }) {
  const payload = bytes(payloadBase64);
  if (payload.length > 0xffffff || !Number.isInteger(type) || type < 0 || type > 255 || !Number.isInteger(flags) || flags < 0 || flags > 255 || !Number.isInteger(streamId) || streamId < 0 || streamId > 0x7fffffff) throw Error('Invalid HTTP/2 frame');
  const out = Buffer.alloc(9 + payload.length); out.writeUIntBE(payload.length, 0, 3); out[3] = type; out[4] = flags; out.writeUInt32BE(streamId, 5); payload.copy(out, 9); return out;
}
function checkScope(url, context) {
  const target = new URL(url);
  if (!['http:', 'https:', 'ws:', 'wss:'].includes(target.protocol) || target.username || target.password) throw Error('Use an HTTP(S)/WS(S) target without URL credentials');
  if (!inScope(target.href.replace(/^ws/, 'http'), context.scope)) throw Error('Target is outside run scope: ' + target.href + '. Review target scope in Workspace settings.');
  return target;
}
function headerLines(text) {
  return text.split('\r\n').filter(Boolean).map(line => {
    const index = line.indexOf(':');
    if (index < 1 || /^[ \t]/.test(line)) throw Error('Routing requires unambiguous header field names');
    return { name: line.slice(0, index).trim().toLowerCase(), value: line.slice(index + 1).trim() };
  });
}
function validateAuthority(value) {
  if (!value || /[\s\/@\\?#]/.test(value)) throw Error('Invalid routing authority');
  return value;
}
function requestUrl(target, authority, requestTarget, context, scheme = target.protocol.replace(/^ws/, 'http')) {
  validateAuthority(authority);
  if (!requestTarget.startsWith('/') && !/^https?:\/\//i.test(requestTarget)) throw Error('Only origin-form or absolute-form HTTP routing is supported');
  const logical = checkScope(new URL(requestTarget, scheme + '//' + authority).href, context);
  if (logical.host.toLowerCase() !== new URL(scheme + '//' + authority).host.toLowerCase()) throw Error('Absolute request target and routing authority disagree');
  return logical.href;
}
function validateHttp1(data, target, context, { malformedOptIn = false } = {}) {
  const text = data.toString('latin1'), routes = [];
  // Inspect every request-looking line, including nested/pipelined requests in
  // explicit framing tests. The wire bytes themselves are never rewritten.
  const requests = /(?:^|\r\n)([!#$%&'*+.^_`|~0-9A-Za-z-]+) ([^\r\n ]+) HTTP\/(1\.[01])\r\n/g;
  let match;
  while ((match = requests.exec(text))) {
    const start = requests.lastIndex, end = text.indexOf('\r\n\r\n', start - 2);
    if (end < 0) throw Error('HTTP request headers are incomplete');
    const headers = headerLines(text.slice(start, end)), hosts = headers.filter(h => h.name === 'host');
    if (!hosts.length && match[3] === '1.1' && !malformedOptIn) throw Error('HTTP/1.1 request requires an explicit Host header');
    for (const host of hosts.length ? hosts : [{ value: target.host }]) routes.push({ url: requestUrl(target, host.value, match[2], context), method: match[1] });
  }
  if (!routes.length) throw Error('Raw HTTP must contain a complete routable HTTP/1 request line');
  if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+ [^\r\n ]+ HTTP\/1\.[01]\r\n/.test(text)) throw Error('Leading bytes obscure HTTP request routing');
  // A bare-LF request boundary is interpreted by some peers but cannot be
  // safely bounded by our CRLF parser. Refuse it instead of admitting only
  // the first interpretation.
  if (/(?:^|[^\r])\n[!#$%&'*+.^_`|~0-9A-Za-z-]+ [^\r\n ]+ HTTP\/1\.[01]/.test(text)) throw Error('Ambiguous bare-LF HTTP routing is unsupported');
  return routes;
}
function parseHttp1Requests(data, policy) {
  if (!['cl', 'te'].includes(policy)) throw Error('HTTP/1 request framing policy must be cl or te');
  const requests = []; let offset = 0;
  while (offset < data.length) {
    const end = data.indexOf('\r\n\r\n', offset);
    if (end < 0) throw Error('HTTP/1 request headers are incomplete under ' + policy);
    const head = data.subarray(offset, end).toString('latin1'), lineEnd = head.indexOf('\r\n');
    if (lineEnd < 0) throw Error('HTTP/1 request line is incomplete under ' + policy);
    const match = /^([!#$%&'*+.^_`|~0-9A-Za-z-]+) (\/[^\r\n ]*) HTTP\/1\.[01]$/.exec(head.slice(0, lineEnd));
    if (!match) throw Error('HTTP/1 request line is invalid under ' + policy);
    const headers = headerLines(head.slice(lineEnd + 2));
    const lengths = headers.filter(h => h.name === 'content-length').map(h => h.value);
    const transfers = headers.filter(h => h.name === 'transfer-encoding').map(h => h.value);
    if (transfers.length && transfers.join(',').toLowerCase().split(',').map(x => x.trim()).at(-1) !== 'chunked') throw Error('Unsupported HTTP/1 transfer encoding under ' + policy);
    let consumed = end + 4;
    if (policy === 'te' && transfers.length) {
      for (;;) {
        const line = data.indexOf('\r\n', consumed);
        if (line < 0) throw Error('HTTP/1 chunk size is incomplete under ' + policy);
        const sizeText = data.subarray(consumed, line).toString('ascii').split(';')[0];
        if (!/^[0-9a-f]+$/i.test(sizeText)) throw Error('HTTP/1 chunk size is invalid under ' + policy);
        const size = parseInt(sizeText, 16);
        if (!Number.isSafeInteger(size)) throw Error('HTTP/1 chunk size exceeds safe range');
        consumed = line + 2;
        if (size === 0) {
          if (consumed + 2 > data.length || data.toString('ascii', consumed, consumed + 2) !== '\r\n') throw Error('HTTP/1 chunk terminator is incomplete under ' + policy);
          consumed += 2; break;
        }
        if (consumed + size + 2 > data.length || data.toString('ascii', consumed + size, consumed + size + 2) !== '\r\n') throw Error('HTTP/1 chunk data is incomplete under ' + policy);
        consumed += size + 2;
      }
    } else if (lengths.length) {
      if (!lengths.every(value => /^\d+$/.test(value) && value === lengths[0])) throw Error('HTTP/1 Content-Length is ambiguous under ' + policy);
      const length = Number(lengths[0]);
      if (!Number.isSafeInteger(length) || consumed + length > data.length) throw Error('HTTP/1 request body is incomplete under ' + policy);
      consumed += length;
    } else if (transfers.length) throw Error('HTTP/1 request has no usable framing under ' + policy);
    requests.push({ method: match[1], route: match[2], offset, wireLength: consumed - offset });
    offset = consumed;
  }
  if (!requests.length) throw Error('HTTP/1 request sequence is empty');
  return requests;
}
function parseFrames(data, { allowIncomplete = false } = {}) {
  const frames = []; let offset = data.subarray(0, PREFACE.length).equals(PREFACE) ? PREFACE.length : 0;
  while (offset + 9 <= data.length) {
    const length = data.readUIntBE(offset, 3);
    if (offset + 9 + length > data.length) break;
    frames.push({ type: data[offset + 3], flags: data[offset + 4], streamId: data.readUInt32BE(offset + 5) & 0x7fffffff, payload: data.subarray(offset + 9, offset + 9 + length), offset, length });
    offset += 9 + length;
  }
  if (!allowIncomplete && offset !== data.length) throw Error('HTTP/2 frame bytes are incomplete');
  return { frames, consumed: offset, incomplete: offset !== data.length };
}
function decodeBlock(decoder, block) {
  let error; const onError = value => { error = value; }; decoder.on('error', onError);
  decoder.write(block); decoder.execute(); decoder.removeListener('error', onError);
  if (error) throw Error('Invalid HPACK header block: ' + error.message);
  const headers = []; let value; while ((value = decoder.read()) !== null) headers.push(value); return headers;
}
function h2Headers(frames, hpack) {
  const decoder = hpack.decompressor.create({ table: { size: 4096 } }), blocks = new Map(), headers = [];
  let continuation = null;
  for (const item of frames) {
    if (continuation !== null && (item.type !== 9 || item.streamId !== continuation)) throw Error('HTTP/2 header continuation is interrupted');
    if (item.type !== 1 && item.type !== 9) continue;
    if (!item.streamId) throw Error('HTTP/2 request headers require a stream');
    if (item.type === 9 && continuation === null) throw Error('Unexpected HTTP/2 CONTINUATION');
    let payload = item.payload;
    if (item.type === 1) {
      if (item.flags & 8) { const padding = payload[0]; if (padding === undefined || padding >= payload.length) throw Error('Invalid HTTP/2 padding'); payload = payload.subarray(1, payload.length - padding); }
      if (item.flags & 32) { if (payload.length < 5) throw Error('Incomplete HTTP/2 priority'); payload = payload.subarray(5); }
    }
    const parts = blocks.get(item.streamId) || []; parts.push(payload); blocks.set(item.streamId, parts);
    if (item.flags & 4) { headers.push({ streamId: item.streamId, headers: decodeBlock(decoder, Buffer.concat(parts)) }); blocks.delete(item.streamId); continuation = null; }
    else continuation = item.streamId;
  }
  if (continuation !== null) throw Error('HTTP/2 header block is incomplete');
  return headers;
}
function validateHttp2(data, target, context, hpack) {
  const parsed = parseFrames(data), routes = [];
  const streams = new Set();
  for (const item of parsed.frames) {
    if (![0,1,2,3,4,5,6,7,8,9].includes(item.type)) throw Error('Unsupported HTTP/2 extension frame type');
    if (item.type === 4 && (item.streamId !== 0 || item.length % 6 !== 0 && !(item.flags & 1 && item.length === 0))) throw Error('Invalid HTTP/2 SETTINGS frame');
    if (item.type === 5) throw Error('HTTP/2 PUSH_PROMISE routing is unsupported');
  }
  for (const item of h2Headers(parsed.frames, hpack)) {
    const values = name => item.headers.filter(h => h.name.toLowerCase() === name).map(h => h.value);
    const authority = values(':authority'), host = values('host'), paths = values(':path'), methods = values(':method'), schemes = values(':scheme');
    if (authority.length !== 1 || paths.length !== 1 || methods.length !== 1 || schemes.length !== 1) throw Error('HTTP/2 routing requires exactly one authority, path, method and scheme');
    if (!['http', 'https'].includes(schemes[0])) throw Error('Invalid HTTP/2 scheme');
    if (schemes[0] !== target.protocol.slice(0, -1)) throw Error('HTTP/2 scheme and connection target disagree');
    if (streams.has(item.streamId)) throw Error('HTTP/2 trailers or repeated request headers are unsupported');
    streams.add(item.streamId);
    const url = requestUrl(target, authority[0], paths[0], context, schemes[0] + ':');
    for (const value of host) if (requestUrl(target, value, paths[0], context, schemes[0] + ':') !== url) throw Error('HTTP/2 Host and authority disagree');
    routes.push({ url, method: methods[0], streamId: item.streamId });
  }
  for (const item of parsed.frames) {
    if (item.type === 3 && !streams.has(item.streamId)) throw Error('Unsupported HTTP/2 routing frame');
    if (item.type === 0 && !streams.has(item.streamId)) throw Error('HTTP/2 DATA has no validated routing headers');
  }
  const bodies = new Map();
  for (const item of parsed.frames) if (item.type === 0) {
    let payload = item.payload;
    if (item.flags & 8) { const padding = payload[0]; if (padding === undefined || padding >= payload.length) throw Error('Invalid HTTP/2 DATA padding'); payload = payload.subarray(1, payload.length - padding); }
    const parts=bodies.get(item.streamId)||[];parts.push(payload);bodies.set(item.streamId,parts);
  }
  for (const [streamId,parts] of bodies) {
    const text=Buffer.concat(parts).toString('latin1');
    const nested=/(?:^|\r\n)([!#$%&'*+.^_`|~0-9A-Za-z-]+ [^\r\n ]+ HTTP\/1\.[01]\r\n)/g;
    const match=nested.exec(text);if(match){const start=match.index+(text.slice(match.index,match.index+2)==='\r\n'?2:0);for(const route of validateHttp1(Buffer.from(text.slice(start),'latin1'),target,context))routes.push({...route,nestedInStream:streamId});}
    if(/(?:^|[^\r])\n[!#$%&'*+.^_`|~0-9A-Za-z-]+ [^\r\n ]+ HTTP\/1\.[01]/.test(text))throw Error('Ambiguous HTTP/1 routing inside HTTP/2 DATA');
  }
  return { ...parsed, routes };
}
function encodeRequests(requests, target, hpack) {
  const compressor = hpack.compressor.create({ table: { size: 4096 } }), writes = [frame({ type: 4 })];
  let next = 1, connectionBodyBytes = 0;
  for (const request of requests) {
    const streamId = request.streamId ?? next; next = streamId + 2;
    if (!Number.isInteger(streamId) || streamId < 1 || streamId % 2 !== 1) throw Error('Client HTTP/2 stream IDs must be positive odd integers');
    const body = request.bodyBase64 === undefined ? null : bytes(request.bodyBase64, 'bodyBase64');
    const list = Array.isArray(request.headers) ? request.headers : Object.entries(request.headers || {}).map(([name, value]) => ({ name, value }));
    const defaults = { ':method': request.method || 'GET', ':scheme': target.protocol.replace(':', ''), ':authority': target.host, ':path': request.path || target.pathname + target.search };
    const names = new Set(list.map(h => String(h.name).toLowerCase()));
    const headers = [...Object.entries(defaults).filter(([name]) => !names.has(name)).map(([name, value]) => ({ name, value })), ...list].map(h => ({ name: String(h.name).toLowerCase(), value: String(h.value) }));
    compressor.write(headers); const block = compressor.read();
    writes.push(frame({ type: 1, flags: 4 | (body?.length ? 0 : 1), streamId, payloadBase64: block.toString('base64') }));
    if (body?.length) {
      connectionBodyBytes += body.length;
      if (body.length > 65535 || connectionBodyBytes > 65535) throw Error('Structured HTTP/2 body exceeds the initial stream or connection flow-control window; use raw frames with explicit flow-control handling');
      for (let offset = 0; offset < body.length; offset += 16384) {
        const part = body.subarray(offset, offset + 16384);
        writes.push(frame({ type: 0, flags: offset + part.length === body.length ? 1 : 0, streamId, payloadBase64: part.toString('base64') }));
      }
    }
  }
  return writes;
}
function parseHttp1Responses(data) {
  const result = []; let offset = 0;
  while (offset < data.length) {
    const end = data.indexOf('\r\n\r\n', offset); if (end < 0) break;
    const head = data.subarray(offset, end).toString('latin1'), lineEnd = head.indexOf('\r\n');
    const first = lineEnd < 0 ? head : head.slice(0, lineEnd), match = /^HTTP\/1\.[01] ([0-9]{3})(?: |$)/.exec(first);
    if (!match) break;
    let headers; try { headers = headerLines(lineEnd < 0 ? '' : head.slice(lineEnd + 2)); } catch { break; }
    const status = Number(match[1]), lengths = headers.filter(h => h.name === 'content-length').map(h => h.value), transfer = headers.filter(h => h.name === 'transfer-encoding').map(h => h.value).join(',').toLowerCase();
    let consumed = end + 4, body;
    if (status < 200 || status === 204 || status === 304) body = Buffer.alloc(0);
    else if (transfer.split(',').map(x => x.trim()).at(-1) === 'chunked') {
      const chunks = []; let complete = false;
      for (;;) { const line = data.indexOf('\r\n', consumed); if (line < 0) break; const sizeText = data.subarray(consumed, line).toString('ascii').split(';')[0]; if (!/^[0-9a-f]+$/i.test(sizeText)) break; const size = parseInt(sizeText, 16); consumed = line + 2; if (size === 0) { if (data.subarray(consumed, consumed + 2).equals(Buffer.from('\r\n'))) { consumed += 2; complete = true; } else { const trailers = data.indexOf('\r\n\r\n', consumed); if (trailers >= 0) { consumed = trailers + 4; complete = true; } } break; } if (consumed + size + 2 > data.length || data.toString('ascii', consumed + size, consumed + size + 2) !== '\r\n') break; chunks.push(data.subarray(consumed, consumed + size)); consumed += size + 2; }
      if (!complete) break; body = Buffer.concat(chunks);
    } else if (lengths.length && lengths.every(value => /^\d+$/.test(value) && value === lengths[0])) {
      const length = Number(lengths[0]); if (!Number.isSafeInteger(length) || consumed + length > data.length) break; body = data.subarray(consumed, consumed + length); consumed += length;
    } else break;
    result.push({ status, headers, bodyBase64: body.toString('base64'), bodySha256: crypto.createHash('sha256').update(body).digest('hex'), offset, wireLength: consumed - offset }); offset = consumed;
  }
  return { responses: result, consumed: offset, incomplete: offset !== data.length };
}
function websocketFrame(payload, { binary = false } = {}) {
  const mask = crypto.randomBytes(4), extra = payload.length < 126 ? 0 : payload.length <= 65535 ? 2 : 8;
  const frame = Buffer.alloc(2 + extra + 4 + payload.length); frame[0] = binary ? 0x82 : 0x81; frame[1] = 0x80 | (extra === 0 ? payload.length : extra === 2 ? 126 : 127);
  if (extra === 2) frame.writeUInt16BE(payload.length, 2); else if (extra === 8) frame.writeBigUInt64BE(BigInt(payload.length), 2);
  mask.copy(frame, 2 + extra); for (let i = 0; i < payload.length; i++) frame[6 + extra + i] = payload[i] ^ mask[i % 4]; return frame;
}
module.exports = { bytes, frame, checkScope, validateHttp1, parseHttp1Requests, validateHttp2, parseFrames, h2Headers, encodeRequests, parseHttp1Responses, websocketFrame, PREFACE };

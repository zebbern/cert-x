// Shared by cert-x capture and the PTK runtime. Token ranges keep untouched
// JSON bytes intact, including large numbers, whitespace and escape spelling.
globalThis.CertXDastInputs = (() => {
  function parseJson(text) {
    if (typeof text !== 'string' || new TextEncoder().encode(text).length > 65536) throw Error('JSON body exceeds the 64 KiB limit.');
    let offset = 0, nodes = 0; const leaves = [];
    const fail = () => { throw Error('Malformed or unsupported JSON body. Capture valid JSON with unique object keys.'); };
    const space = () => { while (/[\t\r\n ]/.test(text[offset] || '\0')) offset++; };
    const pointer = value => String(value).replaceAll('~', '~0').replaceAll('/', '~1');
    function string() {
      const start = offset; if (text[offset++] !== '"') fail();
      while (offset < text.length) {
        const char = text[offset++];
        if (char === '"') { try { return JSON.parse(text.slice(start, offset)); } catch { fail(); } }
        if (char === '\\') { if (offset >= text.length) fail(); offset++; }
        else if (char.charCodeAt(0) < 32) fail();
      }
      fail();
    }
    function value(path, depth) {
      if (depth > 32 || ++nodes > 2048) throw Error('JSON structure exceeds the supported depth or field limit.');
      space(); const start = offset, char = text[offset];
      if (char === '{') {
        offset++; space(); const keys = new Set(); if (text[offset] === '}') { offset++; return; }
        for (;;) {
          space(); const key = string(); if (keys.has(key)) throw Error('Repeated JSON object keys cannot be selected unambiguously.'); keys.add(key);
          space(); if (text[offset++] !== ':') fail(); value(path + '/' + pointer(key), depth + 1); space();
          if (text[offset] === '}') { offset++; return; } if (text[offset++] !== ',') fail();
        }
      }
      if (char === '[') {
        offset++; space(); if (text[offset] === ']') { offset++; return; }
        let index = 0;
        for (;;) { value(path + '/' + index++, depth + 1); space(); if (text[offset] === ']') { offset++; return; } if (text[offset++] !== ',') fail(); }
      }
      let decoded, valueType;
      if (char === '"') { decoded = string(); valueType = 'string'; }
      else {
        const token = /^(?:-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null)/.exec(text.slice(offset))?.[0];
        if (!token) fail(); offset += token.length;
        valueType = token === 'null' ? 'null' : token === 'true' || token === 'false' ? 'boolean' : 'number';
        // Do not round numbers or reinterpret non-string fields.
        decoded = valueType === 'number' ? token : JSON.parse(token);
      }
      if (leaves.length >= 200) throw Error('JSON body exceeds the 200-leaf selection limit.');
      leaves.push({ name: path, index: leaves.length, start, end: offset, value: decoded, valueType });
    }
    value('', 0); space(); if (offset !== text.length) fail(); return leaves;
  }
  function replaceJson(text, selector, replacement) {
    if (typeof replacement !== 'string') throw Error('JSON injection checks require a string replacement.');
    const leaf = parseJson(text).find(item => item.name === selector.name && item.index === selector.index);
    if (!leaf || leaf.valueType !== 'string') throw Error('Select an existing JSON string field; other JSON types are preserved.');
    const next = text.slice(0, leaf.start) + JSON.stringify(replacement) + text.slice(leaf.end);
    parseJson(next); return next;
  }
  function parseEncoded(text) {
    if (typeof text !== 'string' || new TextEncoder().encode(text).length > 65536) throw Error('Encoded inputs exceed the 64 KiB limit.');
    const fields = []; let offset = 0, rawIndex = 0;
    const decode = value => { try { return decodeURIComponent(value.replaceAll('+', ' ')); } catch { throw Error('Malformed parameter encoding cannot be selected exactly.'); } };
    for (const part of text.split('&')) {
      if (part) {
        if (fields.length >= 100) throw Error('Encoded request exceeds the 100-input selection limit.');
        const equals = part.indexOf('=');
        fields.push({ name: decode(equals < 0 ? part : part.slice(0, equals)), value: decode(equals < 0 ? '' : part.slice(equals + 1)), index: fields.length, rawIndex, start: offset, end: offset + part.length });
      }
      offset += part.length + 1; rawIndex++;
    }
    return fields;
  }
  function replaceEncoded(text, selector, replacement) {
    if (typeof replacement !== 'string') throw Error('Encoded input replacement must be a string.');
    const field = parseEncoded(text).find(item => item.name === selector.name && item.index === selector.index);
    if (!field) throw Error('The selected input occurrence no longer matches the capture.');
    const part = text.slice(field.start, field.end), equals = part.indexOf('=');
    // encodeURIComponent leaves apostrophes literal, but HTTP URL parsing later
    // escapes them. Canonical value encoding keeps DNR and wire URLs identical.
    const encoded = encodeURIComponent(replacement).replace(/[!'()*]/g, char => '%' + char.charCodeAt(0).toString(16).toUpperCase());
    const next = text.slice(0, field.start) + (equals < 0 ? part : part.slice(0, equals)) + '=' + encoded + text.slice(field.end);
    parseEncoded(next); return next;
  }
  function queryParts(url) {
    const mark = url.indexOf('?'), fragment = url.indexOf('#');
    if (mark < 0 || fragment >= 0 && mark > fragment) return { prefix: url, text: '', suffix: '', present: false };
    const end = fragment < 0 ? url.length : fragment;
    return { prefix: url.slice(0, mark + 1), text: url.slice(mark + 1, end), suffix: url.slice(end), present: true };
  }
  function getRequestInput(request, selector) {
    const fields = selector.location === 'query' ? parseEncoded(queryParts(request.url).text) : selector.location === 'form' ? parseEncoded(request.body || '') : selector.location === 'json' ? parseJson(request.body) : [];
    const field = fields.find(item => item.name === selector.name && item.index === selector.index);
    if (!field || selector.location === 'json' && field.valueType !== 'string') throw Error('Select an existing string input occurrence.');
    return { ...field, location: selector.location, valueType: field.valueType || 'string' };
  }
  function replaceRequestInput(request, selector, replacement) {
    getRequestInput(request, selector);
    const result = { ...request };
    if (selector.location === 'query') { const parts = queryParts(request.url); result.url = parts.prefix + replaceEncoded(parts.text, selector, replacement) + parts.suffix; }
    else if (selector.location === 'form') result.body = replaceEncoded(request.body || '', selector, replacement);
    else result.body = replaceJson(request.body, selector, replacement);
    return result;
  }
  return Object.freeze({ parseJson, replaceJson, parseEncoded, replaceEncoded, getRequestInput, replaceRequestInput });
})();

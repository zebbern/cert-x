import { scopedUrl } from './dast-core.mjs';

export const DEFAULT_CREDENTIAL_HEADERS = ['cookie', 'authorization', 'proxy-authorization', 'x-api-key', 'x-csrf-token', 'x-xsrf-token'];
export const isCredentialHeader = name => DEFAULT_CREDENTIAL_HEADERS.includes(String(name).toLowerCase()) || /^(?:authentication|api[-_]?key|token|session(?:id)?)$/i.test(name) || /^x-.*(?:auth|token|api[-_]?key|session|csrf|xsrf)/i.test(name);
const managed = new Set(['host', 'content-length', 'connection', 'transfer-encoding', 'accept-encoding', 'if-match', 'if-none-match', 'if-modified-since', 'if-unmodified-since', 'range', 'cookie2']);
const escapeRegex = value => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// This transport does not touch the browser cookie jar. Captured credentials are
// explicit input, not fetch credentials; DNR applies the exact Cookie on the wire.
export function createIsolatedTransport({ api = globalThis.chrome, fetchImpl = globalThis.fetch, now = () => Date.now() } = {}) {
  let active = false, poisoned = false;
  const ready = (async () => {
    const leftovers = (await api.declarativeNetRequest.getSessionRules()).filter(rule => rule.id >= 1800000000 && rule.id < 1800001000 && rule.priority === 1000000 && rule.condition?.initiatorDomains?.includes(api.runtime.id));
    if (leftovers.length) await api.declarativeNetRequest.updateSessionRules({ removeRuleIds: leftovers.map(rule => rule.id) });
  })();
  ready.catch(() => {});
  return async function send({ request, credentials = [], credentialNames = [], scope, deadline, beforeDispatch = async () => {} }) {
    if (active) throw Error('An isolated access request is already running.');
    if (poisoned) throw Error('Credential isolation cleanup failed. Reload the companion before testing again.');
    active = true; let ruleId, timer; const controller = new AbortController();
    try {
      await ready;
      const url = scopedUrl(request.url, scope).href;
      if (!['GET', 'POST'].includes(request.method)) throw Error('Only declared read-only GET/POST requests are supported.');
      if (now() >= deadline) throw Error('Access-test time budget expired.');
      const names = new Set([...DEFAULT_CREDENTIAL_HEADERS, ...credentialNames.map(name => name.toLowerCase()), ...credentials.map(header => header.name.toLowerCase()), ...(request.headers || []).filter(header => isCredentialHeader(header.name)).map(header => header.name.toLowerCase())]);
      const headers = new Headers();
      for (const header of request.headers || []) {
        const name = header.name.toLowerCase();
        if (!names.has(name) && !managed.has(name) && !name.startsWith('sec-') && !name.startsWith('x-ptk-') && !['origin', 'referer', 'user-agent'].includes(name)) headers.set(header.name, header.value);
      }
      for (const header of credentials) if (header.name.toLowerCase() !== 'cookie') headers.set(header.name, header.value);
      headers.set('Cache-Control', 'no-store'); headers.set('Pragma', 'no-cache');
      const cookie = credentials.find(header => header.name.toLowerCase() === 'cookie');
      const regexFilter = '^' + escapeRegex(url) + '$';
      const supported = await api.declarativeNetRequest.isRegexSupported({ regex: regexFilter, isCaseSensitive: true });
      if (!supported.isSupported) throw Error('This endpoint cannot use the isolated credential transport.');
      const used = new Set((await api.declarativeNetRequest.getSessionRules()).map(rule => rule.id));
      ruleId = 1800000000; while (used.has(ruleId)) ruleId++;
      if (ruleId >= 1800001000) throw Error('Isolated access request rule capacity exhausted.');
      const requestHeaders = [{ header: 'cookie', operation: cookie ? 'set' : 'remove', ...(cookie ? { value: cookie.value } : {}) }];
      for (const name of names) if (name !== 'cookie' && !credentials.some(header => header.name.toLowerCase() === name)) requestHeaders.push({ header: name, operation: 'remove' });
      await api.declarativeNetRequest.updateSessionRules({ addRules: [{ id: ruleId, priority: 1000000,
        condition: { regexFilter, isUrlFilterCaseSensitive: true, initiatorDomains: [api.runtime.id], tabIds: [-1], requestMethods: [request.method.toLowerCase()], resourceTypes: ['xmlhttprequest'] },
        action: { type: 'modifyHeaders', requestHeaders, responseHeaders: [{ header: 'set-cookie', operation: 'remove' }, { header: 'set-cookie2', operation: 'remove' }] },
      }], removeRuleIds: [] });
      if (now() >= deadline) throw Error('Access-test time budget expired before dispatch.');
      scopedUrl(url, scope);
      await beforeDispatch();
      if (now() >= deadline) throw Error('Access-test time budget expired before dispatch.');
      timer = setTimeout(() => controller.abort(), Math.max(1, Math.min(10000, deadline - now())));
      const response = await fetchImpl(url, { method: request.method, headers, body: request.method === 'POST' ? request.body || '' : undefined,
        credentials: 'omit', cache: 'no-store', redirect: 'manual', keepalive: false, signal: controller.signal });
      const reader = response.body?.getReader(); let body = '', bytes = 0; const decoder = new TextDecoder();
      if (reader) {
        try { for (;;) { const part = await reader.read(); if (part.done) break; bytes += part.value.byteLength; if (bytes > 1024 * 1024) { await reader.cancel(); throw Error('Access response exceeds one MiB.'); } body += decoder.decode(part.value, { stream: true }); } body += decoder.decode(); }
        finally { reader.releaseLock(); }
      }
      return { status: response.status, contentType: response.headers.get('content-type') || '', body, responseByteLength: bytes, opaque: response.type === 'opaqueredirect' || response.status === 0 };
    } catch (error) {
      if (error?.name === 'AbortError') throw Error('Access request timed out; no retry was made.');
      throw error;
    } finally {
      clearTimeout(timer);
      try { if (ruleId !== undefined) await api.declarativeNetRequest.updateSessionRules({ removeRuleIds: [ruleId] }); }
      catch { poisoned = true; throw Error('Credential isolation cleanup failed. Reload the companion before testing again.'); }
      finally { active = false; }
    }
  };
}

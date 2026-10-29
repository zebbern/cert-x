// Compatibility for existing cert-x account and targeted-test contracts. Native scanning uses the full engine.
import { securityChrome as chrome } from "../engine/platform.mjs";
import "./dast-inputs.js";
import { ptk_module } from '../ptk/background/dast/modules/module.js';
import { ptk_request } from '../ptk/background/rbuilder.js';
import { createTargetedRunner, DAST_PROTOCOL, DAST_FAMILIES } from './dast-core.mjs';
import { createAccessRunner } from './authz-core.mjs';
import { createIsolatedTransport } from './authz-transport.mjs';

const clone = value => JSON.parse(JSON.stringify(value));
const KEY = 'cert_x_dast_batches';
let installed;
const inputs = globalThis.CertXDastInputs;
const selectedAttacks = { xss: ['xss_1', 'xss_2', 'xss_3'], sql_injection: ['sqlinjection_1', 'sqlinjection_3', 'sqlinjection_2', 'sqlinjection_4'], open_redirect: ['redir_1'], jsonp_callback_injection: ['jsonp_callback_1'] };
const passiveModules = ['headers', 'recon_cors_posture', 'recon_cache_privacy', 'recon_error_stacktraces', 'recon_sourcemaps_debug'];
const wireRequest = schema => ({ url: schema.request.url, body: schema.request.body?.text || '' });
function bindValidationConstants(value, constants) {
  if (Array.isArray(value)) return value.map(item => bindValidationConstants(item, constants));
  if (!value || typeof value !== 'object') return value;
  if (Object.keys(value).length === 1 && typeof value.var === 'string' && value.var.startsWith('attack.metadata.')) {
    const name = value.var.slice('attack.metadata.'.length);
    if (Object.hasOwn(constants, name) && ['string', 'number', 'boolean'].includes(typeof constants[name])) return constants[name];
  }
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, bindValidationConstants(item, constants)]));
}
function mutateInput(schema, parameter, value) {
  const wire = inputs.replaceRequestInput(wireRequest(schema), parameter, value), result = clone(schema);
  result.request.url = wire.url;
  if (result.request.body || wire.body) result.request.body = { ...(result.request.body || {}), text: wire.body };
  return result;
}
function requestSchema(seed) {
  const url = new URL(seed.url), headers = seed.headers.filter(header => !['host', 'content-length', 'transfer-encoding', 'connection'].includes(header.name.toLowerCase()));
  const raw = seed.method + ' ' + seed.url + ' HTTP/1.1\r\nHost: ' + url.host + '\r\n' + headers.map(header => header.name + ': ' + header.value).join('\r\n') + '\r\n\r\n' + (seed.body || '');
  const schema = ptk_request.parseRawRequest(raw, { follow_redirect: false, override_headers: true, preserve_browser_headers: true, retry_on_transport_failure: false, transport_retry_count: 0, requestTimeoutMs: 10000 });
  schema.request.url = seed.url;
  // Preserve captured bodies for baseline replay; PTK mutators update text for variants.
  if (seed.method === 'POST') {
    const contentType = seed.headers.find(header => header.name.toLowerCase() === 'content-type')?.value || '';
    const json = /^application\/(?:json|[a-z0-9!#$&^_.+-]+\+json)$/i.test(contentType.split(';')[0].trim());
    schema.request.body = { ...(schema.request.body || {}), mimeType: json ? 'application/json' : 'application/x-www-form-urlencoded', text: seed.body || '', params: json ? [] : Array.from(new URLSearchParams(seed.body || ''), ([name, value]) => ({ name, value })) };
  }
  return schema;
}
async function loadPtk() {
  const response = await fetch(chrome.runtime.getURL('security/ptk/background/dast/modules/modules.json'));
  if (!response.ok) throw Error('The bundled PTK DAST rulepack could not load.');
  const pack = await response.json(), modules = {};
  for (const family of [...Object.keys(selectedAttacks), ...passiveModules]) {
    const definition = pack.modules?.find(module => module.id === family);
    if (!definition || selectedAttacks[family] && !selectedAttacks[family].every(id => definition.attacks?.some(attack => attack.id === id)) || passiveModules.includes(family) && definition.type !== 'passive') throw Error('The expected pinned PTK ' + family + ' definitions are unavailable.');
    modules[family] = { definition, module: new ptk_module(clone(definition)), attacks: definition.attacks.filter(attack => !selectedAttacks[family] || selectedAttacks[family].includes(attack.id)) };
  }
  return {
    parse(seed) { try { return requestSchema(seed); } catch { throw Error('PTK could not parse this captured request.'); } },
    mutate: mutateInput,
    taskSchema(schema, task) {
      const original = inputs.getRequestInput(wireRequest(schema), task.parameter).value, action = task.action;
      const value = action.operation === 'replace' ? action.value : action.position === 'before' ? action.value + original : original + action.value;
      const variant = mutateInput(schema, task.parameter, value); variant.metadata = clone(task.metadata); return variant;
    },
    build(schema, parameters, families = ['xss']) {
      const tasks = [];
      for (const family of families) {
        if (family === 'response_checks') {
          for (const moduleId of passiveModules) {
            const { definition, module, attacks } = modules[moduleId];
            for (const source of attacks) {
              if (Object.keys(source.action || {}).length) throw Error('A passive PTK response rule unexpectedly contains request actions.');
              const attack = module.prepareAttack(clone(source));
              tasks.push({ family, moduleId, strategy: 'passive', attackId: attack.id, attackName: attack.name,
                metadata: { ...definition.metadata?.constants, ...attack.metadata?.constants, validation: clone(attack.validation), condition: clone(attack.condition) } });
            }
          }
          continue;
        }
        if (family === 'sql_boolean' || family === 'ssti') {
          for (const parameter of parameters) {
            const value = inputs.getRequestInput(wireRequest(schema), parameter).value;
            if (family === 'sql_boolean') {
              if (!value || value.length > 128 || /[\r\n'";\\]/.test(value)) continue;
              const contexts = /^-?\d+(?:\.\d+)?$/.test(value) ? ['numeric'] : ['single-quoted', 'double-quoted'];
              for (const context of contexts) tasks.push({ family, strategy: 'boolean', parameter: clone(parameter), context, attackId: 'certx_boolean_' + context, attackName: 'Bounded SQL boolean comparison', originalValue: value });
            } else for (const template of ['mustache', 'dollar', 'erb']) tasks.push({ family, strategy: 'ssti', parameter: clone(parameter), template, attackId: 'certx_ssti_' + template, attackName: 'Bounded template arithmetic', originalValue: value });
          }
          continue;
        }
        const { definition, module, attacks } = modules[family];
        for (const original of attacks) {
          for (const parameter of parameters) {
            const source = clone(original);
            if (family === 'jsonp_callback_injection' && !new RegExp(definition.metadata.constants.jsonpCallbackParamNameRegex, 'i').test(parameter.location === 'json' ? parameter.name.split('/').at(-1) : parameter.name)) continue;
            if (family === 'open_redirect') source.action.params = [{ ...source.action.params[0], name: undefined, value: 'https://cert-x-redirect.invalid/' + crypto.randomUUID() }];
            if (family === 'jsonp_callback_injection') source.action.params[0].value = 'certxJsonp_' + crypto.randomUUID().replaceAll('-', '');
            const attack = module.prepareAttack(source), action = attack.action.params[0];
            const metadata = { ...definition.metadata?.constants, ...attack.metadata?.constants, validation: clone(attack.validation), condition: clone(attack.condition) };
            if (family === 'jsonp_callback_injection') metadata.jsonpCallbackProofRegex = metadata.jsonpCallbackProofRegex.replaceAll('ptkJsonpCallback', action.value);
            if (!['replace', 'add'].includes(action.operation)) throw Error('PTK produced an unsupported selected-input action.');
            // Keep descriptors, not a full captured-body clone per planned test.
            tasks.push({ family, metadata, action: clone(action), parameter: clone(parameter), attackId: attack.id, attackName: attack.name, payload: action.value });
          }
        }
      }
      return tasks;
    },
    control(schema, parameter) {
      return mutateInput(schema, parameter, inputs.getRequestInput(wireRequest(schema), parameter).value + 'certx-control-' + crypto.randomUUID().replaceAll('-', ''));
    },
    validate(attack, original, task) {
      try {
        const { definition, module, attacks } = modules[task?.moduleId || task?.family || 'xss'];
        const declared = { ...definition.metadata?.constants, ...attacks.find(item => item.id === task?.attackId)?.metadata?.constants };
        const constants = Object.fromEntries(Object.keys(declared).map(name => [name, attack.metadata?.[name]]));
        // JsonLogic some/none switches context to a single header. Bind only
        // declared static constants so nested predicates retain the rulepack's
        // intended regexes; dynamic request/response references stay unchanged.
        const evaluated = { ...attack, metadata: { ...attack.metadata, validation: bindValidationConstants(attack.metadata?.validation, constants) } };
        return module.validateAttack(evaluated, original);
      } catch { throw Error('PTK could not validate this response.'); }
    },
    async send(schema) {
      const request = new ptk_request();
      // One fetch attempt, no redirect chain, no global browser-navigation confirmation.
      request.isolatedRedirectSession = false; request.useListeners = false; request.trackWithListeners = false;
      const nonce = crypto.randomUUID(), url = new URL(schema.request.url).href, initiator = 'chrome-extension://' + chrome.runtime.id;
      // PTK builds its Cookie DNR rule from schema.url while fetch canonicalizes
      // URLs. Keep both inputs identical so a quoted query cannot miss the rule
      // and silently use an ambient account instead of the captured identity.
      schema.request.url = url;
      schema.opts.ptk_req_id = nonce;
      schema.request.headers = schema.request.headers.filter(header => !['x-ptk-reqid', 'x-ptk-source'].includes(header.name.toLowerCase()));
      let requestId = null, tracked = null;
      const before = details => {
        if (details.initiator !== initiator || new URL(details.url).href !== url || details.method !== schema.request.method) return;
        if (details.requestHeaders?.find(header => header.name.toLowerCase() === 'x-ptk-reqid')?.value === nonce) requestId = details.requestId;
      };
      const headers = details => {
        if (requestId !== null && details.requestId === requestId && details.initiator === initiator && new URL(details.url).href === url) tracked = details;
      };
      const filter = { urls: [new URL(url).origin + '/*'], types: ['xmlhttprequest'] };
      try {
        chrome.webRequest.onBeforeSendHeaders.addListener(before, filter, ['requestHeaders', 'extraHeaders']);
        chrome.webRequest.onHeadersReceived.addListener(headers, filter, ['responseHeaders', 'extraHeaders']);
        const result = await request.sendRequest(schema);
        if (tracked?.responseHeaders && result.response && Number(result.response.statusCode) === tracked.statusCode) result.response.headers = tracked.responseHeaders;
        if (Number(result.response?.statusCode) === 0 && tracked?.statusCode >= 300 && tracked.statusCode < 400) {
          result.response.statusCode = tracked.statusCode; result.response.headers = tracked.responseHeaders || []; result.response.body = '';
        }
        return result;
      } finally {
        chrome.webRequest.onBeforeSendHeaders.removeListener(before); chrome.webRequest.onHeadersReceived.removeListener(headers);
      }
    },
  };
}
function appBusy() {
  const app = globalThis.ptk_app;
  if (!app) return true;
  const dast = app.dast || app.rattacker;
  const isDastRunning = typeof dast?.engine?.isRunning === 'function' ? dast.engine.isRunning() : dast?.engine?.isRunning;
  return !!(isDastRunning || app.iast?.isScanRunning || app.iast?._certXStarting || app.iast?._certXStopping || app.sast?.isScanRunning || app.sca?.isScanRunning || app.automation?._hasActiveSessionInAnyTab?.());
}
function installAccessGuards(app, accessActive) {
  const marker = Symbol.for('cert-x.access-guard');
  if (globalThis.fetch[marker]) return globalThis.fetch[marker];
  const state = { pending: 0, originalFetch: globalThis.fetch.bind(globalThis) }, originalFetch = globalThis.fetch;
  const guardedFetch = async function (...args) {
    let network = false;
    try { network = ['http:', 'https:'].includes(new URL(args[0]?.url || String(args[0]), chrome.runtime.getURL('/')).protocol); } catch { /* Let native fetch report invalid inputs. */ }
    if (network && accessActive()) throw Error('An isolated account comparison is active. PTK network requests are temporarily paused.');
    if (network) state.pending++;
    try { return await originalFetch.apply(this, args); }
    finally { if (network) state.pending--; }
  };
  guardedFetch[marker] = state; // Do not replace extension-wide fetch: model/MCP traffic is independent.
  const wrap = (object, name, track = false) => {
    if (!object || typeof object[name] !== 'function' || object[name][marker]) return;
    const original = object[name];
    const guarded = function (...args) {
      if (accessActive()) throw Error('An isolated account comparison is active. Stop it before using PTK requests or scans.');
      if (track) state.pending++;
      const settled = () => { if (track) state.pending--; };
      let result;
      try { result = original.apply(this, args); }
      catch (error) { settled(); throw error; }
      if (result && typeof result.then === 'function') return Promise.resolve(result).finally(settled);
      settled(); return result;
    };
    guarded[marker] = true; object[name] = guarded;
  };
  // The inherited transport method is intentionally shadowed on ptk_request.
  // Existing instances also use the guarded prototype lookup.
  wrap(ptk_request.prototype, 'sendRequest', true);
  for (const engine of [app.dast, app.rattacker, app.iast, app.sast, app.sca]) wrap(engine, 'runBackgroundScan', true);
  for (const dast of [app.dast, app.rattacker]) { wrap(dast?.engine, 'start', true); wrap(dast, 'startAutomationSession', true); }
  for (const name of ['msg_session_start', 'startZapConfiguredSession']) wrap(app.automation, name, true);
  for (const name of ['startRecording', 'startReplay', 'startInTab', 'startInActiveTab']) wrap(app.recorder, name, true);
  return state;
}
async function startAccessBatch(runner, payload) {
  try { return await runner.run(payload); }
  catch (error) {
    // run() catches execution failures internally. A thrown rejection here is
    // definite non-admission, unlike a lost RPC reply or transport timeout.
    return { accepted: false, state: 'failed', batchId: payload.batchId, owner: payload.owner, requestsSent: 0, inFlight: 0, error: error.message };
  }
}
export function createCompatibilityRuntime(app, resources) {
  if (installed) return installed;
  let writes = Promise.resolve(), reserved = false, runner, accessRunner, activeContext;
  const acquire = () => { if (reserved) return false; reserved = true; return true; };
  const release = () => { reserved = false; activeContext = null; };
  const persist = (key, data) => {
    const task = writes.then(() => chrome.storage.session.set({ [key]: clone(data) }));
    writes = task.catch(() => {}); return task;
  };
  const ready = (async () => {
    await resources.ready;
    const guards = installAccessGuards(app, () => accessRunner?.hasActive() === true);
    const busy = () => guards.pending > 0 || appBusy();
    runner = createTargetedRunner({ loadPtk: async () => { const engine = await loadPtk(), send = engine.send; return { ...engine, send: async schema => { activeContext?.signal?.throwIfAborted(); await activeContext?.recheck?.(); await activeContext?.checkRequest?.({ url: schema.request.url, method: schema.request.method }); return send(schema); } }; }, interrupted: (await chrome.storage.session.get(KEY))[KEY] || [], isBusy: busy, acquire, release, persist: data => persist(KEY, data) });
    const isolatedSend = createIsolatedTransport({ api: resources.forOwner('security-accounts'), fetchImpl: guards.originalFetch });
    accessRunner = createAccessRunner({
      send: async args => { return isolatedSend({ ...args, beforeDispatch: async () => { activeContext?.signal?.throwIfAborted(); await activeContext?.recheck?.(); await activeContext?.checkRequest?.(args.request); await args.beforeDispatch?.(); } }); },
      interrupted: (await chrome.storage.session.get('cert_x_authz_batches')).cert_x_authz_batches || [],
      isBusy: busy, acquire, release, persist: data => persist('cert_x_authz_batches', data)
    });
  })();
  ready.catch(() => {});
  installed = {
    ready, isBusy: () => reserved,
    async invoke(op, payload = {}, context = {}) {
      await ready;
      context.signal?.throwIfAborted();
      if (context.owner && payload.owner && context.owner !== payload.owner) throw Error('The test belongs to another chat.');
      if (context.recheck) await context.recheck();
      if (op === 'capabilities') {
        await loadPtk();
        return { ready: true, native: true, revision: 5, ordinalInputs: true, authz: true, protocol: DAST_PROTOCOL,
          inputLocations: ['query', 'form', 'json'], families: DAST_FAMILIES,
          moduleIds: [...Object.keys(selectedAttacks), ...passiveModules], attackIds: Object.values(selectedAttacks).flat(),
          compatibility: true, note: 'Legacy selected-request contracts. Use native security scans for complete configurable coverage.',
          limits: { concurrency: 1, maxSeeds: 10 }, defaults: { maxRequests: 100, maxRequestsPerSecond: 5, durationSeconds: 300 },
          redirects: 'headers-only-never-follow', browserExecutionProof: false };
      }
      if (['authz_verify', 'authz_run', 'run'].includes(op)) { if (reserved) throw Error('Another security operation is active.'); activeContext = context; }
      if (op === 'authz_verify') return accessRunner.verify(payload);
      if (op === 'authz_run') return startAccessBatch(accessRunner, payload);
      if (op === 'authz_status') return accessRunner.status(payload);
      if (op === 'authz_stop') return accessRunner.stop(payload);
      if (op === 'authz_result') return accessRunner.result(payload);
      if (op === 'run') return runner.run(payload);
      if (op === 'status') return runner.status(payload);
      if (op === 'stop') return runner.stop(payload);
      if (['result', 'findings', 'export'].includes(op)) return runner.result(payload);
      throw Error('Unsupported legacy security operation.');
    }
  };
  return installed;
}

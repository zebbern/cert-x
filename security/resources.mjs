// Browser resources shared by the agent and the integrated testing engines.
// Facades retain Chrome's callback contract as well as its Promise interface.
const DNR_FIRST = 850000000, DNR_LAST = 859999999;
const DNR_KEY = 'cert_x_security_rule_owners_v1';
const DEBUG_KEY = 'cert_x_debugger_leases_v1';
const SHARED_DOMAINS = new Set(['Network', 'Page', 'Runtime', 'DOM', 'Log', 'Security', 'Performance']);

export function createSecurityResources(native = globalThis.chrome) {
  const attachments = new Map(), facades = new Map(), queues = new Map();
  let debuggerWrites = Promise.resolve();
  const persistDebugger = () => {
    const records = [...attachments.values()].map(state => ({ target: state.target, owners: [...state.owners] }));
    const task = debuggerWrites.then(() => native.storage.session.set({ [DEBUG_KEY]: records }));
    debuggerWrites = task.catch(() => {}); return task;
  };
  const ruleMaps = { session: {}, dynamic: {} }, offscreenOwners = new Set();
  const serial = (key, fn) => {
    const task = (queues.get(key) || Promise.resolve()).catch(() => {}).then(fn);
    queues.set(key, task); task.finally(() => { if (queues.get(key) === task) queues.delete(key); }).catch(() => {});
    return task;
  };
  const keyOf = target => Number.isInteger(target?.tabId) ? 'tab:' + target.tabId : target?.targetId ? 'target:' + target.targetId : target?.extensionId ? 'extension:' + target.extensionId : (() => { throw Error('Debugger target is required.'); })();
  const call = (object, name, ...args) => new Promise((resolve, reject) => {
    // Callback mode works in Chromium versions where this API has no Promise overload.
    try { object[name](...args, result => { const error = native.runtime?.lastError; error ? reject(Error(error.message)) : resolve(result); }); }
    catch (error) { reject(error); }
  });
  const domainKey = (target, domain) => (target.sessionId || '') + ':' + domain;
  const sessionKey = target => target.sessionId || '';
  function forgetContexts(state, sessionId) { state.runtimeContexts.delete(sessionId); }
  function rememberContextEvent(state, target, method, params) {
    const id = sessionKey(target);
    if (id && state.detachedSessions.has(id)) return;
    if (method === 'Runtime.executionContextsCleared') { forgetContexts(state, id); return; }
    if (!['Runtime.executionContextCreated', 'Runtime.executionContextDestroyed'].includes(method)) return;
    let inventory = state.runtimeContexts.get(id);
    if (!inventory) { inventory = { entries: new Map(), incomplete: false }; state.runtimeContexts.set(id, inventory); }
    if (method === 'Runtime.executionContextDestroyed') {
      for (const [key, value] of inventory.entries) if (params.executionContextUniqueId ? value.params.context.uniqueId === params.executionContextUniqueId : key === params.executionContextId) inventory.entries.delete(key);
      return;
    }
    if (!Number.isInteger(params?.context?.id)) { inventory.incomplete = true; return; }
    inventory.entries.delete(params.context.id);
    // This is native context metadata only; never retain evaluated page values.
    const bytes = JSON.stringify(params).length * 2;
    const entries = [...state.runtimeContexts.values()].flatMap(value => [...value.entries.values()]);
    if (bytes > 65536 || entries.length >= 1024 || entries.reduce((sum, value) => sum + value.bytes, 0) + bytes > 2 * 1024 * 1024) { inventory.incomplete = true; return; }
    inventory.entries.set(params.context.id, { target: structuredClone(target), params: structuredClone(params), bytes });
  }
  function replayContexts(state, target, owner) {
    const inventory = state.runtimeContexts.get(sessionKey(target));
    if (inventory?.incomplete) throw Error('Debugger runtime context inventory incomplete; revisit the document under capture.');
    for (const value of inventory?.entries.values() || []) for (const listener of facades.get(owner)?.events || []) listener(structuredClone(value.target), 'Runtime.executionContextCreated', structuredClone(value.params));
  }
  const canonical = value => JSON.stringify(value, (_key, item) => item && typeof item === 'object' && !Array.isArray(item) ? Object.fromEntries(Object.keys(item).sort().map(key => [key, item[key]])) : item);
  const assertLiveSession = (state, target) => { if (target.sessionId && state.detachedSessions.has(target.sessionId)) throw Error('Debugger child session detached: ' + target.sessionId); };
  function forgetSession(state, sessionId) {
    const removed = new Set([sessionId]);
    for (;;) {
      const before = removed.size;
      for (const [id, child] of state.children) if (removed.has(child.parent)) removed.add(id);
      if (removed.size === before) break;
    }
    for (const id of removed) { state.children.delete(id); state.autoAttach.delete(id); state.detachedSessions.add(id); forgetContexts(state, id); }
    for (const [key, entry] of state.domains) if (removed.has(entry.target.sessionId)) state.domains.delete(key);
  }
  function replayChildren(state, parent, owner) {
    for (const child of state.children.values()) if (child.parent === parent) {
      for (const listener of facades.get(owner)?.events || []) listener(structuredClone(child.target), 'Target.attachedToTarget', structuredClone(child.params));
    }
  }
  function descendantOwners(state, parent) {
    const below = id => {
      if (!id || id === parent) return false;
      if (!parent) return true;
      const seen = new Set();
      while (id && !seen.has(id)) { seen.add(id); id = state.children.get(id)?.parent; if (id === parent) return true; }
      return false;
    };
    const owners = new Set();
    for (const [id, entry] of state.autoAttach) if (below(id)) for (const owner of entry.owners) owners.add(owner);
    for (const entry of state.domains.values()) if (below(entry.target.sessionId)) for (const owner of entry.owners) owners.add(owner);
    return owners;
  }
  function deepestFirst(state) {
    const depth = id => { let count = 0; const seen = new Set(); while (id && !seen.has(id)) { seen.add(id); count++; id = state.children.get(id)?.parent; } return count; };
    return [...state.autoAttach].sort(([a], [b]) => depth(b) - depth(a));
  }
  const disableAutoAttach = entry => ({ autoAttach: false, waitForDebuggerOnStart: false, flatten: entry.params.flatten ?? false });
  async function pruneAutoAttach(state) {
    for (const [id, entry] of deepestFirst(state)) {
      if (state.autoAttach.get(id) !== entry || entry.owners.size || descendantOwners(state, id).size) continue;
      await call(native.debugger, 'sendCommand', entry.target, 'Target.setAutoAttach', disableAutoAttach(entry));
      state.autoAttach.delete(id);
    }
  }
  async function releaseAutoAttach(state, id, owner) {
    const entry = state.autoAttach.get(id);
    if (!entry?.owners.has(owner)) return {};
    if (entry.owners.size > 1 || descendantOwners(state, id).size) { entry.owners.delete(owner); return {}; }
    const result = await call(native.debugger, 'sendCommand', entry.target, 'Target.setAutoAttach', disableAutoAttach(entry));
    state.autoAttach.delete(id); return result;
  }
  const ownedRule = id => Number.isInteger(id) && id >= DNR_FIRST && id <= DNR_LAST;
  const debuggerReady = (async () => {
    const previous = (await native.storage.session.get(DEBUG_KEY))[DEBUG_KEY] || [];
    // No execution context survives worker recreation. Release only a saved
    // attachment that Chrome confirms this extension still controls. Never
    // detach a target now owned by DevTools or another extension.
    for (const record of previous) {
      if (!record?.target || !Array.isArray(record.owners)) continue;
      try { await call(native.debugger, 'sendCommand', record.target, 'Runtime.evaluate', { expression: 'void 0', returnByValue: true }); }
      catch { continue; }
      await call(native.debugger, 'detach', record.target);
    }
    await native.storage.session.set({ [DEBUG_KEY]: [] });
  })();
  debuggerReady.catch(() => {});
  const rulesReady = (async () => {
    const saved = (await native.storage.session.get(DNR_KEY))[DNR_KEY];
    for (const kind of ['session', 'dynamic']) {
      if (saved?.[kind] && typeof saved[kind] === 'object') ruleMaps[kind] = saved[kind];
      const rules = await call(native.declarativeNetRequest, kind === 'session' ? 'getSessionRules' : 'getDynamicRules');
      const known = new Set(Object.values(ruleMaps[kind]).flatMap(mapping => Object.values(mapping)));
      const orphaned = rules.filter(rule => ownedRule(rule.id) && !known.has(rule.id)).map(rule => rule.id);
      if (orphaned.length) await call(native.declarativeNetRequest, kind === 'session' ? 'updateSessionRules' : 'updateDynamicRules', { removeRuleIds: orphaned });
    }
  })();
  // Retain failures for callers; bootstrap must not create an unhandled rejection.
  rulesReady.catch(() => {});

  native.debugger.onEvent.addListener((target, method, params) => {
    const state = attachments.get(keyOf(target));
    if (!state) return;
    rememberContextEvent(state, target, method, params);
    if (method === 'Target.attachedToTarget' && typeof params?.sessionId === 'string') {
      if (state.children.has(params.sessionId)) forgetSession(state, params.sessionId);
      forgetContexts(state, params.sessionId);
      state.detachedSessions.delete(params.sessionId);
      state.children.set(params.sessionId, { parent: sessionKey(target), target: structuredClone(target), params: structuredClone(params) });
    }
    if (method === 'Target.detachedFromTarget' && typeof params?.sessionId === 'string') {
      forgetSession(state, params.sessionId);
      void serial('debug:' + keyOf(target), async () => {
        if (attachments.get(keyOf(target)) === state) await pruneAutoAttach(state);
      }).catch(() => {});
    }
    for (const owner of state.owners) for (const listener of facades.get(owner)?.events || []) listener(target, method, params);
  });
  native.debugger.onDetach.addListener((target, reason) => {
    const key = keyOf(target), state = attachments.get(key); attachments.delete(key);
    if (!state) return;
    persistDebugger().catch(() => {});
    for (const owner of state.owners) for (const listener of facades.get(owner)?.detaches || []) listener(target, reason);
  });

  function forOwner(owner) {
    if (typeof owner !== 'string' || !owner) throw Error('A resource owner is required.');
    if (facades.has(owner)) return facades.get(owner).api;
    const events = new Set(), detaches = new Set();
    let callbackError;
    const finish = (promise, callback) => {
      if (typeof callback !== 'function') return promise;
      return promise.then(result => { callback(result); return result; }, error => {
        callbackError = { message: error.message || String(error) };
        try { callback(undefined); } finally { callbackError = undefined; }
      });
    };
    const eventApi = listeners => ({ addListener: fn => listeners.add(fn), removeListener: fn => listeners.delete(fn), hasListener: fn => listeners.has(fn), hasListeners: () => listeners.size > 0 });
    const debuggerApi = {
      onEvent: eventApi(events), onDetach: eventApi(detaches),
      getTargets: callback => finish(call(native.debugger, 'getTargets'), callback),
      attach(target, version, callback) {
        return finish(serial('debug:' + keyOf(target), async () => {
          await debuggerReady;
          const key = keyOf(target); let state = attachments.get(key);
          if (state?.owners.has(owner)) return;
          if (!state) {
            await call(native.debugger, 'attach', target, version);
            state = { target, owners: new Set(), domains: new Map(), autoAttach: new Map(), children: new Map(), detachedSessions: new Set(), runtimeContexts: new Map() }; attachments.set(key, state);
          }
          state.owners.add(owner);
          try { await persistDebugger(); }
          catch (error) { state.owners.delete(owner); if (!state.owners.size) { await call(native.debugger, 'detach', state.target); attachments.delete(key); } throw error; }
        }), callback);
      },
      detach(target, callback) {
        return finish(serial('debug:' + keyOf(target), async () => {
          await debuggerReady;
          const key = keyOf(target), state = attachments.get(key);
          // Legacy agent attach starts with detach; it must not detach another owner.
          if (!state?.owners.has(owner)) return;
          if (state.owners.size === 1) {
            await call(native.debugger, 'detach', state.target);
            attachments.delete(key); await persistDebugger(); return;
          }
          for (const [name, domain] of state.domains) {
            if (!domain.owners.has(owner)) continue;
            if (domain.owners.size === 1) {
              await call(native.debugger, 'sendCommand', domain.target, domain.domain + '.disable', {});
              if (domain.domain === 'Runtime') forgetContexts(state, sessionKey(domain.target));
              state.domains.delete(name);
            } else domain.owners.delete(owner);
          }
          // Release nested subscriptions before their parent. Disabling a
          // parent can synchronously detach children and remove their records.
          for (const [id, entry] of deepestFirst(state)) {
            if (state.autoAttach.get(id) !== entry || !entry.owners.has(owner)) continue;
            await releaseAutoAttach(state, id, owner);
          }
          await pruneAutoAttach(state);
          state.owners.delete(owner);
          await persistDebugger();
        }), callback);
      },
      sendCommand(target, method, params = {}, callback) {
        if (typeof params === 'function') { callback = params; params = {}; }
        // A JavaScript dialog blocks the page, so a queued command awaiting page work
        // (an awaitPromise evaluate, a click whose handler alerts) cannot settle until the
        // dialog is handled. The handling command must not wait behind it; it touches no
        // domain or attachment bookkeeping, so it needs only the ownership check.
        if (method === 'Page.handleJavaScriptDialog') return finish((async () => {
          const state = attachments.get(keyOf(target));
          if (!state?.owners.has(owner)) throw Error('Debugger resource is not acquired by ' + owner + '.');
          assertLiveSession(state, target);
          return call(native.debugger, 'sendCommand', target, method, params);
        })(), callback);
        return finish(serial('debug:' + keyOf(target), async () => {
          const state = attachments.get(keyOf(target));
          if (!state?.owners.has(owner)) throw Error('Debugger resource is not acquired by ' + owner + '.');
          const [domain, action] = method.split('.'), key = domainKey(target, domain), existing = state.domains.get(key);
          if (target.sessionId && state.detachedSessions.has(target.sessionId) && (action === 'disable' || method === 'Target.setAutoAttach' && params.autoAttach === false)) return {};
          assertLiveSession(state, target);
          if (method === 'Target.setAutoAttach') {
            if (typeof params.autoAttach !== 'boolean') throw Error('Target.setAutoAttach requires a boolean autoAttach.');
            const id = sessionKey(target), current = state.autoAttach.get(id);
            if (!params.autoAttach) {
              const result = await releaseAutoAttach(state, id, owner); await pruneAutoAttach(state); return result;
            }
            const config = structuredClone({ ...params, waitForDebuggerOnStart: params.waitForDebuggerOnStart ?? false, flatten: params.flatten ?? false });
            const signature = canonical(config), same = current?.signature === signature;
            const consumers = new Set([...(current?.owners || []), ...descendantOwners(state, id)]);
            if (current && !same && (consumers.size > 1 || !consumers.has(owner))) throw Error('Debugger auto-attach configuration is in use by another owner.');
            if (same) {
              if (!current.owners.has(owner)) { current.owners.add(owner); replayChildren(state, id, owner); }
              return {};
            }
            const result = await call(native.debugger, 'sendCommand', target, method, config);
            assertLiveSession(state, target);
            state.autoAttach.set(id, { target: structuredClone(target), params: config, signature, owners: new Set([owner]) });
            return result;
          }
          if (action === 'enable') {
            if (existing && !existing.owners.has(owner) && !SHARED_DOMAINS.has(domain)) throw Error('Debugger domain is in use: ' + domain);
            const combined = { ...(existing?.params || {}), ...params };
            for (const [field, value] of Object.entries(existing?.params || {})) if (typeof value === 'number' && typeof params[field] === 'number') combined[field] = Math.max(value, params[field]);
            if (domain === 'Runtime' && existing && !existing.owners.has(owner) && state.runtimeContexts.get(sessionKey(target))?.incomplete) throw Error('Debugger runtime context inventory incomplete; revisit the document under capture.');
            const result = await call(native.debugger, 'sendCommand', target, method, combined);
            assertLiveSession(state, target);
            const entry = existing || { target, domain, owners: new Set(), params: combined };
            const newlySubscribed = !entry.owners.has(owner);
            if (domain === 'Runtime' && existing && newlySubscribed) replayContexts(state, target, owner);
            entry.params = combined; entry.owners.add(owner); state.domains.set(key, entry);
            return result;
          }
          if (action === 'disable') {
            if (!existing?.owners.has(owner)) return {};
            if (existing.owners.size > 1) { existing.owners.delete(owner); return {}; }
            const result = await call(native.debugger, 'sendCommand', target, method, params); state.domains.delete(key); if (domain === 'Runtime') forgetContexts(state, sessionKey(target)); await pruneAutoAttach(state); return result;
          }
          return call(native.debugger, 'sendCommand', target, method, params);
        }), callback);
      }
    };
    function rules(kind) {
      const get = kind === 'session' ? 'getSessionRules' : 'getDynamicRules', update = kind === 'session' ? 'updateSessionRules' : 'updateDynamicRules';
      return {
        get: callback => finish(serial('rules', async () => {
          await rulesReady;
          const mapping = ruleMaps[kind][owner] || {}, inverse = new Map(Object.entries(mapping).map(([logical, physical]) => [physical, Number(logical)]));
          return (await call(native.declarativeNetRequest, get)).filter(rule => inverse.has(rule.id)).map(rule => ({ ...rule, id: inverse.get(rule.id) }));
        }), callback),
        update: (change, callback) => finish(serial('rules', async () => {
          await rulesReady;
          const previous = structuredClone(ruleMaps), mapping = { ...(ruleMaps[kind][owner] || {}) };
          const current = await call(native.declarativeNetRequest, get), occupied = new Set(current.map(rule => rule.id));
          for (const entries of Object.values(ruleMaps[kind])) for (const id of Object.values(entries)) occupied.add(id);
          let next = DNR_FIRST;
          const validate = id => { if (!Number.isSafeInteger(id) || id < 1) throw Error('Rule ID must be a positive integer.'); };
          const removed = [];
          for (const id of change.removeRuleIds || []) { validate(id); if (mapping[id]) removed.push(mapping[id]); }
          const added = (change.addRules || []).map(rule => {
            validate(rule.id);
            if (!mapping[rule.id]) { while (occupied.has(next) && next <= DNR_LAST) next++; if (next > DNR_LAST) throw Error('Security rule ID range exhausted.'); mapping[rule.id] = next; occupied.add(next++); }
            return { ...rule, id: mapping[rule.id] };
          });
          await call(native.declarativeNetRequest, update, { removeRuleIds: removed, addRules: added });
          for (const id of change.removeRuleIds || []) if (!(change.addRules || []).some(rule => rule.id === id)) delete mapping[id];
          ruleMaps[kind][owner] = mapping;
          try { await native.storage.session.set({ [DNR_KEY]: ruleMaps }); }
          catch (error) {
            ruleMaps.session = previous.session; ruleMaps.dynamic = previous.dynamic;
            await call(native.declarativeNetRequest, update, { removeRuleIds: [...new Set([...removed, ...added.map(rule => rule.id)])], addRules: current.filter(rule => removed.includes(rule.id) || added.some(item => item.id === rule.id)) });
            throw error;
          }
        }), callback)
      };
    }
    const sessionRules = rules('session'), dynamicRules = rules('dynamic');
    const dnr = new Proxy(native.declarativeNetRequest, { get(target, name) {
      const own = { getSessionRules: sessionRules.get, updateSessionRules: sessionRules.update, getDynamicRules: dynamicRules.get, updateDynamicRules: dynamicRules.update };
      if (own[name]) return own[name]; const value = target[name]; return typeof value === 'function' ? value.bind(target) : value;
    } });
    const messageWrappers = new Map();
    const runtimeMessages = {
      addListener(listener) {
        if (messageWrappers.has(listener)) return;
        const wrapped = (message, sender, reply) => {
          const channel = message?.channel;
          if (typeof channel !== 'string' || (!channel.startsWith('ptk_') && !channel.startsWith('CERT_X_SECURITY_'))) return undefined;
          // Management is dispatched by cert-x after permission checks. Imported
          // popup/page-automation routes must not create a second control plane.
          if (typeof channel === 'string' && (channel.startsWith('ptk_popup2background_') || channel.startsWith('ptk_privileged_replayable_export') || channel === 'ptk_content2background_automation')) return undefined;
          return listener(message, sender, reply);
        };
        messageWrappers.set(listener, wrapped); native.runtime.onMessage.addListener(wrapped);
      },
      removeListener(listener) { const wrapped = messageWrappers.get(listener); if (wrapped) native.runtime.onMessage.removeListener(wrapped); messageWrappers.delete(listener); },
      hasListener(listener) { return messageWrappers.has(listener); }
    };
    const runtime = new Proxy(native.runtime, { get(target, name) { if (name === 'lastError') return callbackError || target.lastError; if (name === 'onMessage') return runtimeMessages; const value = target[name]; return typeof value === 'function' ? value.bind(target) : value; } });
    const offscreen = native.offscreen && {
      hasDocument: callback => finish(call(native.offscreen, 'hasDocument'), callback),
      createDocument(options, callback) { return finish(serial('offscreen', async () => {
        const contexts = await native.runtime.getContexts({ contextTypes: ['OFFSCREEN_DOCUMENT'] });
        const expected = native.runtime.getURL(options.url);
        if (contexts.some(context => context.documentUrl !== expected)) throw Error('An offscreen document is already in use by another capability.');
        if (!contexts.length) await call(native.offscreen, 'createDocument', options);
        offscreenOwners.add(owner);
      }), callback); },
      closeDocument(callback) { return finish(serial('offscreen', async () => {
        if (!offscreenOwners.has(owner)) return;
        if (offscreenOwners.size === 1) await call(native.offscreen, 'closeDocument');
        offscreenOwners.delete(owner);
      }), callback); }
    };
    const api = new Proxy(native, { get(target, name) { if (name === 'debugger') return debuggerApi; if (name === 'runtime') return runtime; if (name === 'declarativeNetRequest') return dnr; if (name === 'offscreen') return offscreen; return target[name]; } });
    facades.set(owner, { api, events, detaches }); return api;
  }
  const chrome = forOwner('security');
  return { chrome, browser: chrome, chromeDebugger: chrome.debugger, forOwner, ready: Promise.all([rulesReady, debuggerReady]) };
}

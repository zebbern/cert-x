import { scopeAllows } from '../config.mjs';

const AUTO_ATTACH = { autoAttach: true, waitForDebuggerOnStart: false, flatten: true, filter: [{ type: 'iframe', exclude: false }, { exclude: true }] };

// One resource owner covers the tab and its flat child sessions. The broker
// shares auto-attach subscriptions with browser control/capture consumers.
export function createIastDocuments({ api, tabId, source, files, context, onCoverage = () => {} }) {
  const targets = new Map(), pending = new Set(), errors = [];
  const injected = new Set();
  let active = false, stopped = false, injectTail = Promise.resolve();
  const key = target => target.sessionId || '';
  const track = promise => { pending.add(promise); promise.finally(() => pending.delete(promise)).catch(() => {}); return promise; };
  const coverage = () => ({ debuggerTargets: [...targets.values()].filter(entry => !entry.detached).length, documentInjections: injected.size, errors: errors.slice(), active });
  const publish = () => onCoverage(coverage());
  const fail = error => { errors.push(error.message || String(error)); publish(); };
  const injectExisting = () => {
    const task = injectTail.catch(() => {}).then(async () => {
      if (!active) return;
      await context.recheck?.(); context.signal?.throwIfAborted();
      const frames = await api.webNavigation.getAllFrames({ tabId }) || [];
      for (const frame of frames) {
        if (!active) return;
        if (!scopeAllows(frame.url, context.scope)) continue;
        if (!frame.documentId) throw Error('IAST requires document IDs for existing frame injection.');
        if (injected.has(frame.documentId)) continue;
        await context.recheck?.(); context.signal?.throwIfAborted();
        const latest = context.scopeNow ? await context.scopeNow() : context.scope;
        if (!scopeAllows(frame.url, latest)) continue;
        try {
          await api.scripting.executeScript({ target: { tabId, documentIds: [frame.documentId] }, world: 'MAIN', files });
          injected.add(frame.documentId);
          publish();
        } catch (error) {
          // A navigated/destroyed document must never fall back to its reused frame ID.
          const current = await api.webNavigation.getAllFrames({ tabId }) || [];
          if (current.some(item => item.documentId === frame.documentId)) throw error;
        }
      }
    });
    injectTail = task; return track(task);
  };
  const install = (target, parent = null) => {
    if (!active) return Promise.resolve();
    const id = key(target), existing = targets.get(id); if (existing) return existing.promise;
    const entry = { target, parent, identifier: null, autoAttach: false, detached: false }; targets.set(id, entry);
    entry.promise = track((async () => {
      const result = await api.debugger.sendCommand(target, 'Page.addScriptToEvaluateOnNewDocument', { source });
      entry.identifier = result.identifier;
      publish();
      if (!active || entry.detached) return;
      await api.debugger.sendCommand(target, 'Target.setAutoAttach', AUTO_ATTACH); entry.autoAttach = true;
      if (active && !entry.detached) await injectExisting();
    })());
    return entry.promise;
  };
  const onEvent = (target, method, params) => {
    if (target.tabId !== tabId) return;
    if (method === 'Target.attachedToTarget' && params.targetInfo?.type === 'iframe' && active) {
      install({ tabId, sessionId: params.sessionId }, key(target)).catch(fail);
    } else if (method === 'Target.detachedFromTarget') {
      const removed = new Set([params.sessionId]);
      for (;;) { const before = removed.size; for (const [id, entry] of targets) if (removed.has(entry.parent)) removed.add(id); if (removed.size === before) break; }
      for (const id of removed) { const entry = targets.get(id); if (entry) entry.detached = true; }
      publish();
    }
  };
  const onDetach = target => { if (target.tabId === tabId) { active = false; for (const entry of targets.values()) entry.detached = true; } };
  const onCommitted = details => { if (active && details.tabId === tabId) injectExisting().catch(fail); };
  async function drain() { while (pending.size) await Promise.allSettled([...pending]); }
  async function stop() {
    if (stopped) return; stopped = true; active = false; publish();
    api.debugger.onEvent.removeListener(onEvent); api.debugger.onDetach.removeListener(onDetach); api.webNavigation.onCommitted.removeListener(onCommitted);
    await drain(); const failures = [];
    for (const entry of [...targets.values()].reverse()) {
      if (entry.detached) continue;
      if (entry.identifier) try { await api.debugger.sendCommand(entry.target, 'Page.removeScriptToEvaluateOnNewDocument', { identifier: entry.identifier }); } catch (error) { if (!entry.detached) failures.push(error); }
      if (entry.autoAttach) try { await api.debugger.sendCommand(entry.target, 'Target.setAutoAttach', { autoAttach: false, waitForDebuggerOnStart: false, flatten: true }); } catch (error) { if (!entry.detached) failures.push(error); }
    }
    try { await api.debugger.detach({ tabId }); } catch (error) { failures.push(error); }
    if (failures.length) throw new AggregateError(failures, 'IAST frame cleanup was incomplete: ' + failures.map(error => error.message).join('; '));
  }
  return {
    async start() {
      active = true; api.debugger.onEvent.addListener(onEvent); api.debugger.onDetach.addListener(onDetach); api.webNavigation.onCommitted.addListener(onCommitted);
      try {
        await api.debugger.attach({ tabId }, '1.3'); await install({ tabId }); await drain();
        if (errors.length) throw Error(errors.join('; '));
      } catch (error) { await stop().catch(cleanup => { error.cleanupError = cleanup.message; }); throw error; }
    },
    stop,
    coverage
  };
}

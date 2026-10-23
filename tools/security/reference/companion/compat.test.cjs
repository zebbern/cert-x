const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), os = require('node:os'), vm = require('node:vm');
const { apply, patch, targets, revision } = require('./compat.cjs');
const source = process.env.PTK_SOURCE || path.resolve(__dirname, '../../../insp/pentestkit-10.0.0-release');
test('companion compatibility patch is repeatable, preserves source and refuses unrecognized output edits', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-x-ptk-compat-'));
  try {
    const originals = new Map(targets.map(relative => [relative, fs.readFileSync(path.join(source, relative), 'utf8')]));
    for (const [relative, content] of originals) { fs.mkdirSync(path.dirname(path.join(temp, relative)), { recursive: true }); fs.writeFileSync(path.join(temp, relative), content); }
    const first = apply(source, temp); assert.equal(first.revision, revision);
    assert.deepEqual(apply(source, temp, first), first);
    for (const [relative, content] of originals) assert.equal(fs.readFileSync(path.join(source, relative), 'utf8'), content);
    const target = targets[0]; fs.appendFileSync(path.join(temp, target), '\n// unrecognized user edit\n');
    assert.throws(() => apply(source, temp, first), /unrecognized edits/);
    assert.match(fs.readFileSync(path.join(temp, target), 'utf8'), /unrecognized user edit/);
  } finally { if (path.resolve(temp).startsWith(path.resolve(os.tmpdir()) + path.sep)) fs.rmSync(temp, { recursive: true, force: true }); }
});
test('patched IAST reserves startup and stopping so parallel requests cannot replace the engine', async () => {
  const relative = targets.find(file => file.endsWith('/iast.js')), content = patch(relative, fs.readFileSync(path.join(source, relative), 'utf8'));
  const method = (start, end) => content.slice(content.indexOf(start), content.indexOf(end, content.indexOf(start)));
  const methods = method('async runBackgroundScan(', 'async _certXRunBackgroundScan(') + ',' + method('async stopBackgroundScan(', 'async _certXStopBackgroundScan(');
  const value = vm.runInNewContext('({' + methods + '})');
  let releaseStart, releaseStop, starts = 0, stops = 0;
  value._certXRunBackgroundScan = async () => { starts++; await new Promise(resolve => releaseStart = resolve); value.isScanRunning = true; return true; };
  value._certXStopBackgroundScan = async () => { stops++; value.isScanRunning = false; await new Promise(resolve => releaseStop = resolve); return true; };
  const started = value.runBackgroundScan(1, 'host', 'SMART', {});
  assert.equal(await value.runBackgroundScan(2, 'host', 'SMART', {}), false); assert.equal(starts, 1);
  releaseStart(); await started;
  const stopped = value.stopBackgroundScan(), secondStop = value.stopBackgroundScan();
  assert.equal(await value.runBackgroundScan(2, 'host', 'SMART', {}), false); assert.equal(stops, 1);
  releaseStop(); await Promise.all([stopped, secondStop]); assert.equal(value._certXStopping, null);
});
test('single-tab reinjection follows same-origin paths without enrolling other tabs or origins', async () => {
  const relative = targets.find(file => file.endsWith('/iast.js')), content = patch(relative, fs.readFileSync(path.join(source, relative), 'utf8'));
  const start = content.indexOf('async onUpdated(tabId, info, tab) {'), end = content.indexOf('removeListeners() {', start);
  const injected = [], value = vm.runInNewContext('({' + content.slice(start, end) + '})', {
    clearIastModuleSendTracking() {}, worker: { isFirefox: false },
    normalizeIastRegistrationTarget: input => { try { return new URL(input); } catch { return null; } },
    shouldReinjectIastAgentForTabUpdate: args => args.isTrackedTab && args.isScanRunning && args.scopeAllowed,
    isIastNavigationUrlInScope: () => { throw Error('Single-tab navigation must use exact-origin scope, not initial path scope'); },
  });
  Object.assign(value, { isScanRunning: true, scanResult: { host: 'target.test', targetUrl: 'https://target.test/safe', settings: { certXSingleTab: true } },
    _normalizeTabId: id => id, _primaryScanTabId: () => 7, isTrackedScanTab: id => id === 7, injectIastAgent: async id => injected.push(id) });
  await value.onUpdated(7, { status: 'complete' }, { url: 'https://target.test/other-route' });
  await value.onUpdated(8, { status: 'complete' }, { url: 'https://target.test/other-route' });
  await value.onUpdated(7, { status: 'complete' }, { url: 'https://third-party.test/other-route' });
  assert.deepEqual(injected, [7]);
});
test('retained cert-x findings cannot be replaced by a larger foreign IAST scan', () => {
  const relative = targets.find(file => file.endsWith('/automation.js')), content = patch(relative, fs.readFileSync(path.join(source, relative), 'utf8'));
  const start = content.indexOf('_collectFindings(session, limit = 100) {'), end = content.indexOf('_collectAnalysisSnapshot(session) {', start);
  let owned = { scanId: 'owned', findings: [{ id: 'owned-one' }, { id: 'owned-two' }] };
  const value = vm.runInNewContext('({' + content.slice(start, end) + '})', {
    MAX_FINDINGS_LIMIT: 500, resultsRegistry: { get: (engine, id) => engine === 'IAST' && id === 'owned' ? owned : null },
  });
  value.app = { iast: { scanResult: { scanId: 'foreign', findings: [{ id: 'foreign-one' }, { id: 'foreign-two' }, { id: 'foreign-three' }] } } };
  value.engines = { getAdapter: () => ({ getFindings() { throw Error('Must not consult unrelated live findings'); } }), _extractFindings: result => result.findings };
  const session = { project: 'cert-x:original-chat', scanIds: { IAST: 'owned' }, engines: ['IAST'] };
  assert.deepEqual(JSON.parse(JSON.stringify(value._collectFindings(session).findings)), owned.findings);
  assert.equal(session.scanIds.IAST, 'owned');
  owned = null; assert.throws(() => value._collectFindings(session), /iast_session_result_unavailable/);
});

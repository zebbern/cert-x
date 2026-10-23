import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'

globalThis.self ||= {}
globalThis.browser ||= {
    runtime: { getURL: path => `chrome-extension://test/${path}`, onMessage: { addListener() {} } },
    tabs: { onRemoved: { addListener() {} }, onUpdated: { addListener() {} } },
    webRequest: { onCompleted: { addListener() {} } },
    storage: { local: { async get() { return {} }, async set() {} } }
}

const { ptk_sca } = await import('../../../security/ptk/background/sca.js')
const { default: retire } = await import('../../../security/ptk/packages/retire/retire.js')
const { scaCaptureKey, decodeScaBody, isScaBodyCandidate } = await import('../../../security/ptk/background/sca/capturedBody.js')
const { BrowserCaptureManager } = await import('../../../security/ptk/background/capture/browserCaptureManager.js')
const fullRepo = JSON.parse(retire.replaceVersion(fs.readFileSync(new URL('../../../security/ptk/packages/retire/jsrepository.json', import.meta.url), 'utf8')))
const repo = { jquery: fullRepo.jquery }
const vulnerableCode = 'var f="1.12.4",a={jquery:f,};'
const cleanCode = 'window.currentLibrary = { version: "4.0.0" };'

function harness() {
    const sca = new ptk_sca()
    sca.isScanRunning = true
    sca.activeTabId = 1
    sca.retire = retire
    sca.repo = repo
    sca.repoReady = Promise.resolve(repo)
    sca._schedulePersistScanResult = () => {}
    const grants = new Map()
    const consumed = []
    const lease = { tabId: 1, getResource: key => grants.get(key), consume: key => { consumed.push(key); grants.delete(key) } }
    const entry = { scan: sca.scanResult, lease, requests: new Map() }
    sca.captureLeases = new Map([[1, entry]])
    return { sca, lease, entry, grants, consumed }
}

function body({ requestId = 'r1', documentId = 'doc-a', body = vulnerableCode, url = 'https://app.test/auth-dynamic.js', ...rest } = {}) {
    return { epoch: 'epoch', tabId: 1, sessionId: '', frameId: 'frame', documentId,
        sessionGeneration: 1, navigationGeneration: 1, requestId, hop: 0, url,
        resourceType: 'Script', response: { mimeType: 'text/javascript', status: 200 },
        complete: true, base64Encoded: false, body, ...rest }
}

test('unmodified PTK content rule detects an executable signature but not a version comment', () => {
    assert.equal(retire.scanFileContent(vulnerableCode, repo, { sha1: () => '' })[0]?.version, '1.12.4')
    assert.deepEqual(retire.scanFileContent('// jquery 1.12.4', repo, { sha1: () => '' }), [])
    assert.deepEqual(retire.scanFileContent(cleanCode, repo, { sha1: () => '' }), [])
})

test('authenticated dynamic script uses exact captured grant, with no refetch', async () => {
    const h = harness()
    h.sca.certXFetch = () => { throw Error('unexpected_refetch') }
    const record = body()
    h.grants.set(scaCaptureKey(record), record)
    await h.sca._onCapturedResource(h.entry, h.lease, { type: 'request', record })
    await h.sca._onCapturedResource(h.entry, h.lease, { type: 'body', record })
    assert.ok(h.sca.scanResult.findings.some(f => f.evidence.sca.component.detection === 'filecontent' && f.evidence.sca.component.version === '1.12.4'), JSON.stringify(h.sca.scanResult.coverageWarnings))
    assert.deepEqual(h.sca.scanResult.scaBodyCoverage, { captured: 1, analyzed: 1, gaps: 0 })
    assert.deepEqual(h.consumed, [scaCaptureKey(record)])
    assert.equal((await h.sca.scan('https://app.test/jquery-1.12.4.js', { metadataOnly: true })).vulns.length > 0, true)
})

test('same URL in account B or a replaced document cannot borrow account A body', async () => {
    const h = harness()
    const a = body(), b = body({ requestId: 'r2', documentId: 'doc-b', body: cleanCode })
    h.grants.set(scaCaptureKey(b), b)
    await h.sca._onCapturedResource(h.entry, h.lease, { type: 'body', record: a })
    await h.sca._onCapturedResource(h.entry, h.lease, { type: 'body', record: b })
    assert.equal(h.sca.scanResult.findings.length, 0)
    assert.equal(h.sca.scanResult.scaBodyCoverage.analyzed, 1)
    assert.equal(h.sca.scanResult.scaBodyCoverage.gaps, 1)
})

test('request bookkeeping keeps reused native IDs separate across documents', async () => {
    const h = harness()
    const a = body({ requestId: 'reused', documentId: 'doc-a' })
    const b = body({ requestId: 'reused', documentId: 'doc-b', body: cleanCode })
    await h.sca._onCapturedResource(h.entry, h.lease, { type: 'request', record: a })
    await h.sca._onCapturedResource(h.entry, h.lease, { type: 'request', record: b })
    assert.equal(h.entry.requests.size, 2)
    h.grants.set(scaCaptureKey(b), b)
    await h.sca._onCapturedResource(h.entry, h.lease, { type: 'body', record: b })
    assert.equal(h.entry.requests.size, 1)
    assert.equal(h.sca.scanResult.findings.length, 0)
})

test('revocation during repository initialization prevents stale-body finding', async () => {
    const h = harness(), record = body()
    let resume
    h.sca.repoReady = new Promise(resolve => { resume = resolve })
    h.grants.set(scaCaptureKey(record), record)
    const pending = h.sca._onCapturedResource(h.entry, h.lease, { type: 'body', record })
    h.grants.delete(scaCaptureKey(record))
    resume(repo)
    await pending
    assert.equal(h.sca.scanResult.findings.length, 0)
    assert.equal(h.sca.scanResult.scaBodyCoverage.analyzed, 0)
    assert.equal(h.sca.scanResult.coverageWarnings[0].reason, 'capture_revoked_before_analysis')
    h.sca.isScanRunning = false
    h.grants.set(scaCaptureKey(record), record)
    await h.sca._onCapturedResource(h.entry, h.lease, { type: 'body', record })
    assert.equal(h.sca.scanResult.findings.length, 0)
})

test('repository load failure does not claim body analysis', async () => {
    const h = harness(), record = body()
    h.sca.repo = {}
    h.sca.retire = null
    h.grants.set(scaCaptureKey(record), record)
    await h.sca._onCapturedResource(h.entry, h.lease, { type: 'body', record })
    assert.deepEqual(h.sca.scanResult.scaBodyCoverage, { captured: 1, analyzed: 0, gaps: 1 })
    assert.equal(h.sca.scanResult.coverageWarnings[0].reason, 'sca_repository_unavailable')
})

test('coverage counters and gaps survive scan reload', () => {
    const h = harness()
    h.sca._bodyGap('https://app.test/auth-dynamic.js', 'response_body_unavailable', { tabId: 1, requestId: 'r1', documentId: 'doc-a' })
    const restored = h.sca._normalizeEnvelope(h.sca.scanResult)
    assert.deepEqual(restored.scaBodyCoverage, { captured: 0, analyzed: 0, gaps: 1 })
    assert.deepEqual(restored.scaSourceCoverage, { captured: 0, analyzed: 0, gaps: 0 })
    assert.equal(restored.coverageWarnings[0].documentId, 'doc-a')
})

test('truncated, invalid and oversized bodies become coverage gaps', async () => {
    const h = harness()
    const cases = [
        body({ requestId: 'truncated', truncated: true }),
        body({ requestId: 'bad-base64', body: '$$$', base64Encoded: true }),
        body({ requestId: 'limit', body: 'a'.repeat(8 * 1024 * 1024 + 1) })
    ]
    for (const record of cases) {
        h.grants.set(scaCaptureKey(record), record)
        await h.sca._onCapturedResource(h.entry, h.lease, { type: 'body', record })
    }
    assert.equal(h.sca.scanResult.findings.length, 0)
    assert.deepEqual(h.sca.scanResult.scaBodyCoverage, { captured: 0, analyzed: 0, gaps: 3 })
    assert.deepEqual(h.sca.scanResult.coverageWarnings.map(w => w.reason), ['response_body_incomplete', 'response_body_decode_failed', 'response_body_limit'])
    assert.equal(h.consumed.length, 3)
})

test('non-success and non-JavaScript responses cannot establish body coverage', async () => {
    const h = harness()
    const cases = [
        body({ requestId: 'auth-failed', response: { status: 401, mimeType: 'text/javascript' } }),
        body({ requestId: 'html', response: { status: 200, mimeType: 'text/html' } })
    ]
    for (const record of cases) {
        h.grants.set(scaCaptureKey(record), record)
        await h.sca._onCapturedResource(h.entry, h.lease, { type: 'body', record })
    }
    assert.equal(h.sca.scanResult.findings.length, 0)
    assert.deepEqual(h.sca.scanResult.coverageWarnings.map(w => w.reason), ['response_status_unavailable', 'non_javascript_response'])
})

test('stop drains admitted work and reports an uncompleted script body', async () => {
    const h = harness(), record = body()
    await h.sca._onCapturedResource(h.entry, h.lease, { type: 'request', record })
    let released = false
    h.entry.promise = Promise.resolve(h.lease)
    h.lease.freeze = () => {}
    h.lease.drain = async () => ({ complete: true })
    h.lease.release = async () => { released = true }
    await h.sca._releaseBrowserCapture(1)
    assert.equal(released, true)
    assert.equal(h.sca.scanResult.scaBodyCoverage.gaps, 1)
    assert.equal(h.sca.scanResult.coverageWarnings[0].reason, 'response_body_unavailable')
})

test('extensionless JavaScript response can gain a late body grant', async () => {
    const h = harness()
    const record = body({ resourceType: 'Fetch', url: 'https://app.test/asset/42' })
    await h.sca._onCapturedResource(h.entry, h.lease, { type: 'response', record })
    assert.equal(h.entry.requests.size, 1)
    h.grants.set(scaCaptureKey(record), record)
    await h.sca._onCapturedResource(h.entry, h.lease, { type: 'body', record })
    assert.equal(h.sca.scanResult.scaBodyCoverage.analyzed, 1)
    assert.equal(h.sca.scanResult.scaBodyCoverage.gaps, 0)
})

test('executed source has separate provenance and repeated batches do not repeat analysis', async () => {
    const h = harness()
    h.entry.ownerId = 'SCA:test'
    h.lease.epoch = 'epoch'
    h.lease.captureId = 'capture'
    const record = body({ requestId: 'debugger:s1', scriptId: 's1', executedSource: true,
        provenance: 'debugger_script_source' })
    const batch = () => ({ isActive: () => true, release() {}, read: () => ({
        identity: { epoch: 'epoch', captureId: 'capture', ownerId: 'SCA:test', tabId: 1 }, records: [record] }) })
    await h.sca._onSourceBatch(h.entry, h.lease, batch())
    await h.sca._onSourceBatch(h.entry, h.lease, batch())
    assert.deepEqual(h.sca.scanResult.scaSourceCoverage, { captured: 1, analyzed: 1, gaps: 0 })
    assert.deepEqual(h.sca.scanResult.scaBodyCoverage, { captured: 0, analyzed: 0, gaps: 0 })
    assert.ok(h.sca.scanResult.findings.every(finding => finding.evidence.sca.acquisition === 'debugger_script_source'))
})

test('identical source and HTTP body in one document are analyzed once', async () => {
    const h = harness()
    h.entry.ownerId = 'SCA:test'
    h.lease.epoch = 'epoch'
    h.lease.captureId = 'capture'
    const source = body({ requestId: 'debugger:same', scriptId: 'same', executedSource: true,
        provenance: 'debugger_script_source' })
    await h.sca._onSourceBatch(h.entry, h.lease, { isActive: () => true, release() {}, read: () => ({
        identity: { epoch: 'epoch', captureId: 'capture', ownerId: 'SCA:test', tabId: 1 }, records: [source] }) })
    const response = body({ requestId: 'http:same' })
    h.grants.set(scaCaptureKey(response), response)
    await h.sca._onCapturedResource(h.entry, h.lease, { type: 'body', record: response })
    assert.equal(h.sca.scanResult.scaSourceCoverage.analyzed, 1)
    assert.deepEqual(h.sca.scanResult.scaBodyCoverage, { captured: 1, analyzed: 0, gaps: 0 })
    assert.equal(h.sca.scanResult.findings.length > 0, true)
})

test('replaced document revokes an in-flight executed source', async () => {
    const h = harness()
    h.entry.ownerId = 'SCA:test'
    h.lease.epoch = 'epoch'
    h.lease.captureId = 'capture'
    let resume, active = true
    h.sca.repoReady = new Promise(resolve => { resume = resolve })
    const record = body({ requestId: 'debugger:s2', scriptId: 's2', executedSource: true,
        provenance: 'debugger_script_source' })
    const batch = { isActive: () => active, release() {}, read: () => ({
        identity: { epoch: 'epoch', captureId: 'capture', ownerId: 'SCA:test', tabId: 1 }, records: [record] }) }
    const pending = h.sca._onSourceBatch(h.entry, h.lease, batch)
    active = false
    resume(repo)
    await pending
    assert.equal(h.sca.scanResult.findings.length, 0)
    assert.equal(h.sca.scanResult.scaSourceCoverage.analyzed, 0)
    assert.equal(h.sca.scanResult.coverageWarnings.at(-1).reason, 'script_source_revoked_before_analysis')
})

test('candidate and decoder rules reject unrelated JSON and preserve UTF-8 base64 scripts', () => {
    assert.equal(isScaBodyCandidate(body({ resourceType: 'Fetch', url: 'https://app.test/api/token', response: { mimeType: 'application/json' } })), false)
    assert.equal(isScaBodyCandidate(body({ resourceType: 'Script' })), true)
    assert.equal(decodeScaBody(body({ body: btoa('window.x = "ok";'), base64Encoded: true })), 'window.x = "ok";')
})

test('capture manager grants a selected script by exact document and revokes it on replacement', async () => {
    let emit, admit
    const adapter = {
        setEventSink(fn) { emit = fn }, setAdmission(fn) { admit = fn },
        async configure() {}, async release() {}, async drain() {},
        getSnapshot: () => ({ frames: [{ tabId: 1, frameId: 'frame', documentId: 'doc-a',
            url: 'https://app.test/page', documentUrl: 'https://app.test/page', resourceType: 'Document',
            sessionGeneration: 1, navigationGeneration: 1 }] })
    }
    const manager = new BrowserCaptureManager({ adapter, epoch: 'epoch' })
    const lease = await manager.acquire({ ownerId: 'SCA:test', tabId: 1,
        scope: { targetUrl: 'https://app.test/page' }, capabilities: ['network', 'authBodies'],
        selectResource: (record, capability) => capability === 'authBodies' && isScaBodyCandidate(record) })
    const record = { ...body(), documentUrl: 'https://app.test/page' }
    assert.equal(admit(record, 'authBodies'), true)
    emit({ type: 'body', record })
    const exact = { ...record, epoch: lease.epoch }
    assert.equal(lease.getResource(scaCaptureKey(exact))?.body, vulnerableCode)
    assert.equal(lease.getResources({ url: record.url }).length, 0) // store rejects URL-only lookup
    emit({ type: 'invalidate', record: { ...record, reason: 'document_replaced' } })
    assert.equal(lease.getResource(scaCaptureKey(exact)), undefined)
    await lease.release('test_done')
})

test('SCA acquires only scoped script body capture for its scan owner', async () => {
    const sca = new ptk_sca()
    let acquired
    const lease = { tabId: 1, subscribe: () => () => {}, async release() {} }
    sca.setBrowserCaptureManager({ async acquire(options) { acquired = options; return lease } })
    const returned = await sca._acquireBrowserCapture(1, { targetUrl: 'https://app.test/page' })
    assert.equal(returned, lease)
    assert.equal(acquired.ownerId, `SCA:${sca.scanResult.scanId}`)
    assert.deepEqual(acquired.capabilities, ['network', 'authBodies', 'sources', 'executedSources'])
    assert.equal(acquired.selectResource(body(), 'authBodies'), true)
    assert.equal(acquired.selectResource({ executedSource: true }, 'sources'), true)
    assert.equal(acquired.selectResource(body(), 'sources'), false)
    assert.equal(acquired.selectResource(body({ resourceType: 'Fetch', url: 'https://app.test/api/token', response: {} }), 'authBodies'), false)
    await sca._releaseBrowserCapture(1, 'reset')
})

test('unavailable debugger source keeps body capture active and records a source gap', async () => {
    const sca = new ptk_sca()
    sca.isScanRunning = true
    sca._schedulePersistScanResult = () => {}
    const lease = { tabId: 1, subscribe: () => () => {}, subscribeSourceBatches: () => () => {},
        async collectExecutedSources() { throw Error('debugger_domain_in_use') }, async release() {} }
    sca.setBrowserCaptureManager({ async acquire() { return lease } })
    assert.equal(await sca._acquireBrowserCapture(1, { targetUrl: 'https://app.test/page' }), lease)
    assert.equal(sca.scanResult.scaBodyCoverage.gaps, 0)
    assert.equal(sca.scanResult.scaSourceCoverage.gaps, 1)
    assert.equal(sca.scanResult.coverageWarnings[0].reason, 'debugger_domain_in_use')
    await sca._releaseBrowserCapture(1, 'reset')
})


test('per-scan acquisition byte budgets apply before content analysis', async () => {
    const h = harness()
    h.entry.acquisition = { maxResourceBytes: 10, maxTotalBytes: 20 }
    const record = body()
    h.grants.set(scaCaptureKey(record), record)
    await h.sca._onCapturedResource(h.entry, h.lease, { type: 'body', record })
    assert.equal(h.sca.scanResult.findings.length, 0)
    assert.equal(h.sca.scanResult.coverageWarnings.at(-1).reason, 'acquisition_resource_limit')
    h.entry.acquisition = { maxResourceBytes: 1000, maxTotalBytes: 20 }
    h.grants.set(scaCaptureKey(record), record)
    await h.sca._onCapturedResource(h.entry, h.lease, { type: 'body', record })
    assert.equal(h.sca.scanResult.coverageWarnings.at(-1).reason, 'acquisition_total_limit')
})


test('stop outcome and effective acquisition configuration survive reload with bounded fields', () => {
    const h = harness()
    h.sca.scanResult.scaDrain = { complete: false, reason: 'capture_drain_timeout', gaps: 2 }
    h.sca.scanResult.scaAcquisitionLimits = { requested: { maxScripts: 1, drainTimeoutMs: 75 }, effective: { maxScripts: 1, maxResourceBytes: 8388608, maxTotalBytes: 33554432 } }
    const restored = h.sca._normalizeEnvelope(h.sca.scanResult)
    assert.deepEqual(restored.scaDrain, h.sca.scanResult.scaDrain)
    assert.deepEqual(restored.scaAcquisitionLimits, h.sca.scanResult.scaAcquisitionLimits)
    const invalid = h.sca._normalizeEnvelope({ scaDrain: { complete: 'yes' }, scaAcquisitionLimits: { effective: { maxScripts: Infinity, maxResourceBytes: -1 } } })
    assert.equal(invalid.scaDrain, undefined)
    assert.deepEqual(invalid.scaAcquisitionLimits, { effective: {} })
})

test('stop does not wait for blocked initial source collection once lease exists', async () => {
    const h = harness()
    let resolveInitial, releaseCleanup
    h.entry.promise = new Promise(resolve => { resolveInitial = resolve })
    h.entry.acquisition = { drainTimeoutMs: 10 }
    h.lease.stopAndDrain = async () => ({ complete: false, reason: 'capture_drain_timeout' })
    h.lease.release = () => new Promise(resolve => { releaseCleanup = resolve })
    const stopping = h.sca._releaseBrowserCapture(1)
    const result = await Promise.race([stopping.then(() => 'stopped'), new Promise(resolve => setTimeout(() => resolve('hung'), 100))])
    assert.equal(result, 'stopped')
    assert.equal(h.sca.scanResult.scaDrain.complete, false)
    assert.equal(h.sca.scanResult.scaDrain.cleanupPending, true)
    assert.equal(h.sca.captureLeases.has(1), false)
    releaseCleanup(); resolveInitial(); await new Promise(setImmediate)
    assert.equal(h.sca.scanResult.scaDrain.cleanupPending, false)
})

test('stop bounds pending lease acquisition, aborts it, and records later cleanup', async () => {
    const h = harness()
    let resolveInitial
    h.entry.lease = null
    h.entry.controller = new AbortController()
    h.entry.promise = new Promise(resolve => { resolveInitial = resolve })
    h.entry.acquisition = { drainTimeoutMs: 5 }
    await h.sca._releaseBrowserCapture(1)
    assert.equal(h.entry.controller.signal.aborted, true)
    assert.equal(h.sca.scanResult.scaDrain.complete, false)
    assert.equal(h.sca.scanResult.scaDrain.reason, 'capture_acquisition_stop_timeout')
    assert.equal(h.sca.captureLeases.has(1), false)
    resolveInitial(); await new Promise(setImmediate)
    assert.equal(h.sca.scanResult.scaDrain.cleanupPending, false)
})

test('one completed tab cannot hide another tab incomplete stop', async () => {
    const h = harness()
    h.lease.stopAndDrain = async () => ({ complete: false, reason: 'capture_drain_timeout' })
    h.lease.release = async () => {}
    h.sca.captureLeases.set(2, { scan: h.sca.scanResult, requests: new Map(), sourceTasks: new Set(),
      lease: { tabId: 2, async stopAndDrain() { return { complete: true, gaps: 0 } }, async release() {} } })
    await h.sca._releaseAllBrowserCapture()
    assert.equal(h.sca.scanResult.scaDrain.complete, false)
    assert.equal(h.sca.scanResult.scaDrain.tabs[1].complete, false)
    assert.equal(h.sca.scanResult.scaDrain.tabs[2].complete, true)
    assert.equal(h.sca._normalizeEnvelope(h.sca.scanResult).scaDrain.complete, false)
})


test('source batch analysis cannot escape the overall stop deadline', async () => {
    const h = harness()
    let resolveAnalysis
    h.entry.acquisition = { drainTimeoutMs: 5 }
    h.entry.sourceTasks = new Set([new Promise(resolve => { resolveAnalysis = resolve })])
    h.lease.stopAndDrain = async () => ({ complete: true })
    h.lease.release = async () => {}
    await h.sca._releaseBrowserCapture(1)
    assert.equal(h.sca.scanResult.scaDrain.complete, false)
    assert.equal(h.sca.scanResult.scaDrain.reason, 'capture_analysis_timeout')
    assert.equal(h.sca.captureLeases.has(1), false)
    resolveAnalysis()
})


test('late preloaded acquisition cannot write coverage into a replacement scan', async () => {
    const sca = new ptk_sca()
    sca.isScanRunning = true
    sca._schedulePersistScanResult = () => {}
    let resolveCollector
    const lease = { tabId: 1, subscribe: () => () => {}, subscribeSourceBatches: () => () => {},
        collectExecutedSources: () => new Promise(resolve => { resolveCollector = resolve }), async release() {} }
    sca.setBrowserCaptureManager({ async acquire() { return lease } })
    const started = sca._acquireBrowserCapture(1, { targetUrl: 'https://app.test/page' })
    const rejected = assert.rejects(started, /capture_owner_unavailable/)
    await new Promise(setImmediate)
    sca.captureLeases.get(1).stopping = true
    sca.captureLeases.clear()
    sca.scanResult = sca.getScanResultSchema()
    resolveCollector({ gaps: 1, childDocumentsUninspected: 1, effectiveLimits: { maxScripts: 1 } })
    await rejected
    assert.equal(sca.scanResult.scaAcquisitionLimits, undefined)
    assert.equal(sca.scanResult.scaSourceCoverage.gaps, 0)
    assert.equal(sca.scanResult.coverageWarnings?.length || 0, 0)
})

test('late rejected content analysis cannot append gaps to a new scan', async () => {
    const h = harness()
    let rejectRepo
    h.sca.repoReady = new Promise((resolve, reject) => { rejectRepo = reject })
    const record = body()
    h.grants.set(scaCaptureKey(record), record)
    const pending = h.sca._onCapturedResource(h.entry, h.lease, { type: 'body', record })
    h.sca.scanResult = h.sca.getScanResultSchema()
    rejectRepo(Error('repository_replaced'))
    await pending
    assert.equal(h.sca.scanResult.scaBodyCoverage.gaps, 0)
    assert.equal(h.sca.scanResult.coverageWarnings?.length || 0, 0)
})

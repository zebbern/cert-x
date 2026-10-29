// Imported PTK v10 regression; paths adapted to the owned cert-x subsystem.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url))
const CONTENT_IAST = await fs.readFile(
    path.join(TEST_DIR, '../../../security/ptk/content/iast.js'),
    'utf8'
)

function loadInternalMessagePredicate() {
    const start = CONTENT_IAST.indexOf('function isIastInternalMessagePayload')
    const end = CONTENT_IAST.indexOf('function isHiddenFrameTarget', start)
    assert.notEqual(start, -1, 'internal message predicate start not found')
    assert.notEqual(end, -1, 'internal message predicate end not found')
    return Function(`${CONTENT_IAST.slice(start, end)}; return isIastInternalMessagePayload;`)()
}

test('IAST recognizes only exact PTK-owned postMessage envelopes as internal', () => {
    const isInternal = loadInternalMessagePredicate()
    for (const source of [
        'ptk-automation',
        'ptk-extension',
        'ptk-spa-net',
        'ptk-spa',
        'ptk-leak',
        'ptk-leak-set',
        'ptk-pmtest',
        'ptk-xss'
    ]) {
        assert.equal(isInternal({ source }), true, source)
    }
    assert.equal(isInternal({ channel: 'ptk_iast_agent_ready' }), true)
    assert.equal(isInternal({ ptk_iast: true }), true)
    assert.equal(isInternal({ source: 'application' }), false)
    assert.equal(isInternal({ source: 'ptk-user-controlled' }), false)
    assert.equal(isInternal('ptk-spa-net'), false)
})

test('IAST postMessage sink bypasses PTK-owned envelopes before taint reporting', () => {
    const start = CONTENT_IAST.indexOf('// window.postMessage misuse')
    const end = CONTENT_IAST.indexOf('// IFrame navigation/content sinks', start)
    assert.notEqual(start, -1, 'postMessage sink start not found')
    assert.notEqual(end, -1, 'postMessage sink end not found')
    const source = CONTENT_IAST.slice(start, end)
    const internalGuard = source.indexOf('if (isIastInternalMessagePayload(message))')
    const taintReporter = source.indexOf('maybeReportTaintedValue(payload')
    assert.notEqual(internalGuard, -1)
    assert.notEqual(taintReporter, -1)
    assert.equal(internalGuard < taintReporter, true)
    assert.match(source, /return origPostMessage\.apply\(this, arguments\)/)
})

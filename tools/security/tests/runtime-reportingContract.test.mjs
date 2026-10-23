// Imported PTK v10 regression; paths adapted to the owned cert-x subsystem.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'

import {
    captureReportEngineSnapshots,
    countDastPresentationAttacks,
    countDastExecutedAttacks,
    groupDastReconFindings,
    partitionReportFindings,
    resolveReportEngineResult,
    summarizeReportFindings
} from '../../../security/ptk/browser/assets/js/report/reportingContract.js'

function finding(severity, extra = {}) {
    return {
        engine: 'DAST',
        severity,
        ...extra
    }
}

test('DAST report separates recon from vulnerability findings without requiring type', () => {
    const findings = [
        ...Array.from({ length: 7 }, () => finding('high')),
        finding('low'),
        finding('info'),
        ...Array.from({ length: 4 }, () => finding('low', { outputKind: 'recon' }))
    ]

    const partitioned = partitionReportFindings('DAST', findings)
    const summary = summarizeReportFindings(partitioned.findings)

    assert.equal(partitioned.findings.length, 9)
    assert.equal(partitioned.discoveries.length, 4)
    assert.deepEqual(summary, {
        findingsCount: 9,
        critical: 0,
        high: 7,
        medium: 0,
        low: 1,
        info: 1
    })
    assert.equal(
        summary.critical + summary.high + summary.medium + summary.low + summary.info,
        summary.findingsCount
    )
})

test('SAST hint and artifact observations are discovery, not findings', () => {
    const partitioned = partitionReportFindings('SAST', [
        { engine: 'SAST', severity: 'high', findingKind: 'finding' },
        { engine: 'SAST', severity: 'info', findingKind: 'hint' },
        { engine: 'SAST', severity: 'info', findingKind: 'artifact' }
    ])

    assert.equal(partitioned.findings.length, 1)
    assert.equal(partitioned.discoveries.length, 2)
})

test('IAST report includes vulnerability findings and excludes informational runtime items', () => {
    const partitioned = partitionReportFindings('IAST', [
        ...Array.from({ length: 5 }, () => ({ engine: 'IAST', severity: 'high' })),
        ...Array.from({ length: 6 }, () => ({ engine: 'IAST', severity: 'low' })),
        ...Array.from({ length: 10 }, () => ({ engine: 'IAST', severity: 'info' }))
    ])
    const summary = summarizeReportFindings(partitioned.findings)

    assert.equal(partitioned.findings.length, 11)
    assert.equal(partitioned.discoveries.length, 0)
    assert.equal(partitioned.excluded.length, 10)
    assert.deepEqual(summary, {
        findingsCount: 11,
        critical: 0,
        high: 5,
        medium: 0,
        low: 6,
        info: 0
    })
})

test('DAST attack total follows the bounded presentation snapshot and its grouping rules', () => {
    const requests = Array.from({ length: 478 }, (_, index) => ({
        id: `req-${index + 1}`,
        original: { request: { method: 'GET', url: `https://example.test/${index}` } },
        attacks: [{ id: `attack-${index + 1}`, success: false }]
    }))
    requests.push({
        id: 'req-recon-1',
        original: { request: { method: 'GET', url: 'https://example.test/a' } },
        attacks: [{ id: 'recon-1', outputKind: 'recon', presentationAggregate: 'scan', ruleId: 'server-banner' }]
    })
    requests.push({
        id: 'req-recon-2',
        original: { request: { method: 'GET', url: 'https://example.test/b' } },
        attacks: [{ id: 'recon-2', outputKind: 'recon', presentationAggregate: 'scan', ruleId: 'server-banner' }]
    })
    requests.push({
        id: 'req-finding',
        original: { request: { method: 'GET', url: 'https://example.test/finding' } },
        attacks: [{ id: 'finding-1', success: true, severity: 'high' }]
    })

    assert.equal(countDastPresentationAttacks({ stats: { attacksCount: 502 }, requests }), 480)
    assert.equal(countDastExecutedAttacks({ stats: { attacksCount: 502 }, requests }), 502)
    assert.equal(countDastExecutedAttacks({ requests }), 481)
})

test('DAST execution fallback preserves legacy records and does not count presentation groups', () => {
    const items = [{ attacks: [{}, {}, {}] }]
    assert.equal(countDastExecutedAttacks({ requests: [], items }), 3)
    assert.equal(countDastExecutedAttacks({ stats: { attacksCount: 'invalid' }, items }), 3)
    assert.equal(countDastExecutedAttacks({ stats: { attacksCount: -1 }, items }), 3)
    assert.equal(countDastExecutedAttacks({ stats: { attacksCount: 0 }, items }), 0)
    assert.equal(countDastExecutedAttacks({}), 0)
})

test('DAST reconnaissance grouping retains every observation and its evidence', () => {
    const findings = ['a', 'b'].map((id) => finding('low', {
        id, outputKind: 'recon', ruleId: 'banner', presentationAggregate: 'scan',
        location: { url: `https://example.test/${id}`, method: 'GET' },
        evidence: { marker: id }
    }))
    const before = JSON.stringify(findings)
    const groups = groupDastReconFindings({}, findings)
    assert.equal(groups.length, 1)
    assert.equal(groups[0].length, 2)
    assert.equal(groups[0][0], findings[0])
    assert.equal(groups[0][1], findings[1])
    assert.equal(JSON.stringify(findings), before)
})

test('full report consumes the captured engine result instead of a newer live result', async () => {
    let liveLoads = 0
    const snapshots = {
        dast: {
            captured: true,
            capturedAt: '2026-07-25T10:00:00.000Z',
            scanResult: { scanId: 'scan-old', host: 'example.test' }
        }
    }

    const result = await resolveReportEngineResult({
        snapshots,
        engine: 'dast',
        loadLive: async () => {
            liveLoads += 1
            return { scanResult: { scanId: 'scan-new', host: 'example.test' } }
        }
    })

    assert.equal(result.scanResult.scanId, 'scan-old')
    assert.equal(liveLoads, 0)
})

test('snapshot capture records every engine even when one has no result', async () => {
    const controllers = {
        dast: { init: async () => ({ scanResult: { scanId: 'dast-1' } }) },
        iast: { init: async () => ({ scanResult: { scanId: 'iast-1' } }) },
        sast: { init: async () => ({ scanResult: null }) },
        sca: { init: async () => { throw new Error('unavailable') } }
    }

    const snapshots = await captureReportEngineSnapshots(
        async (engine) => controllers[engine],
        { now: () => new Date('2026-07-25T10:00:00.000Z') }
    )

    assert.deepEqual(Object.keys(snapshots), ['dast', 'iast', 'sast', 'sca'])
    assert.equal(snapshots.dast.scanResult.scanId, 'dast-1')
    assert.equal(snapshots.iast.scanResult.scanId, 'iast-1')
    assert.equal(snapshots.sast.scanResult, null)
    assert.equal(snapshots.sca.scanResult, null)
    assert.equal(snapshots.sca.error, 'unavailable')
})

// Original PTK dashboard/report markup is not shipped; cert-x UI integration is tested separately.

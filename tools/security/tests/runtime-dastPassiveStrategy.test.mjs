// Imported PTK v10 regression; paths adapted to the owned cert-x subsystem.
import test from 'node:test'
import assert from 'node:assert/strict'

globalThis.self = globalThis

const { dastEngine } = await import('../../../security/ptk/background/dast/dastEngine.js')
const { DastTaskScheduler } = await import('../../../security/ptk/background/dast/services/dastTaskScheduler.js')

function engineHarness() {
    const engine = Object.create(dastEngine.prototype)
    engine.taskScheduler = new DastTaskScheduler()
    engine.strategyConfig = { strategy: 'SMART', findingScope: 'url-param-module' }
    engine._strategyFindingKeys = new Set()
    engine._fingerprintFromPayload = () => 'GET|fixture.test|/profile'
    engine._extractParamName = () => null
    engine._shouldCountSuccessAsFindingCandidate = () => true
    engine._taskConditionRequiresModuleExecuted = () => false
    engine._incrementStrategyStat = (field, delta = 1) => {
        engine.stats[field] = (engine.stats[field] || 0) + delta
    }
    engine.stats = {}
    return engine
}

function task(type, attackId) {
    return {
        type,
        moduleId: 'headers',
        module: { id: 'headers' },
        attack: { id: attackId, metadata: {} },
        payload: { request: { url: 'https://fixture.test/profile' } },
        urlFingerprint: 'GET|fixture.test|/profile'
    }
}

test('SMART strategy executes independent passive rules while preserving active stop-on-first', () => {
    const engine = engineHarness()
    const reported = []
    const execute = candidate => {
        if (engine._shouldSkipTaskDueToStrategy(candidate)) return false
        const result = { success: true, metadata: { id: candidate.attack.id } }
        reported.push(candidate.attack.id)
        engine._recordStrategyFinding(candidate, result)
        return true
    }

    assert.equal(execute(task('passive', 'header_csp_weak_scripts')), true)
    assert.equal(execute(task('passive', 'header_csp_frame_ancestors_missing_or_weak')), true)
    assert.deepEqual(reported, [
        'header_csp_weak_scripts',
        'header_csp_frame_ancestors_missing_or_weak'
    ])
    assert.equal(engine._strategyFindingKeys.size, 0)

    assert.equal(execute(task('active', 'active-first')), true)
    assert.equal(execute(task('active', 'active-second')), false)
    assert.equal(engine._strategyFindingKeys.size, 1)
    assert.equal(engine.stats.skippedDueToStrategy, 1)
})

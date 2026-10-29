// Imported PTK v10 regression; paths adapted to the owned cert-x subsystem.
import assert from 'node:assert/strict'
import test from 'node:test'

import {
    SensitiveArtifactStore,
    sensitiveArtifactTtls
} from '../../../security/ptk/background/sensitiveArtifactStore.js'

function legacyStorage(initial = {}) {
    const values = { ...initial }
    return {
        values,
        async get(key) {
            return { [key]: values[key] }
        },
        async remove(key) {
            delete values[key]
        }
    }
}

test('sensitive artifacts migrate out of shared local storage', async () => {
    const legacy = legacyStorage({
        ptk_jwt: { token: 'header.payload.signature' }
    })
    const store = new SensitiveArtifactStore({ indexedDBApi: null, legacyStorage: legacy })

    assert.deepEqual(await store.getItem('ptk_jwt'), { token: 'header.payload.signature' })
    assert.equal(legacy.values.ptk_jwt, undefined)
    assert.deepEqual(await store.getItem('ptk_jwt'), { token: 'header.payload.signature' })
})

test('expired artifacts are deleted and no longer returned', async () => {
    let now = 1_000
    const store = new SensitiveArtifactStore({
        indexedDBApi: null,
        legacyStorage: legacyStorage(),
        now: () => now
    })
    await store.setItem('ptk_jwt', { token: 'secret' }, { ttlMs: 100 })
    now = 1_101

    assert.deepEqual(await store.getItem('ptk_jwt'), {})
    assert.equal(store.memory.has('ptk_jwt'), false)
})

test('sensitive artifact classes have explicit bounded retention', () => {
    for (const key of [
        'ptk_jwt',
        'ptk_rbuilder',
        'ptk_recorder',
        'ptk_bugbounty_session_profiles_v1',
        'ptk_bugbounty_evidence_packages_v1'
    ]) {
        assert.equal(Number.isFinite(sensitiveArtifactTtls[key]), true)
        assert.equal(sensitiveArtifactTtls[key] > 0, true)
    }
})

test('clearAll removes every background-only artifact', async () => {
    const store = new SensitiveArtifactStore({ indexedDBApi: null, legacyStorage: legacyStorage() })
    await store.setItem('ptk_jwt', { token: 'one' })
    await store.setItem('ptk_rbuilder', [{ request: 'two' }])
    await store.clearAll()

    assert.deepEqual(await store.getItem('ptk_jwt'), {})
    assert.deepEqual(await store.getItem('ptk_rbuilder'), {})
})

// Imported PTK v10 regression; paths adapted to the owned cert-x subsystem.
import test from 'node:test'
import assert from 'node:assert/strict'

globalThis.self = globalThis.self || {}
globalThis.browser = globalThis.browser || {
    runtime: {
        getURL: (path) => `chrome-extension://ptk-test/${path}`,
        onMessage: { addListener() { }, removeListener() { } }
    },
    tabs: {
        onRemoved: { addListener() { }, removeListener() { } },
        onUpdated: { addListener() { }, removeListener() { } },
        sendMessage: async () => ({ resources: [] })
    },
    webRequest: {
        onCompleted: { addListener() { }, removeListener() { } }
    },
    storage: {
        local: {
            async get() { return {} },
            async set() { }
        }
    }
}

const { ptk_sca } = await import('../../../security/ptk/background/sca.js')

test('SCA accepts resources from a scoped related tab and rejects unrelated tabs', async () => {
    const engine = new ptk_sca()
    const scanned = []
    engine.isScanRunning = true
    engine.activeTabId = 1
    engine.scopedTabCoordinator = {
        isTrackedTab(engineId, tabId) {
            return engineId === 'SCA' && tabId === 2
        }
    }
    engine.scan = async (url) => {
        scanned.push(url)
        return { vulns: [] }
    }

    engine.onCompleted({
        tabId: 2,
        url: 'https://cdn.example.test/jquery-3.4.1.min.js'
    })
    engine.onCompleted({
        tabId: 3,
        url: 'https://cdn.example.test/unrelated.js'
    })
    await new Promise((resolve) => setTimeout(resolve, 0))

    assert.deepEqual(scanned, ['https://cdn.example.test/jquery-3.4.1.min.js'])
})

test('SCA completion collects already-present resources only for in-scope tracked tabs', async () => {
    const engine = new ptk_sca()
    const collected = []
    engine.isScanRunning = true
    engine.activeTabId = 1
    engine.scopedTabCoordinator = {
        isTrackedTab(_engineId, tabId) {
            return tabId === 2
        },
        isUrlInScope(_engineId, url) {
            return url === 'https://app.test/child/'
        }
    }
    engine.collectCurrentTabResources = async (tabId) => {
        collected.push(tabId)
        return []
    }

    await engine.onUpdated(2, { status: 'complete' }, { url: 'https://app.test/child/' })
    await engine.onUpdated(3, { status: 'complete' }, { url: 'https://app.test/unrelated/' })
    await new Promise((resolve) => setTimeout(resolve, 0))

    assert.deepEqual(collected, [2])
})

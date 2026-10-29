// Imported PTK v10 regression; paths adapted to the owned cert-x subsystem.
import test from 'node:test'
import assert from 'node:assert/strict'

import {
    ScopedTabSessionCoordinator
} from '../../../security/ptk/background/common/scopedTabSessionCoordinator.js'

test('explicit workspace host scope enrolls related ports/subdomains while retaining ownership and exclusions',async()=>{
 const coordinator=new ScopedTabSessionCoordinator({browserApi:createBrowserApi()});
 await coordinator.registerSession('IAST',{primaryTabId:1,targetUrl:'https://app.test/app',workspaceScope:{origins:['https://app.test'],excludePaths:['/private'],matchMode:'host',includeSubdomains:true}});
 assert.equal(coordinator.isUrlInScope('IAST','http://app.test:8080/app'),true);
 assert.equal(await coordinator.observeCreatedNavigationTarget({sourceTabId:1,tabId:2,url:'http://api.app.test:8080/app'}),true);
 assert.equal(coordinator.isTrackedTab('IAST',2),true);
 assert.equal(await coordinator.observeCreatedTab({id:3,url:'http://api.app.test:8080/app'}),false,'Matching URL alone is not ownership');
 for(const url of ['http://api.app.test:8080/private/data','http://badapp.test/app'])assert.equal(coordinator.isUrlInScope('IAST',url),false);
});

function createEvent() {
    const listeners = new Set()
    return {
        addListener(listener) {
            listeners.add(listener)
        },
        removeListener(listener) {
            listeners.delete(listener)
        },
        emit(...args) {
            for (const listener of listeners) listener(...args)
        },
        get size() {
            return listeners.size
        }
    }
}

function createBrowserApi(tabsById = new Map()) {
    return {
        tabs: {
            onCreated: createEvent(),
            onUpdated: createEvent(),
            onRemoved: createEvent(),
            async get(tabId) {
                const tab = tabsById.get(tabId)
                if (!tab) throw new Error('tab_not_found')
                return { ...tab }
            }
        },
        webNavigation: {
            onCreatedNavigationTarget: createEvent()
        }
    }
}

test('scoped tab coordinator enrolls bounded same-origin descendants and rejects unrelated tabs', async () => {
    const tabs = new Map([
        [1, { id: 1, url: 'http://127.0.0.1:8080/demo/' }]
    ])
    const browserApi = createBrowserApi(tabs)
    const enrolled = []
    const released = []
    const coordinator = new ScopedTabSessionCoordinator({ browserApi })

    await coordinator.registerSession('IAST', {
        primaryTabId: 1,
        targetUrl: 'http://127.0.0.1:8080/demo/',
        scopeMode: 'origin',
        onEnroll: (meta) => enrolled.push({ ...meta }),
        onRelease: (meta) => released.push({ ...meta })
    })

    assert.equal(await coordinator.observeCreatedNavigationTarget({
        sourceTabId: 1,
        tabId: 2,
        url: 'http://127.0.0.1:8080/targets/support-widget/vulnerable/'
    }), true)
    assert.equal(coordinator.isTrackedTab('IAST', 2), true)
    assert.equal(coordinator.getTabMeta('IAST', 2).parentTabId, 1)
    assert.equal(coordinator.getTabMeta('IAST', 2).rootTabId, 1)
    assert.equal(coordinator.getTabMeta('IAST', 2).depth, 1)

    assert.equal(await coordinator.observeCreatedNavigationTarget({
        sourceTabId: 2,
        tabId: 3,
        url: 'http://127.0.0.1:8080/targets/support-widget/review/details/'
    }), true)
    assert.equal(coordinator.getTabMeta('IAST', 3).parentTabId, 2)
    assert.equal(coordinator.getTabMeta('IAST', 3).depth, 2)

    // Same origin is not ownership without opener lineage.
    assert.equal(await coordinator.observeCreatedTab({
        id: 4,
        url: 'http://127.0.0.1:8080/targets/support-widget/vulnerable/'
    }), false)
    assert.equal(coordinator.isTrackedTab('IAST', 4), false)

    assert.equal(await coordinator.observeCreatedNavigationTarget({
        sourceTabId: 1,
        tabId: 5,
        url: 'https://example.test/external'
    }), false)
    assert.equal(coordinator.isTrackedTab('IAST', 5), false)
    assert.deepEqual(enrolled.map((entry) => entry.tabId), [2, 3])
    assert.deepEqual(released, [])
})

test('scoped tab coordinator keeps about:blank children pending and releases external redirects', async () => {
    const browserApi = createBrowserApi(new Map([
        [10, { id: 10, url: 'https://app.test/start/' }]
    ]))
    const enrolled = []
    const released = []
    const coordinator = new ScopedTabSessionCoordinator({ browserApi })

    await coordinator.registerSession('SCA', {
        primaryTabId: 10,
        targetUrl: 'https://app.test/start/',
        scopeMode: 'origin',
        onEnroll: (meta) => enrolled.push({ ...meta }),
        onRelease: (meta) => released.push({ ...meta })
    })

    assert.equal(await coordinator.observeCreatedTab({
        id: 11,
        openerTabId: 10,
        url: 'about:blank'
    }), false)
    assert.equal(coordinator.isTrackedTab('SCA', 11), false)
    assert.equal(coordinator.getTabMeta('SCA', 11, { includePending: true }).state, 'pending')

    assert.equal(await coordinator.observeTabUpdated(11, {
        url: 'https://app.test/components/review/'
    }, {
        id: 11,
        url: 'https://app.test/components/review/'
    }), true)
    assert.equal(coordinator.isTrackedTab('SCA', 11), true)

    assert.equal(await coordinator.observeCreatedNavigationTarget({
        sourceTabId: 11,
        tabId: 12,
        url: 'https://app.test/components/review/details/'
    }), true)
    assert.equal(coordinator.isTrackedTab('SCA', 12), true)

    assert.equal(await coordinator.observeTabUpdated(11, {
        url: 'https://outside.test/landing'
    }, {
        id: 11,
        url: 'https://outside.test/landing'
    }), false)
    assert.equal(coordinator.isTrackedTab('SCA', 11), false)
    assert.equal(coordinator.isTrackedTab('SCA', 12), false)
    assert.deepEqual(enrolled.map((entry) => entry.tabId), [11, 12])
    assert.deepEqual(released.map((entry) => [entry.tabId, entry.reason]), [
        [12, 'ancestor_out_of_scope'],
        [11, 'out_of_scope_navigation']
    ])
})

test('scoped tab coordinator preserves explicit path scope and isolates engine sessions', async () => {
    const browserApi = createBrowserApi(new Map([
        [20, { id: 20, url: 'https://range.test/escape/' }]
    ]))
    const dastEnrolled = []
    const sastEnrolled = []
    const coordinator = new ScopedTabSessionCoordinator({ browserApi })

    await coordinator.registerSession('DAST', {
        primaryTabId: 20,
        targetUrl: 'https://range.test/escape/',
        scopeMode: 'path',
        onEnroll: (meta) => dastEnrolled.push(meta.tabId)
    })
    await coordinator.registerSession('SAST', {
        primaryTabId: 20,
        targetUrl: 'https://range.test/escape/',
        scopeMode: 'origin',
        onEnroll: (meta) => sastEnrolled.push(meta.tabId)
    })

    await coordinator.observeCreatedNavigationTarget({
        sourceTabId: 20,
        tabId: 21,
        url: 'https://range.test/address/location/assign'
    })
    assert.equal(coordinator.isTrackedTab('DAST', 21), false)
    assert.equal(coordinator.isTrackedTab('SAST', 21), true)

    await coordinator.observeCreatedNavigationTarget({
        sourceTabId: 20,
        tabId: 22,
        url: 'https://range.test/escape/reflected/body?q=one'
    })
    assert.equal(coordinator.isTrackedTab('DAST', 22), true)
    assert.equal(coordinator.isTrackedTab('SAST', 22), true)

    coordinator.unregisterSession('SAST')
    assert.equal(coordinator.hasSession('SAST'), false)
    assert.equal(coordinator.hasSession('DAST'), true)
    assert.deepEqual(dastEnrolled, [22])
    assert.deepEqual(sastEnrolled, [21, 22])
})

test('scoped tab coordinator enforces tab-count and depth bounds and cleans closed descendants', async () => {
    const browserApi = createBrowserApi(new Map([
        [30, { id: 30, url: 'https://bounded.test/' }]
    ]))
    const released = []
    const coordinator = new ScopedTabSessionCoordinator({
        browserApi,
        maxRelatedTabs: 2,
        maxDepth: 2
    })
    await coordinator.registerSession('DAST', {
        primaryTabId: 30,
        targetUrl: 'https://bounded.test/',
        scopeMode: 'origin',
        onRelease: (meta) => released.push({ ...meta })
    })

    assert.equal(await coordinator.observeCreatedNavigationTarget({
        sourceTabId: 30,
        tabId: 31,
        url: 'https://bounded.test/one'
    }), true)
    assert.equal(await coordinator.observeCreatedNavigationTarget({
        sourceTabId: 31,
        tabId: 32,
        url: 'https://bounded.test/two'
    }), true)
    assert.equal(await coordinator.observeCreatedNavigationTarget({
        sourceTabId: 32,
        tabId: 33,
        url: 'https://bounded.test/too-deep'
    }), false)
    assert.equal(await coordinator.observeCreatedNavigationTarget({
        sourceTabId: 30,
        tabId: 34,
        url: 'https://bounded.test/too-many'
    }), false)

    coordinator.observeTabRemoved(31)
    assert.equal(coordinator.isTrackedTab('DAST', 31), false)
    assert.equal(coordinator.isTrackedTab('DAST', 32), false)
    assert.deepEqual(released.map((entry) => [entry.tabId, entry.reason]), [
        [32, 'ancestor_tab_closed'],
        [31, 'tab_closed']
    ])
})

test('scoped tab coordinator adds and removes browser listeners once', () => {
    const browserApi = createBrowserApi()
    const coordinator = new ScopedTabSessionCoordinator({ browserApi })

    assert.equal(coordinator.start(), true)
    assert.equal(coordinator.start(), false)
    assert.equal(browserApi.tabs.onCreated.size, 1)
    assert.equal(browserApi.tabs.onUpdated.size, 1)
    assert.equal(browserApi.tabs.onRemoved.size, 1)
    assert.equal(browserApi.webNavigation.onCreatedNavigationTarget.size, 1)

    assert.equal(coordinator.stop(), true)
    assert.equal(browserApi.tabs.onCreated.size, 0)
    assert.equal(browserApi.tabs.onUpdated.size, 0)
    assert.equal(browserApi.tabs.onRemoved.size, 0)
    assert.equal(browserApi.webNavigation.onCreatedNavigationTarget.size, 0)
})

test('native navigation and tabs signals enroll a related child only once, including overlapping callbacks', async () => {
    for (const nativeFirst of [true, false]) {
        const coordinator = new ScopedTabSessionCoordinator({ browserApi: createBrowserApi() })
        const enrolled = []
        let finishEnroll
        const held = new Promise(resolve => { finishEnroll = resolve })
        await coordinator.registerSession('DAST', {
            primaryTabId: 50, targetUrl: 'https://owned.test/app/', scopeMode: 'path',
            onEnroll: async meta => { enrolled.push(meta.tabId); await held }
        })
        const native = () => coordinator.observeCreatedNavigationTarget({
            sourceTabId: 50, tabId: 51, url: 'https://owned.test/app/child'
        })
        const tab = () => coordinator.observeCreatedTab({
            openerTabId: 50, id: 51, url: 'https://owned.test/app/child'
        })
        const first = nativeFirst ? native() : tab()
        assert.deepEqual(enrolled, [51])
        assert.equal(await (nativeFirst ? tab() : native()), true)
        assert.deepEqual(enrolled, [51], 'second native lineage signal must not activate twice')
        finishEnroll()
        assert.equal(await first, true)
        assert.equal(await native(), true)
        assert.deepEqual(enrolled, [51])
        assert.equal(coordinator.isTrackedTab('DAST', 50), true)
        assert.equal(coordinator.isTrackedTab('DAST', 51), true)
    }
})

test('native navigation listener preserves parent ownership, path scope and pending-child budgets', async () => {
    const coordinator = new ScopedTabSessionCoordinator({
        browserApi: createBrowserApi(), maxRelatedTabs: 1, maxDepth: 1
    })
    const enrolled = []
    await coordinator.registerSession('DAST', {
        primaryTabId: 60, targetUrl: 'https://owned.test/app/', scopeMode: 'path',
        onEnroll: meta => enrolled.push(meta.tabId)
    })
    for (const details of [
        { sourceTabId: 999, tabId: 61, url: 'https://owned.test/app/child' },
        { sourceTabId: 60, tabId: 62, url: 'https://foreign.test/app/child' },
        { sourceTabId: 60, tabId: 63, url: 'https://owned.test/other/' },
        { sourceTabId: 60, tabId: 60, url: 'https://owned.test/app/' }
    ]) assert.equal(await coordinator.observeCreatedNavigationTarget(details), false)
    assert.deepEqual(enrolled, [])
    assert.equal(await coordinator.observeCreatedNavigationTarget({
        sourceTabId: 60, tabId: 64, url: 'about:blank'
    }), false)
    assert.equal(coordinator.getTabMeta('DAST', 64, { includePending: true }).state, 'pending')
    assert.equal(await coordinator.observeCreatedNavigationTarget({
        sourceTabId: 64, tabId: 65, url: 'https://owned.test/app/grandchild'
    }), false, 'a pending parent cannot enroll another tab')
    assert.equal(await coordinator.observeCreatedNavigationTarget({
        sourceTabId: 60, tabId: 66, url: 'https://owned.test/app/over-budget'
    }), false, 'pending tabs consume the related-tab cap')
    assert.equal(await coordinator.observeTabUpdated(64, { url: 'https://owned.test/app/child' }), true)
    assert.equal(await coordinator.observeCreatedNavigationTarget({
        sourceTabId: 64, tabId: 65, url: 'https://owned.test/app/grandchild'
    }), false, 'active descendants still obey depth bound')
    assert.deepEqual(enrolled, [64])
    coordinator.unregisterSession('DAST')
    assert.equal(await coordinator.observeCreatedNavigationTarget({
        sourceTabId: 60, tabId: 67, url: 'https://owned.test/app/child'
    }), false, 'stopped owners cannot enroll children')
})

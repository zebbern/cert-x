// Imported PTK v10 regression; paths adapted to the owned cert-x subsystem.
import assert from 'node:assert/strict'
import test from 'node:test'

function restoreGlobal(name, value, existed) {
    if (existed) globalThis[name] = value
    else delete globalThis[name]
}

function makeWebRequestEvent(listeners, name) {
    return {
        addListener(fn) {
            listeners[name] = fn
        },
        removeListener(fn) {
            assert.equal(listeners[name], fn)
            listeners[name] = null
        }
    }
}

test('manual Request Builder follows redirects with only response-issued cookies and only locks restricted-header hops', async (t) => {
    const originalGlobals = Object.fromEntries(
        ['self', 'browser', 'chrome', 'fetch'].map((name) => [name, {
            existed: Object.prototype.hasOwnProperty.call(globalThis, name),
            value: globalThis[name]
        }])
    )
    t.after(() => {
        for (const [name, state] of Object.entries(originalGlobals)) {
            restoreGlobal(name, state.value, state.existed)
        }
    })

    const listeners = {}
    const dnrCalls = []
    const fetchCalls = []
    let requestSequence = 0
    globalThis.self = { isFirefox: false }
    globalThis.browser = {
        runtime: {
            id: 'ptk-rbuilder-unit-id',
            getURL: (value = '') => `chrome-extension://ptk-rbuilder-unit-id/${value}`
        },
        webRequest: {
            onBeforeRequest: makeWebRequestEvent(listeners, 'onBeforeRequest'),
            onBeforeSendHeaders: makeWebRequestEvent(listeners, 'onBeforeSendHeaders'),
            onHeadersReceived: makeWebRequestEvent(listeners, 'onHeadersReceived')
        },
        storage: {
            local: {
                get: async () => ({}),
                set: async () => undefined
            }
        }
    }
    globalThis.chrome = {
        runtime: { id: 'ptk-rbuilder-unit-id' },
        declarativeNetRequest: {
            async updateSessionRules(value) {
                dnrCalls.push(structuredClone(value))
            },
            async getSessionRules() {
                return []
            },
            async getDynamicRules() {
                return []
            },
            async updateDynamicRules() {
                return undefined
            }
        }
    }

    globalThis.fetch = async (url, params = {}) => {
        const requestId = `request-${++requestSequence}`
        const requestHeaders = Object.entries(params.headers || {}).map(([name, value]) => ({ name, value }))
        fetchCalls.push({ url, params: structuredClone(params) })
        listeners.onBeforeRequest?.({ requestId, type: 'xmlhttprequest', url, method: params.method })
        listeners.onBeforeSendHeaders?.({ requestId, requestHeaders })

        if (url === 'http://example.test/doLogin') {
            listeners.onHeadersReceived?.({
                requestId,
                statusCode: 302,
                statusLine: 'HTTP/1.1 302 Found',
                responseHeaders: [
                    { name: 'Set-Cookie', value: 'JSESSIONID=issued-session; Path=/; HttpOnly' },
                    { name: 'Location', value: '/login.jsp' }
                ]
            })
            return {
                status: 0,
                statusText: '',
                headers: new Map(),
                async text() { return '' }
            }
        }

        listeners.onHeadersReceived?.({
            requestId,
            statusCode: 200,
            statusLine: 'HTTP/1.1 200 OK',
            responseHeaders: [{ name: 'Content-Type', value: 'text/html' }]
        })
        return {
            status: 200,
            statusText: 'OK',
            headers: new Map([['content-type', 'text/html']]),
            async text() { return 'Syntax error: Encountered "\\\'" at line 1, column 68.' }
        }
    }

    const { ptk_request, ptk_request_manager } = await import('../../../security/ptk/background/rbuilder.js')
    const manager = { storage: [] }
    const result = await ptk_request_manager.prototype.msg_send_request.call(manager, {
        useListeners: true,
        schema: {
            opts: {
                override_headers: true,
                follow_redirect: true,
                update_content_length: true
            },
            request: {
                method: 'POST',
                url: 'http://example.test/doLogin',
                headers: [
                    { name: 'Content-Type', value: 'application/x-www-form-urlencoded' },
                    { name: 'Authorization', value: 'Bearer initial-only' }
                ],
                body: { text: 'btnSubmit=Login&passw=asd%27&uid=asd' }
            },
            response: {}
        }
    })

    assert.equal(result.response.statusCode, 200)
    assert.equal(result.response.redirectCount, 1)
    assert.equal(result.response.redirected, true)
    assert.equal(result.response.url, 'http://example.test/login.jsp')
    assert.match(result.response.body, /column 68/u)
    assert.equal(fetchCalls.length, 2)
    assert.ok(fetchCalls.every((call) => call.params.credentials === 'omit'))
    assert.ok(fetchCalls.every((call) => call.params.redirect === 'manual'))
    assert.equal(fetchCalls[0].params.method, 'POST')
    assert.equal(fetchCalls[1].params.method, 'GET')
    assert.equal(Object.hasOwn(fetchCalls[1].params, 'body'), false)

    const addCalls = dnrCalls.filter((call) => Array.isArray(call.addRules))
    assert.equal(addCalls.length, 1)
    const secondHeaders = addCalls[0].addRules[0].action.requestHeaders
    assert.deepEqual(
        secondHeaders.find((header) => header.header.toLowerCase() === 'cookie'),
        { header: 'Cookie', operation: 'set', value: 'JSESSIONID=issued-session' }
    )
    assert.equal(secondHeaders.some((header) => header.header.toLowerCase() === 'content-type'), false)
    assert.equal(addCalls[0].addRules[0].condition.regexFilter, '^http://example\\.test/login\\.jsp$')
    assert.equal(dnrCalls.filter((call) => Array.isArray(call.removeRuleIds)).length, 1)

    dnrCalls.length = 0
    fetchCalls.length = 0
    globalThis.fetch = async (url, params = {}) => {
        fetchCalls.push({ url, params: structuredClone(params) })
        return {
            status: 200,
            statusText: 'OK',
            headers: new Map([['content-type', 'text/plain']]),
            async text() { return 'dast' }
        }
    }
    const dastRequest = new ptk_request()
    const dastResult = await dastRequest.sendRequest({
        opts: { override_headers: true, follow_redirect: true },
        request: {
            method: 'GET',
            url: 'http://example.test/dast',
            headers: [{ name: 'Accept', value: 'text/plain' }]
        },
        response: {}
    })
    assert.equal(dastResult.response.statusCode, 200)
    assert.equal(fetchCalls.length, 1)
    assert.equal(fetchCalls[0].params.credentials, 'omit')
    assert.equal(fetchCalls[0].params.redirect, 'follow')
    assert.equal(dnrCalls.length, 0)

    dnrCalls.length = 0
    fetchCalls.length = 0
    let retryAttempt = 0
    globalThis.fetch = async (url, params = {}) => {
        retryAttempt += 1
        fetchCalls.push({ url, params: structuredClone(params) })
        if (retryAttempt === 1) throw new TypeError('Failed to fetch')
        return {
            status: 200,
            statusText: 'OK',
            headers: new Map([['content-type', 'text/plain']]),
            async text() { return 'recovered' }
        }
    }
    const retryRequest = new ptk_request()
    retryRequest.isolatedRedirectSession = true
    const retryResult = await retryRequest.sendRequest({
        opts: {
            override_headers: true,
            follow_redirect: true,
            retry_on_transport_failure: true,
            transport_retry_count: 1,
            transport_retry_delay_ms: 0
        },
        request: {
            method: 'GET',
            url: 'http://example.test/retry',
            headers: [{ name: 'Accept', value: 'text/plain' }]
        },
        response: {}
    })
    assert.equal(retryResult.response.statusCode, 200)
    assert.equal(retryResult.response.body, 'recovered')
    assert.equal(retryResult.response.transportAttempts, 2)
    assert.equal(retryResult.response.transportRetried, true)
    assert.equal(retryResult.response.transportRetryCount, 1)
    assert.equal(fetchCalls.length, 2)
    assert.equal(dnrCalls.length, 0)

    dnrCalls.length = 0
    fetchCalls.length = 0
    const explicitCookieResult = await ptk_request_manager.prototype.msg_send_request.call(manager, {
        useListeners: true,
        schema: {
            opts: { override_headers: true, follow_redirect: true },
            request: {
                method: 'GET',
                url: 'http://example.test/explicit-cookie',
                headers: [{ name: 'Cookie', value: 'raw=expected' }]
            },
            response: {}
        }
    })
    assert.equal(explicitCookieResult.response.statusCode, 200)
    assert.equal(fetchCalls[0].params.credentials, 'omit')
    assert.equal(fetchCalls[0].params.redirect, 'manual')
    const explicitRule = dnrCalls.find((call) => Array.isArray(call.addRules))?.addRules?.[0]
    assert.deepEqual(
        explicitRule.action.requestHeaders.find((header) => header.header.toLowerCase() === 'cookie'),
        { header: 'Cookie', operation: 'set', value: 'raw=expected' }
    )

    dnrCalls.length = 0
    fetchCalls.length = 0
    const noFollowResult = await ptk_request_manager.prototype.msg_send_request.call(manager, {
        useListeners: true,
        schema: {
            opts: { override_headers: true, follow_redirect: false },
            request: {
                method: 'GET',
                url: 'http://example.test/no-follow',
                headers: [{ name: 'Accept', value: 'text/plain' }]
            },
            response: {}
        }
    })
    assert.equal(noFollowResult.response.statusCode, 200)
    assert.equal(fetchCalls[0].params.credentials, 'omit')
    assert.equal(fetchCalls[0].params.redirect, 'manual')
    assert.equal(dnrCalls.length, 0)
})

test('isolated redirect header merge strips cross-origin credentials', async () => {
    const originalSelf = globalThis.self
    const selfExisted = Object.prototype.hasOwnProperty.call(globalThis, 'self')
    globalThis.self = { isFirefox: true }
    const { RequestBuilderTransport } = await import('../../../security/ptk/background/requestBuilder/transport.js')
    const transport = new RequestBuilderTransport()
    const schema = { opts: { update_content_length: true } }
    const crossOrigin = transport._isolatedRedirectHeaders([
        { name: 'Authorization', value: 'Bearer secret' },
        { name: 'Proxy-Authorization', value: 'Basic secret' },
        { name: 'Origin', value: 'https://first.test' },
        { name: 'Referer', value: 'https://first.test/start' },
        { name: 'Cookie', value: 'ambient=secret' },
        { name: 'Accept', value: 'text/html' }
    ], {
        currentUrl: 'https://second.test/final',
        previousUrl: 'https://first.test/start',
        method: 'GET',
        body: null,
        cookieHeader: '',
        ptkReqId: 'request-id',
        ptkSource: 'rbuilder',
        schema
    })
    const names = crossOrigin.ruleHeaders.map((header) => header.name.toLowerCase())
    assert.equal(names.includes('authorization'), false)
    assert.equal(names.includes('proxy-authorization'), false)
    assert.equal(names.includes('origin'), false)
    assert.equal(names.includes('referer'), false)
    assert.equal(names.includes('cookie'), false)
    assert.equal(names.includes('accept'), true)

    const browserManaged = transport._isolatedRedirectHeaders([
        { name: 'Cookie', value: 'raw=expected' },
        { name: 'Origin', value: 'https://origin.test' },
        { name: 'User-Agent', value: 'PTK-Test/1' },
        { name: 'Accept', value: 'application/json' }
    ], {
        currentUrl: 'https://first.test/start',
        method: 'GET',
        body: null,
        cookieHeader: 'raw=expected',
        ptkReqId: 'request-id-2',
        ptkSource: 'rbuilder',
        schema: { opts: { override_headers: false, update_content_length: true } }
    })
    assert.deepEqual(
        browserManaged.ruleHeaders.map((header) => header.name.toLowerCase()).sort(),
        ['cookie', 'x-ptk-reqid', 'x-ptk-source']
    )
    assert.equal(browserManaged.fetchHeaders.Origin, 'https://origin.test')
    assert.equal(browserManaged.fetchHeaders['User-Agent'], 'PTK-Test/1')

    if (selfExisted) globalThis.self = originalSelf
    else delete globalThis.self
})

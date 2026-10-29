// Imported PTK v10 regression; paths adapted to the owned cert-x subsystem.
import test from 'node:test'
import assert from 'node:assert/strict'

globalThis.self = globalThis
globalThis.fetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({ modules: [] }),
    text: async () => JSON.stringify({ modules: [] })
})

const { dastEngine } = await import('../../../security/ptk/background/dast/dastEngine.js')

function storedTask() {
    return {
        moduleId: 'stored_xss_blind',
        module: { id: 'stored_xss_blind', runtime: { mode: 'standard' } },
        attack: {
            id: 'stored_xss_comment_svg',
            action: {
                random: 'abc123',
                params: [{ value: "<svg/onload=window.postMessage({source:'ptk-xss',id:'PTK_STORED_XSS_abc123'},'*')>" }]
            },
            runtime: {
                confirmation: {
                    tracking: {
                        enabled: true,
                        mode: 'followup_get',
                        marker: 'PTK_STORED_XSS_%%random%%',
                        confidence: 90
                    }
                }
            }
        },
        payload: {
            metadata: {
                attacked: { location: 'form', name: 'comment' }
            }
        }
    }
}

function storedExecution(body = 'stored PTK_STORED_XSS_abc123') {
    return {
        request: {
            url: 'https://example.test/comments',
            ui_url: 'https://example.test/comments',
            method: 'POST',
            headers: [{ name: 'Content-Type', value: 'application/x-www-form-urlencoded' }],
            body: { text: 'comment=payload' }
        },
        response: {
            statusCode: 302,
            headers: [
                { name: 'Location', value: '/comments/42' },
                { name: 'X-External-Location', value: 'https://outside.test/ignored' }
            ],
            body
        },
        metadata: {
            attacked: { location: 'form', name: 'comment' }
        }
    }
}

function makeEngine({ executed = true, followupMarker = true } = {}) {
    const engine = Object.create(dastEngine.prototype)
    const events = []
    const followups = []
    const browserUrls = []
    const browserMarkers = []
    engine.host = 'example.test'
    engine.domains = []
    engine._appendTaskRuntimeEvent = (_task, _context, event) => events.push(event)
    engine.activeAttack = async (request) => {
        followups.push(structuredClone(request))
        return {
            request: structuredClone(request.request),
            response: {
                statusCode: 200,
                headers: [{ name: 'Content-Type', value: 'text/html' }],
                body: followupMarker ? 'render PTK_STORED_XSS_abc123' : 'clean render'
            }
        }
    }
    engine._withBrowserNavAttackTab = async (url, fn) => {
        browserUrls.push(url)
        return fn(71)
    }
    engine._runBrowserNavChecksInTab = async (_tabId, _task, _context, marker) => {
        browserMarkers.push(marker)
        return {
            dom_xss: {
                vulnerable: executed,
                executed,
                reflected: false,
                sinkKey: executed ? 'img:onerror' : null,
                context: executed ? { type: 'event_handler', attr: 'onerror' } : null
            }
        }
    }
    return { engine, events, followups, browserUrls, browserMarkers }
}

test('stored-XSS retrieval is not reported without exact browser execution', async () => {
    const { engine, events, browserUrls, browserMarkers } = makeEngine({ executed: false })
    const task = storedTask()
    const result = await engine._runTracking(task, storedExecution(), {
        original: { request: { url: 'https://example.test/comments', method: 'POST' } }
    })

    assert.equal(result, null)
    assert.deepEqual(browserMarkers, ['PTK_STORED_XSS_abc123', 'PTK_STORED_XSS_abc123'])
    assert.deepEqual(browserUrls, [
        'https://example.test/comments',
        'https://example.test/comments/42'
    ])
    assert.equal(events.some((event) => event.type === 'dast_stored_xss_retrieved_unconfirmed'), true)
})

test('stored-XSS reports executed only after the exact browser marker is observed', async () => {
    const { engine, followups, browserUrls, browserMarkers } = makeEngine({ executed: true })
    const task = storedTask()
    const result = await engine._runTracking(task, storedExecution(), {
        original: { request: { url: 'https://example.test/comments', method: 'POST' } }
    })

    assert.equal(result.success, true)
    assert.equal(result.executed, true)
    assert.equal(result.trackingTier, 'executed')
    assert.equal(result.metadata.confirmation.channel, 'browser_nav')
    assert.equal(result.metadata.storedXss.submission.method, 'POST')
    assert.deepEqual(result.metadata.storedXss.submission.attacked, { location: 'form', name: 'comment' })
    assert.equal(result.metadata.storedXss.renderUrl, 'https://example.test/comments')
    assert.deepEqual(browserUrls, ['https://example.test/comments'])
    assert.deepEqual(browserMarkers, ['PTK_STORED_XSS_abc123'])
    assert.ok(followups.length <= 2)
    assert.ok(followups.every((entry) => entry.request.method === 'GET'))
    assert.ok(followups.every((entry) => entry.request.body === null))
})

test('stored-XSS follow-up retrieval uses the same exact browser execution gate', async () => {
    const { engine, browserUrls, browserMarkers } = makeEngine({ executed: true, followupMarker: true })
    const result = await engine._runTracking(storedTask(), storedExecution('submission accepted'), {
        original: { request: { url: 'https://example.test/comments', method: 'POST' } }
    })

    assert.equal(result?.success, true)
    assert.equal(result?.trackingTier, 'executed')
    assert.equal(result?.tracking?.source, 'browser')
    assert.equal(result?.tracking?.marker, 'PTK_STORED_XSS_abc123')
    assert.deepEqual(browserUrls, ['https://example.test/comments'])
    assert.deepEqual(browserMarkers, ['PTK_STORED_XSS_abc123'])
})

test('stored-XSS immediate-response retrieval still requires browser execution', async () => {
    const { engine, browserUrls } = makeEngine({ executed: true, followupMarker: false })
    const result = await engine._runTracking(storedTask(), storedExecution(), {
        original: { request: { url: 'https://example.test/comments', method: 'POST' } }
    })

    assert.equal(result?.success, true)
    assert.equal(result?.metadata?.confirmation?.channel, 'browser_nav')
    assert.deepEqual(browserUrls, ['https://example.test/comments'])
})

test('stored-XSS ignores missing and wrong retrieval markers without opening a browser tab', async () => {
    const { engine, browserUrls, events } = makeEngine({ executed: true, followupMarker: false })
    const result = await engine._runTracking(storedTask(), storedExecution('wrong marker'), {
        original: { request: { url: 'https://example.test/comments', method: 'POST' } }
    })

    assert.equal(result, null)
    assert.deepEqual(browserUrls, [])
    assert.equal(events.some((event) => event.type === 'dast_stored_xss_retrieved_unconfirmed'), false)
})

test('stored-XSS render candidates are same-origin, in-scope and capped at two', () => {
    const { engine } = makeEngine()
    const executed = storedExecution()
    executed.response.headers = [{ name: 'Location', value: 'https://outside.test/review' }]
    executed.response.finalUrl = 'https://example.test/comments/42'

    const candidates = engine._storedXssRenderCandidates(storedTask(), executed, {
        original: { request: { url: 'https://example.test/comments', method: 'POST' } }
    })

    assert.deepEqual(candidates, [
        'https://example.test/comments',
        'https://example.test/comments/42'
    ])
})

test('stored-XSS dispatch does not change generic upload confirmation tiers', async () => {
    const { engine, browserUrls } = makeEngine()
    const uploadTask = {
        moduleId: 'file_upload_advanced',
        module: { id: 'file_upload_advanced', runtime: { mode: 'standard' } },
        attack: {
            id: 'file_upload_html',
            action: {
                files: [{ filename: 'proof.html', content: '<p>PTK_UPLOAD_TEST</p>' }]
            },
            runtime: {
                confirmation: {
                    tracking: {
                        enabled: true,
                        mode: 'followup_get',
                        marker: 'PTK_UPLOAD_TEST',
                        confidence: 91
                    }
                }
            },
            metadata: {
                extensions: {
                    fileUpload: { confirmationTier: 'retrieved' }
                }
            }
        }
    }
    const uploadExecution = storedExecution('accepted PTK_UPLOAD_TEST')
    uploadExecution.request.url = 'https://example.test/upload'
    uploadExecution.request.ui_url = 'https://example.test/upload'

    const result = await engine._runTracking(uploadTask, uploadExecution, {
        original: { request: { url: 'https://example.test/upload', method: 'POST' } }
    })

    assert.equal(result?.success, true)
    assert.equal(result?.trackingTier, 'retrieved')
    assert.equal(result?.executed, false)
    assert.deepEqual(browserUrls, [])
})

test('shared reflected XSS still skips response-only tracking execution claims', async () => {
    const { engine, browserUrls, events } = makeEngine()
    const reflectedTask = {
        moduleId: 'xss',
        module: { id: 'xss', runtime: { mode: 'standard' } },
        attack: {
            id: 'xss_1',
            action: { params: [{ value: '<script>alert(987101)</script>' }] },
            runtime: {
                confirmation: {
                    tracking: {
                        enabled: true,
                        mode: 'followup_get',
                        marker: '<script>alert(987101)</script>',
                        confidence: 90
                    }
                }
            }
        }
    }
    const result = await engine._runTracking(
        reflectedTask,
        storedExecution('<script>alert(987101)</script>'),
        { original: { request: { url: 'https://example.test/search', method: 'GET' } } }
    )

    assert.equal(result, null)
    assert.deepEqual(browserUrls, [])
    assert.equal(
        events.some((event) => event.reason === 'reflected_xss_requires_validation_or_browser_execution'),
        true
    )
})

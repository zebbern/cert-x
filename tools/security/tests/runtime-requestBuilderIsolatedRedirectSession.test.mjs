// Imported PTK v10 regression; paths adapted to the owned cert-x subsystem.
import assert from 'node:assert/strict'
import test from 'node:test'

import {
    IsolatedRedirectCookieJar,
    isRedirectStatus,
    redirectRequestTransition
} from '../../../security/ptk/background/requestBuilder/isolatedRedirectSession.js'

test('isolated redirect jar carries only explicitly seeded cookies on the initial origin', () => {
    const jar = new IsolatedRedirectCookieJar()
    jar.seedRequestCookieHeader('http://example.test/login', 'session=raw; feature=one')

    assert.equal(jar.cookieHeaderFor('http://example.test/next'), 'session=raw; feature=one')
    assert.equal(jar.cookieHeaderFor('https://example.test/next'), '')
    assert.equal(jar.cookieHeaderFor('http://other.test/next'), '')
})

test('isolated redirect jar accepts bounded exact-host response cookies with path and Secure enforcement', () => {
    const jar = new IsolatedRedirectCookieJar()
    const now = Date.UTC(2026, 7, 9)
    jar.absorbResponseHeaders('https://example.test/account/login', [
        { name: 'Set-Cookie', value: 'root=one; Path=/; HttpOnly' },
        { name: 'set-cookie', value: 'account=two; Path=/account; Secure' },
        { name: 'Set-Cookie', value: 'rejected=three; Domain=.test; Path=/' }
    ], now)

    assert.equal(
        jar.cookieHeaderFor('https://example.test/account/view', now),
        'account=two; root=one'
    )
    assert.equal(jar.cookieHeaderFor('http://example.test/account/view', now), 'root=one')
    assert.equal(jar.cookieHeaderFor('https://example.test/public', now), 'root=one')
    assert.equal(jar.cookieHeaderFor('https://other.test/account/view', now), '')
})

test('isolated redirect jar applies default paths, replacement, expiry, and resource bounds', () => {
    const now = Date.UTC(2026, 7, 9)
    const jar = new IsolatedRedirectCookieJar({ maxCookies: 2 })
    jar.absorbResponseHeaders('http://example.test/a/login', [
        { name: 'Set-Cookie', value: 'first=one' },
        { name: 'Set-Cookie', value: 'second=two; Path=/' },
        { name: 'Set-Cookie', value: 'third=three; Path=/' }
    ], now)

    assert.equal(jar.cookieHeaderFor('http://example.test/a/next', now), 'second=two; third=three')
    jar.absorbResponseHeaders('http://example.test/a/login', [
        { name: 'Set-Cookie', value: 'second=updated; Path=/' },
        { name: 'Set-Cookie', value: 'third=deleted; Path=/; Max-Age=0' }
    ], now)
    assert.equal(jar.cookieHeaderFor('http://example.test/a/next', now), 'second=updated')
})

test('redirect transition follows Fetch method rewriting without changing 307 or 308 bodies', () => {
    assert.equal(isRedirectStatus(302), true)
    assert.equal(isRedirectStatus(304), false)
    assert.deepEqual(
        redirectRequestTransition(302, 'POST', 'a=1'),
        { method: 'GET', body: null, bodyWasDropped: true }
    )
    assert.deepEqual(
        redirectRequestTransition(303, 'PATCH', '{"a":1}'),
        { method: 'GET', body: null, bodyWasDropped: true }
    )
    assert.deepEqual(
        redirectRequestTransition(307, 'POST', 'a=1'),
        { method: 'POST', body: 'a=1', bodyWasDropped: false }
    )
    assert.deepEqual(
        redirectRequestTransition(308, 'PUT', 'a=1'),
        { method: 'PUT', body: 'a=1', bodyWasDropped: false }
    )
})

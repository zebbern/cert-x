import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { scopeAllows, scopeWithin, validateScope } from '../../../security/config.mjs';

const require = createRequire(import.meta.url);
const { inScope } = require('../../host/security/oast.cjs');
const { checkScope, validateHttp1 } = require('../../host/security/raw-wire.cjs');

test('browser and native scope admission agree on exact origins, host ports, schemes, subdomains and exclusions', () => {
  const scopes = [
    { origins: ['https://app.test:8443'], excludePaths: ['/private'] },
    { origins: ['https://app.test:8443'], excludePaths: ['/private'], matchMode: 'host' },
    { origins: ['https://app.test:8443'], excludePaths: ['/private'], matchMode: 'host', includeSubdomains: true },
  ];
  const targets = ['https://app.test:8443/public', 'http://app.test:8080/public', 'https://api.app.test/public', 'https://sibling.test/public', 'https://badapp.test/public', 'http://app.test/private/item', 'https://api.app.test/%70rivate/item', 'https://api.app.test//private/item'];
  for (const scope of scopes) for (const target of targets) assert.equal(inScope(target, scope), scopeAllows(target, scope), `${scope.matchMode || 'origin'} ${target}`);
  assert.deepEqual(scopes.map(scope => scopeAllows('http://app.test:8080/public', scope)), [false, true, true]);
  assert.deepEqual(scopes.map(scope => scopeAllows('https://api.app.test/public', scope)), [false, false, true]);
  assert.equal(scopeAllows('https://badapp.test/public', scopes[2]), false);
  assert.equal(scopeAllows('https://api.app.test/%70rivate/item', scopes[2]), false);
  assert.equal(checkScope('wss://api.app.test:9443/socket', { scope: scopes[2] }).hostname, 'api.app.test');
  assert.throws(() => checkScope('ws://badapp.test/socket', { scope: scopes[2] }), /badapp.test.*Workspace settings/);
  const target = checkScope('http://app.test:8080/', { scope: scopes[1] });
  assert.equal(validateHttp1(Buffer.from('GET /public HTTP/1.1\r\nHost: app.test:9090\r\n\r\n'), target, { scope: scopes[1] })[0].url, 'http://app.test:9090/public');
  assert.throws(() => validateHttp1(Buffer.from('GET /public HTTP/1.1\r\nHost: badapp.test:9090\r\n\r\n'), target, { scope: scopes[1] }), /badapp.test.*Workspace settings/);
  assert.equal(scopeAllows('http://api.127.0.0.1:8080/', { origins: ['https://127.0.0.1'], excludePaths: [], matchMode: 'host', includeSubdomains: true }), false);
});

test('run scope can narrow but cannot expand a configured workspace scope', () => {
  const exact = validateScope({ origins: ['https://app.test:8443'], excludePaths: [] });
  const host = validateScope({ origins: ['https://app.test:8443'], excludePaths: [], matchMode: 'host' });
  const subdomains = validateScope({ origins: ['https://app.test:8443'], excludePaths: [], matchMode: 'host', includeSubdomains: true });
  assert.equal(scopeWithin(exact, host), true);
  assert.equal(scopeWithin(host, exact), false);
  assert.equal(scopeWithin(subdomains, host), false);
  assert.equal(scopeWithin(host, subdomains), true);
  assert.equal(scopeWithin(validateScope({ origins: ['http://api.app.test:8080'], excludePaths: [] }), subdomains), true);
  assert.equal(scopeWithin(validateScope({ origins: ['http://badapp.test'], excludePaths: [] }), subdomains), false);
});

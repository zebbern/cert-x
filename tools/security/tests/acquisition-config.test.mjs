import test from 'node:test';
import assert from 'node:assert/strict';
import { ACQUISITION_DEFAULTS, ACQUISITION_MAXIMA, cleanSettings, resolveConfig, validateOptions, validateLimits } from '../../../security/config.mjs';

test('acquisition defaults preserve old settings and merge individual workspace/run fields', () => {
  assert.deepEqual(resolveConfig().acquisition, ACQUISITION_DEFAULTS);
  const settings = { version: 1, defaults: { acquisition: { maxScripts: 240, drainTimeoutMs: 7000 } }, workspaces: { one: { defaults: { acquisition: { maxResourceBytes: 1024 } } } } };
  assert.deepEqual(resolveConfig(settings, 'one', { acquisition: { drainTimeoutMs: 9000 } }).acquisition,
    { ...ACQUISITION_DEFAULTS, maxScripts: 240, maxResourceBytes: 1024, drainTimeoutMs: 9000 });
  assert.equal(resolveConfig(settings, 'two').acquisition.maxResourceBytes, ACQUISITION_DEFAULTS.maxResourceBytes);
  assert.equal(resolveConfig(settings, 'one', { preset: 'ptk-defaults' }).acquisition.maxScripts, 240);
  assert.deepEqual(cleanSettings(JSON.parse(JSON.stringify(settings))), cleanSettings(settings));
});

test('explicit acquisition ceilings intersect and cannot be raised by run preferences', () => {
  const settings = { defaults: { acquisition: { maxScripts: 600, maxResourceBytes: 4096 } }, limits: { acquisition: { maxScripts: 400, maxTotalBytes: 8192 } }, workspaces: { one: { limits: { acquisition: { maxScripts: 200, maxTotalBytes: null, maxResourceBytes: 2048 } } } } };
  const config = resolveConfig(settings, 'one');
  assert.equal(config.acquisition.maxScripts, 200); assert.equal(config.acquisition.maxResourceBytes, 2048); assert.equal(config.acquisition.maxTotalBytes, 8192);
  assert.deepEqual(config.limits.acquisition, { maxResourceBytes: 2048, maxTotalBytes: 8192, maxScripts: 200 });
  assert.throws(() => resolveConfig(settings, 'one', { acquisition: { maxScripts: 201 } }), /explicit user limit/);
  assert.throws(() => resolveConfig(settings, 'one', { acquisition: { maxTotalBytes: 8193 } }), /explicit user limit/);
  assert.equal(resolveConfig(settings, 'one', { acquisition: { maxScripts: 100 } }).acquisition.maxScripts, 100);
  assert.equal(resolveConfig(settings, 'two').acquisition.maxScripts, 400);
});

test('acquisition validates exact fields and finite platform bounds before persistence', () => {
  assert.deepEqual(validateOptions({ acquisition: ACQUISITION_MAXIMA }).acquisition, ACQUISITION_MAXIMA);
  for (const key of Object.keys(ACQUISITION_DEFAULTS)) {
    for (const value of [0, -1, 1.5, '128', NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, ACQUISITION_MAXIMA[key] + 1, null]) {
      assert.throws(() => validateOptions({ acquisition: { [key]: value } }), /integer/);
    }
    assert.deepEqual(validateLimits({ acquisition: { [key]: null } }), { acquisition: { [key]: null } });
  }
  assert.throws(() => validateOptions({ acquisition: [] }), /object/);
  assert.throws(() => validateOptions({ acquisition: { typo: 1 } }), /Unknown acquisition/);
  assert.throws(() => validateLimits({ acquisition: { typo: 1 } }), /Unknown acquisition/);
  assert.throws(() => validateOptions(JSON.parse('{"acquisition":{"__proto__":1}}')), /Unsafe/);
});

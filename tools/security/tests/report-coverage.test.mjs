import test from 'node:test';
import assert from 'node:assert/strict';
import { runCoverageLines, runCoverageMarkdown } from '../../../security/ptk/browser/assets/js/report/runCoverage.js';

test('report coverage retains incomplete outcome, recovery and resolved acquisition settings', () => {
    const run = { runId: 'run-one', state: 'incomplete', config: { acquisition: { maxResourceBytes: 1024, maxTotalBytes: 4096, maxScripts: 8, drainTimeoutMs: 2500 } }, coverage: { dast: { phase: 'no_active_probes', probeDispatches: 0, baselineDispatches: 1 }, scaBodies: { analyzed: 2 }, scaSources: { analyzed: 2 }, actionableGaps: [{ engine: 'SCA', summary: 'Capture timed out.', recovery: { instruction: 'Repeat only the affected workflow.' }, examples: [{ reason: 'capture_drain_timeout', url: 'https://example.test/body.js' }] }] } };
    const value = runCoverageLines(run).join('\n');
    assert.match(value, /State: incomplete/); assert.match(value, /Probes dispatched: 0/);
    assert.match(value, /counts may overlap/); assert.match(value, /Capture timed out/); assert.match(value, /Repeat only/);
    assert.match(value, /capture_drain_timeout/); assert.match(value, /resource bytes 1024/); assert.match(value, /drain milliseconds 2500/);
});

test('Markdown coverage escapes target strings and preserves no-metadata compatibility', () => {
    assert.equal(runCoverageMarkdown(), '');
    const value = runCoverageMarkdown({ runId: '<img src=x>', state: 'unknown', coverage: { actionableGaps: [{ summary: '[click](https://evil.test)\n# fake heading', examples: [{ reason: '`code`' }] }] } });
    assert.ok(!value.includes('<img')); assert.ok(!value.includes('\n# fake')); assert.match(value, /\\\[click\\\]/); assert.match(value, /\\`code\\`/);
    assert.match(runCoverageMarkdown({ state: 'completed', coverage: {} }), /not proof of complete application coverage/);
});

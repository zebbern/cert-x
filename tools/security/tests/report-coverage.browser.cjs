// Actual offscreen Markdown and both PDF renderers, including parsed PDF text.
const assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path'), os = require('node:os'), cp = require('node:child_process');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const root = path.resolve(__dirname, '../../..'), temp = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-x-report-coverage-'));
let browser;
async function main() {
    browser = await chromium.launchPersistentContext(path.join(temp, 'profile'), { headless: true, executablePath: require('../../chromium-path.cjs'), args: ['--disable-extensions-except=' + root, '--load-extension=' + root] });
    const worker = browser.serviceWorkers()[0] || await browser.waitForEvent('serviceworker');
    await worker.evaluate(async () => { await certXSecurity.ready; await ptk_app.offscreenRuntimeManager.ensureDocument(); });
    const run = { runId: 'coverage-fixture-owned-run', state: 'incomplete', config: { acquisition: { maxResourceBytes: 1024, maxTotalBytes: 8192, maxScripts: 20, drainTimeoutMs: 7500 } }, coverage: { dast: { phase: 'no_active_probes', probeDispatches: 0, baselineDispatches: 1 }, actionableGaps: [{ engine: 'SCA', summary: 'Capture did not finish before its stop deadline.', recovery: { instruction: 'Keep partial evidence and repeat only the affected workflow.' }, examples: [{ reason: 'capture_drain_timeout', url: 'https://fixture.test/pending.js' }] }] } };
    const data = { engine: 'SAST', scanId: 'native-fixture', host: 'fixture.test', findings: [{ id: 'fixture-finding', engine: 'SAST', moduleId: 'dom-xss', ruleId: 'dom-xss-taint', ruleName: 'Source to HTML sink', vulnId: 'dom_xss', severity: 'high', description: 'Native finding is preserved.', evidence: { sast: { codeSnippet: 'sink.innerHTML = location.hash;', source: { name: 'location.hash' }, sink: { name: 'innerHTML' } } } }] };
    const results = [];
    for (const [format, preset] of [['markdown', 'technical'], ['pdf', 'technical'], ['pdf', 'executive']]) {
        const result = await worker.evaluate(args => chrome.runtime.sendMessage({ channel: 'CERT_X_SECURITY_DOM', action: 'report', args }), { reports: [{ engine: 'SAST', data }], format, options: { preset }, meta: { host: 'fixture.test', generatedAt: '2026-10-22T00:00:00Z', run } });
        assert.equal(result.ok, true, JSON.stringify(result)); const artifact = result.artifact; assert.equal(artifact.findings, 1);
        let text = artifact.text, pages = null;
        if (format === 'pdf') {
            const file = path.join(temp, preset + '.pdf'); fs.writeFileSync(file, Buffer.from(artifact.bytes));
            const parsed = JSON.parse(cp.execFileSync(process.env.PYTHON_PATH || 'python', ['-c', 'import json,sys; from pypdf import PdfReader; r=PdfReader(sys.argv[1]); print(json.dumps({"pages":len(r.pages),"text":"\\n".join(p.extract_text() or "" for p in r.pages)}))', file], { encoding: 'utf8', windowsHide: true }));
            text = parsed.text; pages = parsed.pages; assert.equal(pages, artifact.pages);
            assert.match(text, new RegExp('Page 1/' + pages));
        }
        const normalized = text.replace(/\\(.)/g, '$1').replace(/\s+/g, ' ');
        for (const required of ['Coverage and remaining gaps', 'coverage-fixture-owned-run', 'State: incomplete', 'Probes dispatched: 0', 'Capture did not finish', 'Keep partial evidence', 'capture_drain_timeout', 'resource bytes 1024', 'Source to HTML sink']) assert.ok(normalized.includes(required), format + '/' + preset + ' missing ' + required);
        results.push({ format, preset, pages, coveragePresent: true, nativeFindingPreserved: true });
    }
    console.log(JSON.stringify({ checks: results }));
}
main().catch(error => { console.error(error); process.exitCode = 1; }).finally(async () => {
    await browser?.close();
    const absolute = path.resolve(temp); if (absolute.startsWith(path.resolve(os.tmpdir()) + path.sep) && path.basename(absolute).startsWith('cert-x-report-coverage-')) fs.rmSync(absolute, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

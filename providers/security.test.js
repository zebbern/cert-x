const test = require("node:test"), assert = require("node:assert/strict"), http = require("node:http"), fs = require("node:fs"), path = require("node:path"), os = require("node:os");
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || "C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core");

// Browser plugin not available. Exercise the actual UI module with the KI_SECURITY contract.
test("security settings preserve explicit limits, show lifecycle and evidence, and handle failures at 420/720px", async () => {
  const server = http.createServer((req, res) => {
    if (req.url.split('?')[0] === '/security/config.mjs') { res.setHeader('Content-Type', 'text/javascript'); return res.end(fs.readFileSync(path.join(__dirname, '../security/config.mjs'))); }
    const file = { "/security.js": "security.js", "/security.css": "security.css", "/providers.css": "providers.css" }[req.url.split("?")[0]];
    if (file) { res.setHeader("Content-Type", file.endsWith(".js") ? "text/javascript" : "text/css"); return res.end(fs.readFileSync(path.join(__dirname, file))); }
    res.setHeader("Content-Type", "text/html"); res.end('<!doctype html><html data-theme="dark"><head><title>Security testing</title><link rel="stylesheet" href="/providers.css"></head><body><main class="page"><section id="security-section"></section><section id="authz-section" hidden></section></main><script type="module">import {initSecurity} from "/security.js"; await initSecurity(); window.ready=true;</script></body></html>');
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || path.join(process.env.LOCALAPPDATA, "ms-playwright/chromium-1234/chrome-win64/chrome.exe"), headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 420, height: 950 } }), errors = [];
    page.on("pageerror", error => errors.push(error.message));
    await page.addInitScript(() => {
      const defaults = { preset: "thorough", scanStrategy: "COMPREHENSIVE", scanControlProfile: "wide", maxRequestsPerSecond: 5, concurrency: 3, planningConcurrency: 2, runCve: true, maxRequests: null, durationSeconds: null };
      window.securityMock = { calls: [], listeners: [], runs: [], failExport: true, failStart: false, integrations: { localAccessEnabled: true, oastConnectionId: null, browserBackend: 'extension', zapEnabled: false, connections: [{ id: 'callbacks-one', label: 'Callbacks' }] }, config: { ...defaults }, settings: { version: 1, defaults: { ...defaults }, limits: {}, workspaces: {} } };
      const saved = sessionStorage.getItem('security-settings-fixture'); if (saved) Object.assign(securityMock, JSON.parse(saved));
      securityMock.runtimeListeners = [];
      window.chrome = { storage: { onChanged: { addListener: fn => securityMock.listeners.push(fn), removeListener: fn => securityMock.listeners = securityMock.listeners.filter(item => item !== fn) } }, runtime: { id: 'fixture', onMessage: { addListener: fn => securityMock.runtimeListeners.push(fn), removeListener: fn => securityMock.runtimeListeners = securityMock.runtimeListeners.filter(item => item !== fn) }, sendMessage: async message => {
        securityMock.calls.push(message); if (message.type !== "KI_SECURITY") return { ok: false, error: "Unexpected message type" }; let result;
        if (message.op === "state") result = { workspaceId: "workspace-one", capabilities: { engines: ["DAST", "IAST", "SAST", "SCA"], unavailable: [{ name: "Raw HTTP transport", reason: "Not available in this browser" }] }, settings: securityMock.settings, config: securityMock.config, accounts: [{ accountId: "account-one", label: "Alice", role: "member" }], runs: securityMock.runs };
        else if (message.op === 'integrations') result = securityMock.integrations;
        else if (message.op === 'save_integrations') { Object.assign(securityMock.integrations, { oastConnectionId: message.oastConnectionId, zapEnabled: message.zapEnabled }); result = securityMock.integrations; }
        else if (message.op === 'local_status') result = securityMock.oldHost ? { ready: false, needsUpdate: true } : { ready: true, components: { node: { ready: true }, chromium: { ready: true }, jre: { ready: true }, zap: { ready: true }, webhook: { ready: true } } };
        else if (message.op === 'local_setup') return new Promise(resolve => { securityMock.setupReply = resolve; for (const fn of securityMock.runtimeListeners) fn({type:'KI_SECURITY_SETUP_PROGRESS',progress:{type:'setup_progress',phase:'download',bytes:25,total:100}}, {id:'fixture'}); });
        else if (message.op === 'local_cancel_setup') { securityMock.setupReply({ok:false,error:'Setup cancelled'}); result = {cancelled:true}; }
        else if (message.op === 'local_restart') result = {restarted:true,runtime:{ready:true,components:{}}};
        else if (message.op === 'execute') {
          const args = message.arguments;
          if (message.capability === 'candidate' && args.action === 'list') result = { candidates: [{ id: 'candidate-one', title: 'Ownership candidate', severity: 'medium', routeKey: '/account' }], snapshotId: 'snapshot-one', sourceRunId: 'run-one', nextOffset: null, coverage: { tested: 1, inconclusive: 1 }, runId: 'operation-list' };
          else if (message.capability === 'candidate' && args.action === 'reproduce') result = { jobId: 'job-one', runId: 'reproduction-one', sourceRunId: 'run-one', persistent: true, state: 'running' };
          else if (message.capability === 'candidate' && args.action === 'status') result = { jobId: 'job-one', runId: 'reproduction-one', state: 'completed' };
          else if (message.capability === 'browser') result = { sessionId: 'browser-one', runId: 'browser-operation', persistent: true, state: 'open' };
          else if (message.capability === 'evidencePackage') result = { evidencePackage: { id: 'package-one' }, reportDraft: { title: 'Draft candidate report' }, runId: 'package-operation' };
          else return { ok: false, error: 'Unexpected native operation' };
        }
        else if (message.op === "tabs") result = [{ tabId: 3, title: "Other", origin: "https://other.example", active: true }, { tabId: 7, title: "Application", url: 'https://target.example/account', origin: "https://target.example", working: true }];
        else if (message.op === "configure") {
          const value = message.scope === "workspace" ? securityMock.settings.workspaces[message.workspaceId] ||= {} : securityMock.settings;
          if (message.defaults) { value.defaults = message.defaults; securityMock.config = message.defaults; }
          if (message.limits) value.limits = message.limits;
          sessionStorage.setItem('security-settings-fixture', JSON.stringify({ settings: securityMock.settings, config: securityMock.config }));
          result = securityMock.settings;
        } else if (message.op === "start") {
          if (securityMock.failStart) return { ok: true, result: { success: false, error: "Account identity changed." } };
          result = { runId: "run-one", owner: message.session, workspaceId: "workspace-one", tabId: message.tabId, engines: message.engines, config: message.options, title: "Application", origin: "https://target.example", state: "running", summary: { findingsCount: 1 }, coverage: { warnings: ["One resource was unavailable."] } }; securityMock.runs = [result];
        } else if (message.op === "stop") { securityMock.runs[0].state = "stopping"; result = securityMock.runs[0]; }
        else if (message.op === "status") { if (securityMock.runs[0].state === "stopping" && securityMock.releaseStop) securityMock.runs[0].state = "completed"; result = securityMock.runs[0]; }
        else if (message.op === "findings") result = { findings: [{ id: "finding-" + message.offset, title: message.offset ? "Second finding" : '<img src=x onerror="window.findingExecuted=true">', engine: "DAST", severity: "high", classification: message.offset ? "execution_observed" : "observation", executionObserved: !!message.offset, evidenceId: "evidence-one", evidence: { reflection: true } }], nextOffset: message.offset ? null : 1, warnings: ["Partial response capture."] };
        else if (message.op === "evidence") result = { request: { method: "GET", url: "https://target.example/search?q=marker" }, response: { status: 200, body: "marker" } };
        else if (message.op === "export") { if (securityMock.failExport) return { ok: false, error: "Export could not be saved." }; result = { reports: [{ downloadId: 5, name: "report.json", size: 125 }] }; }
        else return { ok: false, error: "Unexpected operation: " + message.op };
        return { ok: true, result: JSON.parse(JSON.stringify(result)) };
      } } };
    });
    await page.goto("http://127.0.0.1:" + server.address().port + "/?session=chat-one"); await page.waitForFunction(() => window.ready);
    assert.equal(await page.title(), "Security testing"); await page.getByRole("heading", { name: "Security testing", exact: true }).waitFor();
    assert.equal(await page.getByLabel("Target page", { exact: true }).inputValue(), "7");
    assert.equal(await page.getByLabel("Testing preset", { exact: true }).inputValue(), "thorough");
    assert.equal(await page.getByText("Scan options", { exact: true }).evaluate(node => node.parentElement.open), false);
    assert.match(await page.getByRole("link", { name: "Third-party notices", exact: true }).getAttribute("href"), /security\/third-party-notices\.json$/);
    assert.match(await page.getByRole("link", { name: "PTK license", exact: true }).getAttribute("href"), /security\/ptk\/LICENSE-PTK\.txt$/);
    assert.match(await page.getByRole('link', { name: 'Local runtime notices', exact: true }).getAttribute('href'), /tools\/security\/runtime\/THIRD_PARTY_NOTICES\.md$/);
    assert.equal(await page.getByLabel('Reproduction browser backend', { exact: true }).count(), 0);
    assert.equal(await page.getByText(/install|pairing|companion|Check connection/i).count(), 0);
    assert.equal(await page.getByText('Local runtime & connections', { exact: true }).evaluate(node => node.parentElement.open), false);
    await page.getByText('Local runtime & connections', { exact: true }).click();
    await page.getByRole('button', { name: 'Check runtime', exact: true }).click(); await page.getByText(/Runtime connected · Browser: ready/).waitFor();
    await page.getByRole('button', { name: 'Set up browser', exact: true }).click(); await page.getByText('Downloading runtime · 25%', {exact:true}).waitFor();
    await page.getByRole('button', { name: 'Cancel setup', exact: true }).click(); await page.getByText('Setup cancelled', {exact:true}).waitFor(); assert.equal(await page.getByRole('button', { name: 'Cancel setup', exact: true }).isVisible(), false);
    await page.getByText('Stops active local testing.', {exact:true}).waitFor();await page.getByRole('button',{name:'Restart local runtime',exact:true}).click();await page.getByText('Local runtime restarted. Previous local operations were stopped.',{exact:true}).waitFor();
    await page.evaluate(() => securityMock.oldHost = true); await page.getByRole('button', { name: 'Check runtime', exact: true }).click(); await page.getByText('Update local runtime from Local computer settings.', { exact: true }).waitFor();
    await page.getByLabel('Callback connection', { exact: true }).selectOption('callbacks-one'); await page.getByRole('switch', { name: 'Include ZAP in Thorough' }).focus(); await page.keyboard.press('Space');
    await page.getByRole('button', { name: 'Save connections', exact: true }).click(); await page.getByText('Testing connections saved.', { exact: true }).waitFor();
    const connections = await page.evaluate(() => securityMock.calls.find(call => call.op === 'save_integrations')); assert.equal(connections.oastConnectionId, 'callbacks-one'); assert.equal(connections.zapEnabled, true); assert.equal(Object.hasOwn(connections, 'browserBackend'), false);
    await page.evaluate(() => { securityMock.integrations.localAccessEnabled = false; for (const fn of securityMock.listeners) fn({ki_native_settings:{}}, 'local'); });
    await page.getByText('Local computer access is off.', { exact: true }).waitFor(); assert.equal(await page.getByRole('button', { name: 'Set up browser', exact: true }).isDisabled(), true);
    await page.getByText('Local runtime & connections', { exact: true }).click();
    await page.screenshot({ path: path.join(os.tmpdir(), "cert-x-security-420-compact.png"), fullPage: true });
    await page.getByText("Scan options", { exact: true }).click();
    const acquisitionSummary = page.getByText('Acquisition limits', { exact: true });
    assert.equal(await acquisitionSummary.evaluate(node => node.parentElement.open), false);
    await acquisitionSummary.focus(); await page.keyboard.press('Enter');
    assert.equal(await acquisitionSummary.evaluate(node => node.parentElement.open), true);
    assert.equal(await page.getByLabel('Acquisition: Per resource (MiB)', { exact: true }).inputValue(), '8');
    await page.getByLabel('Acquisition: Loaded scripts', { exact: true }).fill('256');
    await page.getByLabel('Acquisition: Finish pending reads (seconds)', { exact: true }).fill('7.5');
    assert.equal(await page.getByRole("switch", { name: "Active testing (DAST)" }).getAttribute("aria-checked"), "true");
    assert.equal(await page.locator('input[type="checkbox"]').count(), 0);
    await page.getByLabel("Run request budget", { exact: true }).fill("2500"); await page.getByLabel("Run duration in seconds", { exact: true }).fill("3600");
    await page.getByLabel("Concurrent requests", { exact: true }).fill("6");
    await page.getByRole("button", { name: "Save for workspace", exact: true }).click();
    await page.getByText("Workspace defaults saved.", { exact: true }).waitFor();
    const configuration = await page.evaluate(() => securityMock.calls.find(call => call.op === "configure"));
    assert.equal(configuration.scope, "workspace"); assert.equal(configuration.workspaceId, "workspace-one"); assert.equal(configuration.defaults.maxRequests, 2500); assert.equal(configuration.defaults.durationSeconds, 3600); assert.equal(configuration.defaults.concurrency, 6); assert.equal(configuration.limits, undefined);
    assert.deepEqual(configuration.defaults.acquisition, { maxResourceBytes: 8388608, maxTotalBytes: 33554432, maxScripts: 256, drainTimeoutMs: 7500 });
    await page.getByText("Your limits", { exact: true }).click();
    await page.getByLabel("Maximum allowed run requests", { exact: true }).fill("3000");
    await page.getByText('Acquisition ceilings', { exact: true }).click();
    await page.getByLabel('Maximum acquisition: Loaded scripts', { exact: true }).fill('512');
    await page.getByRole("button", { name: "Save limits", exact: true }).click(); await page.getByText("Limits saved.", { exact: true }).waitFor();
    const limits = await page.evaluate(() => securityMock.calls.filter(call => call.op === "configure").at(-1));
    assert.equal(limits.defaults, undefined); assert.deepEqual(limits.limits, { maxRequestsPerSecond: null, concurrency: null, maxRequests: 3000, durationSeconds: null, acquisition: { maxResourceBytes: null, maxTotalBytes: null, maxScripts: 512, drainTimeoutMs: null } });
    await page.reload(); await page.waitForFunction(() => window.ready);
    assert.equal(await page.getByLabel('Acquisition: Loaded scripts', { exact: true }).inputValue(), '256');
    assert.equal(await page.getByLabel('Acquisition: Finish pending reads (seconds)', { exact: true }).inputValue(), '7.5');
    assert.equal(await page.getByLabel('Maximum acquisition: Loaded scripts', { exact: true }).inputValue(), '512');
    assert.equal(await page.getByText('Acquisition limits', { exact: true }).evaluate(node => node.parentElement.open), false);
    await page.getByLabel("Account", { exact: true }).selectOption("account-one");
    await page.getByRole("button", { name: "Start scan", exact: true }).click(); await page.getByRole("button", { name: "Stop", exact: true }).waitFor();
    const started = await page.evaluate(() => securityMock.calls.find(call => call.op === "start")); assert.equal(started.tabId, 7); assert.equal(started.accountId, "account-one"); assert.deepEqual(started.engines, ["DAST", "IAST", "SAST", "SCA"]); assert.equal(started.options.maxRequests, 2500);
    assert.equal(started.options.acquisition.maxScripts, 256); assert.equal(started.options.acquisition.drainTimeoutMs, 7500);
    await page.getByRole("button", { name: "Findings", exact: true }).click();
    assert.equal(await page.locator(".security-finding img").count(), 0); assert.equal(await page.evaluate(() => window.findingExecuted), undefined);
    await page.getByText("DAST · high · Observation · Execution not observed", { exact: true }).waitFor();
    await page.getByRole("button", { name: "View full evidence", exact: true }).click(); await page.getByText("Full evidence", { exact: true }).waitFor();
    await page.getByRole("button", { name: "Load more", exact: true }).click(); await page.getByRole("heading", { name: "Second finding", exact: true }).waitFor(); assert.equal(await page.getByRole("button", { name: "Load more", exact: true }).isVisible(), false);
    await page.getByText("DAST · high · Execution observed", { exact: true }).waitFor();
    await page.getByRole('button', { name: 'Investigate', exact: true }).click(); await page.getByRole('heading', { name: 'Ownership candidate', exact: true }).waitFor();
    await page.getByRole('button', { name: 'Save evidence package', exact: true }).click(); await page.getByText('Evidence package', { exact: true }).waitFor();
    const evidenceCall = await page.evaluate(() => securityMock.calls.filter(call => call.capability === 'evidencePackage').at(-1)); assert.equal(evidenceCall.arguments.runId, 'run-one'); assert.equal(evidenceCall.arguments.candidateId, 'candidate-one'); assert.equal(evidenceCall.arguments.snapshotId, 'snapshot-one');
    await page.getByText('Reproduce in browser', { exact: true }).click(); await page.getByRole('button', { name: 'Create isolated browser', exact: true }).click(); assert.equal(await page.getByLabel('Browser session', { exact: true }).inputValue(), 'browser-one');
    await page.getByRole('button', { name: 'Reproduce candidate', exact: true }).click(); await page.getByRole('button', { name: 'Check reproduction', exact: true }).click();
    const reproductionStatus = await page.evaluate(() => securityMock.calls.filter(call => call.capability === 'candidate' && call.arguments.action === 'status').at(-1)); assert.equal(reproductionStatus.arguments.runId, 'run-one'); assert.equal(reproductionStatus.arguments.executionRunId, 'reproduction-one'); assert.equal(reproductionStatus.arguments.jobId, 'job-one');
    await page.getByRole("button", { name: "Export report", exact: true }).click(); await page.getByText("Export could not be saved.", { exact: true }).waitFor();
    assert.equal(await page.getByText("Saved 1 report to Outputs.", { exact: true }).count(), 0);
    await page.evaluate(() => securityMock.failExport = false); await page.getByRole("button", { name: "Export report", exact: true }).click(); await page.getByText("Saved 1 report to Outputs.", { exact: true }).waitFor();
    assert.equal((await page.evaluate(() => securityMock.calls.filter(call => call.op === "export").at(-1))).format, "json");
    await page.getByLabel("Report format", { exact: true }).selectOption("pdf"); await page.getByLabel("PDF report style", { exact: true }).selectOption("executive");
    await page.getByRole("button", { name: "Export report", exact: true }).click();
    const pdf = await page.evaluate(() => securityMock.calls.filter(call => call.op === "export").at(-1)); assert.equal(pdf.format, "pdf"); assert.deepEqual(pdf.options, { preset: "executive" });
    await page.getByLabel("Report format", { exact: true }).selectOption("markdown"); assert.equal(await page.getByLabel("PDF report style", { exact: true }).isVisible(), false);
    await page.getByRole("button", { name: "Export report", exact: true }).click(); assert.equal((await page.evaluate(() => securityMock.calls.filter(call => call.op === "export").at(-1))).format, "markdown");
    await page.getByText("Configuration and coverage", { exact: true }).click(); await page.getByRole("button", { name: "Stop", exact: true }).focus();
    await page.evaluate(() => { securityMock.runs[0].summary.findingsCount = 2; for (const listener of securityMock.listeners) listener({ ki_security_runs: {} }, "local"); });
    await page.getByText(/2 findings/).waitFor(); assert.equal(await page.evaluate(() => document.activeElement.textContent), "Stop"); assert.equal(await page.getByText("Configuration and coverage", { exact: true }).evaluate(node => node.parentElement.open), true);
    await page.getByRole("button", { name: "Stop", exact: true }).click(); await page.getByRole("button", { name: "Stopping…", exact: true }).waitFor();
    // The run stays stopping until released, so the page's 3 s status poll cannot clear it before the check above.
    await page.evaluate(() => securityMock.releaseStop = true); await page.getByText(/Completed ·/).waitFor();
    await page.evaluate(() => securityMock.failStart = true); await page.getByRole("button", { name: "Start scan", exact: true }).click(); await page.getByText("Account identity changed.", { exact: true }).waitFor();
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    await page.getByText('Scan options', { exact: true }).click(); await page.getByText('Acquisition limits', { exact: true }).click();
    for (const width of [420, 720]) for (const theme of ['dark', 'light']) {
      await page.setViewportSize({ width, height: 950 }); await page.evaluate(theme => document.documentElement.dataset.theme = theme, theme);
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
      await page.screenshot({ path: path.join(os.tmpdir(), `cert-x-security-${width}-${theme}.png`), fullPage: true });
    }
    assert.deepEqual(errors, []);
  } finally { await browser.close(); await new Promise(resolve => server.close(resolve)); }
});

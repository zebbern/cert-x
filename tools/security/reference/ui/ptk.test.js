const test = require("node:test"), assert = require("node:assert/strict"), http = require("node:http"), fs = require("node:fs"), path = require("node:path"), os = require("node:os");
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || "C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core");
test("PTK settings handle lifecycle, application failures and untrusted findings without claiming unverified success", async () => {
  const server = http.createServer((req, res) => {
    const file = { "/ptk.js": "ptk.js", "/ptk.css": "ptk.css", "/providers.css": "providers.css" }[req.url.split("?")[0]];
    if (file) { res.setHeader("Content-Type", file.endsWith("js") ? "text/javascript" : "text/css"); return res.end(fs.readFileSync(path.join(__dirname, file))); }
    res.setHeader("Content-Type", "text/html"); res.end('<!doctype html><html data-theme="dark"><head><link rel="stylesheet" href="/providers.css"></head><body><main class="page"><section id="ptk-section"></section></main><script type="module">import {initPtk} from "/ptk.js"; await initPtk(); window.ready=true;</script></body></html>');
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || path.join(process.env.LOCALAPPDATA, "ms-playwright/chromium-1234/chrome-win64/chrome.exe"), headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 420, height: 950 } }), errors = [];
    page.on("pageerror", error => errors.push(error.message));
    await page.addInitScript(() => {
      window.ptkMock = { calls: [], scans: [], listeners: [], failExport: true, ready: false, observationState: "starting", reloads: 0, tabUrl: "https://target.example/app" };
      window.chrome = { tabs: { get: async () => ({ url: ptkMock.tabUrl }), reload: async () => { ptkMock.reloads++; } }, storage: { onChanged: { addListener: fn => ptkMock.listeners.push(fn), removeListener: fn => ptkMock.listeners = ptkMock.listeners.filter(value => value !== fn) } }, runtime: { sendMessage: async message => {
        ptkMock.calls.push(message); let result;
        if (message.op === "tabs") result = [{ tabId: 3, title: "Unrelated page", origin: "https://other.example", url: "https://other.example/", active: true }, { tabId: 7, title: "Application", origin: "https://target.example", url: "https://target.example/app", working: true }];
        else if (message.op === "check") result = { tabId: 7, origin: "https://target.example", version: "10.0.0", ready: ptkMock.ready, automationEnabled: ptkMock.ready, blockers: ptkMock.ready ? [] : ["automation_disabled"] };
        else if (message.op === "state") result = { scans: ptkMock.scans };
        else if (message.op === "start") {
          ptkMock.ready = true;
          result = { scanId: "scan-1", owner: message.session, tabId: 7, origin: "https://target.example", title: "Application", sessionId: "ptk-1", engines: message.engines, mode: message.engines.includes("IAST") ? "observe" : "analyze", observationState: message.engines.includes("IAST") ? "starting" : undefined, startedAt: Date.now(), deadline: Date.now() + message.durationSeconds * 1000, state: "running", summary: { findingsCount: 1 }, warnings: ["One source could not be collected."] }; ptkMock.scans = [result];
        } else if (message.op === "stop") { ptkMock.scans[0].state = "stopping"; result = ptkMock.scans[0]; }
        else if (message.op === "status") { if (ptkMock.scans[0].state === "stopping") { ptkMock.scans[0].state = "completed"; if (ptkMock.scans[0].mode === "observe") ptkMock.scans[0].cleanup = { reloadRecommended: true, message: "Observation stopped. Reload the page when ready to reset instrumentation." }; } else if (ptkMock.scans[0].mode === "observe") { ptkMock.scans[0].observationState = ptkMock.observationState; ptkMock.scans[0].readiness = { agentReady: ptkMock.observationState === "observing", modulesLoaded: ptkMock.observationState === "observing" }; ptkMock.scans[0].coverage = { warnings: ptkMock.observationState === "degraded" ? ["Modules are not ready."] : [] }; } result = ptkMock.scans[0]; }
        else if (message.op === "extend") { const scan = ptkMock.scans[0]; scan.deadline = Math.min(scan.deadline + 300000, scan.startedAt + 1800000); result = scan; }
        else if (message.op === "findings") result = { scan: ptkMock.scans[0], findings: [{ id: "f1", title: '<img src=x onerror="window.findingExecuted=true">', engine: ptkMock.scans[0].mode === "observe" ? "IAST" : "SAST", confidence: "medium", severity: "high", evidence: { source: "location.hash", sink: "innerHTML" } }], nearbyActions: ptkMock.scans[0].mode === "observe" ? [{ id: "action-1", tool: "click", label: "Submit search", route: "https://target.example/search", startedAt: Date.now(), outcome: "completed" }] : [], truncated: true, warnings: ["Optional analysis snapshot is unavailable."], analysis: { summary: { coverage: "partial" }, warnings: ["Coverage is partial."] } };
        else if (message.op === "export") { if (ptkMock.failExport) return { ok: false, error: "Export chunk is missing." }; result = { reports: [{ downloadId: 5, name: "report.json.gz", size: 25 }], warnings: [] }; }
        else return { ok: false, error: "Unexpected operation" };
        return { ok: true, result: JSON.parse(JSON.stringify(result)) };
      } } };
    });
    await page.goto("http://127.0.0.1:" + server.address().port + "/?session=chat-one"); await page.waitForFunction(() => window.ready);
    await page.getByText("PTK is available · activation needed", { exact: true }).waitFor();
    assert.equal(await page.getByLabel("PTK tab", { exact: true }).inputValue(), "7", "The working tab must win over the active tab and list order");
    assert.equal(await page.evaluate(() => ptkMock.calls.find(call => call.op === "tabs").session), "chat-one");
    await page.getByRole("button", { name: "Analyze app", exact: true }).click();
    await page.getByRole("button", { name: "Stop", exact: true }).waitFor();
    await page.getByText("Ready · PTK 10.0.0", { exact: true }).waitFor();
    assert.equal(await page.getByText("PTK is available · activation needed", { exact: true }).count(), 0);
    const start = await page.evaluate(() => ptkMock.calls.find(call => call.op === "start"));
    assert.deepEqual(start, { type: "KI_PTK", op: "start", session: "chat-one", tabId: 7, expectedOrigin: "https://target.example", engines: ["SAST", "SCA"], durationSeconds: 60 });
    assert.equal(await page.getByRole("button", { name: "Export report", exact: true }).isDisabled(), true);
    await page.getByRole("button", { name: "Findings", exact: true }).click();
    await page.getByText("Scanner candidates · verify impact before reporting", { exact: true }).waitFor();
    assert.equal(await page.locator(".ptk-finding img").count(), 0); assert.equal(await page.evaluate(() => window.findingExecuted), undefined);
    await page.getByText("One source could not be collected.", { exact: true }).first().waitFor();
    await page.getByText("Preview shortened. Export the report for the retained findings.", { exact: true }).waitFor();
    await page.getByText("Optional analysis snapshot is unavailable.", { exact: true }).waitFor();
    await page.getByRole("button", { name: "Stop", exact: true }).click();
    await page.getByRole("button", { name: "Stopping…", exact: true }).waitFor();
    await page.locator(".ptk-scan .ptk-meta").filter({ hasText: "completed" }).waitFor();
    await page.getByRole("button", { name: "Export report", exact: true }).click();
    await page.getByText("Export chunk is missing.", { exact: true }).waitFor();
    assert.equal(await page.getByText("Saved 1 report to Outputs.", { exact: true }).count(), 0);
    await page.evaluate(() => ptkMock.failExport = false);
    await page.getByRole("button", { name: "Export report", exact: true }).click();
    await page.getByText("Saved 1 report to Outputs.", { exact: true }).waitFor();
    await page.getByRole("button", { name: "Observe while browsing", exact: true }).click();
    await page.getByText("IAST · Starting instrumentation · 1 candidate", { exact: true }).waitFor();
    assert.equal(await page.getByText("IAST · Observing · 1 candidate", { exact: true }).count(), 0);
    const observe = await page.evaluate(() => ptkMock.calls.filter(call => call.op === "start").at(-1));
    assert.deepEqual(observe.engines, ["IAST"]); assert.equal(observe.durationSeconds, 600);
    assert.equal(await page.getByRole("button", { name: "Observe while browsing", exact: true }).isDisabled(), true);
    await page.evaluate(() => ptkMock.observationState = "degraded");
    await page.getByText("IAST · Degraded coverage · 1 candidate", { exact: true }).waitFor();
    await page.getByText("Modules are not ready.", { exact: true }).waitFor();
    await page.evaluate(() => ptkMock.observationState = "observing");
    await page.getByText("IAST · Observing · 1 candidate", { exact: true }).waitFor();
    await page.getByText("Instrumentation and coverage", { exact: true }).click();
    await page.getByRole("button", { name: "Extend 5 minutes", exact: true }).focus();
    await page.evaluate(() => { ptkMock.scans[0].warnings.push("Coverage updated."); for (const listener of ptkMock.listeners) listener({ ki_ptk_scans: {} }, "local"); });
    await page.getByText("Coverage updated.", { exact: true }).waitFor();
    assert.equal(await page.evaluate(() => document.activeElement.textContent), "Extend 5 minutes", "Live updates preserve keyboard focus");
    assert.equal(await page.getByText("Instrumentation and coverage", { exact: true }).evaluate(summary => summary.parentElement.open), true);
    const deadlineBefore = await page.evaluate(() => ptkMock.scans[0].deadline);
    await page.getByRole("button", { name: "Extend 5 minutes", exact: true }).click();
    assert.equal(await page.evaluate(() => ptkMock.scans[0].deadline), deadlineBefore + 300000);
    await page.getByRole("button", { name: "Findings", exact: true }).click();
    await page.getByText("Nearby activity · timing only", { exact: true }).click();
    await page.getByText("Nearby actions provide context; timing does not establish the cause of a finding.", { exact: true }).waitFor();
    await page.getByText(/Submit search/).waitFor();
    await page.screenshot({ path: path.join(os.tmpdir(), "cert-x-iast-observing-420.png"), fullPage: true });
    await page.evaluate(() => { ptkMock.scans[0].deadline = ptkMock.scans[0].startedAt + 1800000; for (const listener of ptkMock.listeners) listener({ ki_ptk_scans: {} }, "local"); });
    await page.waitForFunction(() => [...document.querySelectorAll("button")].find(button => button.textContent === "Extend 5 minutes")?.disabled);
    await page.getByRole("button", { name: "Stop", exact: true }).click();
    await page.getByText("IAST · Completed · 1 candidate", { exact: true }).waitFor();
    assert.equal(await page.evaluate(() => ptkMock.reloads), 0, "Stopping must not automatically reload the page");
    await page.evaluate(() => ptkMock.tabUrl = "https://other.example/");
    await page.getByRole("button", { name: "Reload page", exact: true }).click();
    await page.getByText("The tab changed origin. Reload the intended page directly.", { exact: true }).waitFor();
    assert.equal(await page.evaluate(() => ptkMock.reloads), 0);
    await page.evaluate(() => ptkMock.tabUrl = "https://target.example/app");
    await page.getByRole("button", { name: "Reload page", exact: true }).click();
    assert.equal(await page.evaluate(() => ptkMock.reloads), 1);
    await page.getByRole("button", { name: "Export report", exact: true }).click();
    await page.getByText("Saved 1 report to Outputs.", { exact: true }).waitFor();
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    await page.setViewportSize({ width: 720, height: 950 }); assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    await page.screenshot({ path: path.join(os.tmpdir(), "cert-x-ptk-settings.png"), fullPage: true });
    await page.goto("http://127.0.0.1:" + server.address().port + "/"); await page.waitForFunction(() => window.ready);
    assert.equal(await page.getByRole("button", { name: "Analyze app", exact: true }).isDisabled(), true);
    assert.equal(await page.getByRole("button", { name: "Observe while browsing", exact: true }).isDisabled(), true);
    await page.getByText("Open a Bug bounty chat to analyze this page.", { exact: true }).waitFor();
    assert.deepEqual(errors, []);
  } finally { await browser.close(); await new Promise(resolve => server.close(resolve)); }
});

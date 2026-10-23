const test = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), os = require("node:os"), http = require("node:http");
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || "C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core");
test("DAST UI selects exact fields, freezes plans, respects replay consent and reports real batch outcomes", async () => {
  const server = http.createServer((req, res) => {
    const file = { "/dast.js": "dast.js", "/dast.css": "dast.css", "/providers.css": "providers.css" }[req.url.split("?")[0]];
    if (file) { res.setHeader("Content-Type", file.endsWith(".js") ? "text/javascript" : "text/css"); return res.end(fs.readFileSync(path.join(__dirname, file))); }
    res.setHeader("Content-Type", "text/html"); res.end('<!doctype html><html data-theme="dark"><head><link rel="stylesheet" href="/providers.css"></head><body><main class="page"><section id="dast-section"></section></main><script type="module">import {initDast} from "/dast.js"; await initDast(); window.ready=true;</script></body></html>');
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || path.join(process.env.LOCALAPPDATA, "ms-playwright/chromium-1234/chrome-win64/chrome.exe"), headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 420, height: 1000 } }), errors = [];
    page.on("pageerror", error => errors.push(error.message));
    await page.addInitScript(() => {
      window.fixture = { calls: [], plans: [], failRun: true, failExport: true, listeners: [], state: { workspace: { id: "workspace", name: "Target workspace" }, scope: { origins: ["https://target.test"], excludePaths: ["/logout"] }, capture: null, requests: [], plans: [], batches: [] } };
      const clone = value => JSON.parse(JSON.stringify(value));
      window.chrome = { storage: { onChanged: { addListener: fn => fixture.listeners.push(fn), removeListener: fn => fixture.listeners = fixture.listeners.filter(item => item !== fn) } }, runtime: { sendMessage: async message => {
        fixture.calls.push(clone(message)); let result;
        if (message.op === "tabs") result = [{ tabId: 2, title: "Unrelated active page", origin: "https://unrelated.test", active: true }, { tabId: 7, title: "Application", origin: "https://target.test", working: true }];
        else if (message.op === "state") result = fixture.state;
        else if (message.op === "capture") {
          fixture.state.capture = { active: message.action === "start", tabId: message.tabId || 7, origin: "https://target.test", count: 2 };
          fixture.state.requests = [
            { requestId: "get-1", method: "GET", url: "https://target.test/search", statusCode: 200, supported: true, requiresReplayConsent: true, parameters: [{ location: "query", name: "q", index: 0 }, { location: "query", name: "page", index: 1 }, { location: "query", name: "csrf", index: 2, supported: false, reason: "Authentication and session inputs are preserved, not mutated." }] },
            { requestId: "post-1", method: "POST", url: "https://target.test/profile", statusCode: 200, supported: true, requiresReplayConsent: true, parameters: [{ location: "form", name: "displayName", index: 0 }] },
            { requestId: "json-1", method: "POST", url: "https://target.test/json", statusCode: 200, supported: true, requiresReplayConsent: true, parameters: [
              { location: "json", name: "/profile/display~1name", index: 0, valueType: "string", compatibleFamilies: ["xss", "sql_injection", "open_redirect"] },
              { location: "json", name: "/count", index: 1, valueType: "number", supported: false, compatibleFamilies: [] },
              { location: "json", name: "/active", index: 2, valueType: "boolean", supported: false, compatibleFamilies: [] },
              { location: "json", name: "/empty", index: 3, valueType: "null", supported: false, compatibleFamilies: [] },
            ] },
            ...[["duplicate", "GET", "query"], ["duplicate-form", "POST", "form"]].map(([requestId, method, location]) => ({ requestId, method, url: "https://target.test/" + requestId, supported: true, requiresReplayConsent: true, compatibleFamilies: ["xss", "sql_boolean", "ssti", "jsonp_callback_injection", "response_checks"], parameters: [0, 1].map(index => ({ location, name: "q", index, compatibleFamilies: ["xss", "sql_boolean", "ssti", "jsonp_callback_injection"] })) })),
            { requestId: "response-only", method: "GET", url: "https://target.test/no-inputs", supported: true, requiresReplayConsent: true, compatibleFamilies: ["response_checks"], parameters: [] },
            { requestId: "unsupported", method: "POST", url: "https://target.test/upload", supported: false, reason: "Multipart bodies are not supported.", parameters: [] },
          ]; result = fixture.state.capture;
        } else if (message.op === "prepare") {
          result = { planId: "plan-" + fixture.plans.length, planHash: "hash-" + fixture.plans.length, state: "prepared", createdAt: Date.now(), expiresAt: Date.now() + 60000, scope: fixture.state.scope, budget: message.budget, families: message.families,
            requests: message.requests.map(item => ({ ...fixture.state.requests.find(request => request.requestId === item.requestId), ...item })) };
          fixture.plans.push(clone(result)); fixture.state.plans.push(clone(result));
        } else if (message.op === "run") {
          const plan = fixture.plans.find(plan => plan.planId === message.planId); if (!plan || plan.planHash !== message.planHash) return { ok: false, error: "Plan changed." };
          result = { batchId: "batch-" + fixture.state.batches.length, planId: plan.planId, state: fixture.failRun ? "auth_expired" : "running", requestsSent: fixture.failRun ? 1 : 0, findingsCount: 0, error: fixture.failRun ? "The baseline returned HTTP 401." : null };
          fixture.state.batches.push(result);
        } else if (message.op === "status") { const batch = fixture.state.batches.find(batch => batch.batchId === message.batchId); if (batch.state === "stopping") batch.state = "completed"; else if (batch.state === "running") { batch.requestsSent += 1; batch.findingsCount = 1; } result = batch; }
        else if (message.op === "stop") { const batch = fixture.state.batches.find(batch => batch.batchId === message.batchId); batch.state = "stopping"; result = batch; }
        else if (message.op === "findings") result = { batch: { ...fixture.state.batches.find(batch => batch.batchId === message.batchId), plan: { requests: [{ requestId: "internal-uuid-not-for-display", method: "POST", url: "https://target.test/duplicate-form" }] } }, findings: [{ title: '<img src=x onerror="window.findingExecuted=true">', classification: "reproduced_reflection", verifiedImpact: false, severity: "medium", parameter: { name: "q" }, baseline: { status: 200 }, mutation: { requestId: "get-1", parameter: "q" }, confirmation: { status: "reflected", proof: "Reflection does not establish script execution." } },
          ...[["sql_injection", "candidate"], ["sql_injection", "reproduced_sql_error"], ["open_redirect", "candidate"], ["open_redirect", "reproduced_redirect"], ["sql_boolean", "reproduced_boolean_difference"], ["ssti", "reproduced_template_evaluation"]].map(([family, classification]) => ({ family, classification, title: family + " evidence", verifiedImpact: false, parameter: { name: "/input" } })),
          { family: "sql_injection", classification: "reproduced_sql_error", title: "Root JSON string", parameter: { location: "json", name: "", index: 0 } },
          { family: "xss", classification: "reproduced_reflection", title: "Second repeated field", parameter: { location: "query", name: "q", index: 1 } }
        ], observations: [{ id: "callback", endpoint: "https://target.test/jsonp", method: "GET", family: "jsonp_callback_injection", title: '<img src=x onerror="window.observationExecuted=true">', classification: "callback_control", note: "A selected callback name appeared in the response. Browser execution was not tested." }, { id: "headers", requestId: "internal-uuid-not-for-display", family: "response_checks", title: "Response headers", note: "Header configuration observation." }, { id: "unknown", requestId: "missing-internal-id", family: "response_checks", title: "Earlier response", note: "Source reference no longer available." }], coverage: ["tested", "skipped", "unsupported", "inconclusive"].map((state, index) => ({ requestId: "internal-uuid-not-for-display", family: "sql_boolean", parameter: { location: "query", name: "q", index: 1 }, state, reason: ["Check completed.", "Request budget exhausted.", "Response representation unsupported.", "Responses drifted."][index], probesSent: index === 0 ? 5 : 0, matched: false })), warnings: ["Browser execution was not tested."], truncated: true };
        else if (message.op === "export") { if (fixture.failExport) return { ok: false, error: "Report download did not finish." }; result = { reports: [{ downloadId: 1, name: "dast-report.json", size: 100 }] }; }
        else return { ok: false, error: "Unexpected operation" };
        return { ok: true, result: clone(result) };
      } } };
    });
    await page.goto("http://127.0.0.1:" + server.address().port + "/?session=chat-one"); await page.waitForFunction(() => window.ready);
    assert.equal(await page.getByLabel("DAST target tab").inputValue(), "7");
    await page.getByRole("button", { name: "Capture requests", exact: true }).click();
    await page.getByRole("button", { name: "Stop capture", exact: true }).waitFor();
    assert.equal((await page.evaluate(() => fixture.calls.find(call => call.op === "capture"))).expectedOrigin, "https://target.test");
    assert.equal(await page.getByRole("button", { name: "Select POST https://target.test/upload", exact: true }).isDisabled(), true);
    assert.equal(await page.getByRole("button", { name: "Select GET https://target.test/duplicate", exact: true }).isDisabled(), false);
    await page.getByRole("button", { name: "Select GET https://target.test/search", exact: true }).click();
    assert.equal(await page.getByRole("switch", { name: "Test csrf · query #3", exact: true }).isDisabled(), true);
    assert.equal(await page.getByRole("switch", { name: "Test csrf · query #3", exact: true }).getAttribute("aria-checked"), "false");
    await page.getByRole("switch", { name: "Test page · query #2", exact: true }).click();
    const replay = page.getByRole("switch", { name: "Allow replay of GET https://target.test/search", exact: true });
    await replay.focus(); await page.keyboard.press("Space");
    assert.equal(await replay.getAttribute("aria-checked"), "false", "Replay consent supports keyboard activation");
    await page.getByRole("button", { name: "Review test plan", exact: true }).click();
    await page.getByText("Select Allow replay for GET https://target.test/search before preparing the batch.", { exact: true }).waitFor();
    assert.equal(await page.evaluate(() => fixture.calls.filter(call => call.op === "prepare").length), 0);
    await page.getByRole("switch", { name: "Allow replay of GET https://target.test/search", exact: true }).click();
    await page.getByRole("button", { name: "Review test plan", exact: true }).click();
    const first = await page.evaluate(() => fixture.calls.find(call => call.op === "prepare"));
    assert.deepEqual(first.requests, [{ requestId: "get-1", parameters: [{ location: "query", name: "q", index: 0 }], allowReplay: true }]);
    assert.deepEqual(first.budget, { maxRequests: 100, maxRequestsPerSecond: 1, concurrency: 1, durationSeconds: 300 }); assert.deepEqual(first.families, ["xss"]);
    assert.equal(await page.getByRole("switch", { name: "SQL errors", exact: true }).isDisabled(), true, "Legacy summaries only advertise XSS compatibility");
    await page.getByText("Test options", { exact: true }).click(); await page.getByLabel("Maximum DAST requests").fill("50");
    assert.equal(await page.locator(".dast-plan").isVisible(), false, "Changing a selection or budget invalidates the displayed immutable plan");
    await page.getByRole("button", { name: "Review test plan", exact: true }).click(); await page.getByRole("button", { name: "Run tests", exact: true }).click();
    await page.getByText(/Batch authentication expired/).waitFor(); assert.equal(await page.getByText("Test batch started.", { exact: true }).count(), 0);
    await page.evaluate(() => fixture.failRun = false);
    await page.getByRole("button", { name: "Review test plan", exact: true }).click(); await page.getByRole("button", { name: "Run tests", exact: true }).click();
    await page.getByText("Batch running.", { exact: true }).waitFor();
    await page.waitForFunction(() => [...document.querySelectorAll("button")].some(button => button.textContent === "Stop" && !button.disabled));
    const active = page.locator(".dast-batch").first();
    assert.equal(await active.getByRole("button", { name: "Export report", exact: true }).isDisabled(), true);
    await active.getByRole("button", { name: "Findings", exact: true }).click();
    await page.getByText("Browser execution was not tested.", { exact: true }).waitFor(); await page.getByText("Reproduced reflection · medium · q", { exact: true }).waitFor(); assert.equal(await page.locator(".dast-results img").count(), 0); assert.equal(await page.evaluate(() => window.findingExecuted), undefined);
    for (const label of ["SQL error candidate", "Reproduced SQL error", "Open redirect candidate", "Reproduced HTTP redirect", "Reproduced boolean difference", "Reproduced template evaluation"]) await page.getByText(label + " · /input", { exact: true }).waitFor();
    await page.locator(".dast-observations").getByRole("heading", { name: "Observations", exact: true }).waitFor();
    await page.locator(".dast-observations").getByText(/JSONP callback control · Callback control/).waitFor();
    assert.equal(await page.locator(".dast-observations img").count(), 0); assert.equal(await page.evaluate(() => window.observationExecuted), undefined);
    for (const state of ["Tested", "Skipped", "Unsupported", "Inconclusive"]) await page.locator(".dast-coverage").getByText("Boolean SQLi · " + state, { exact: true }).waitFor();
    await page.locator(".dast-coverage").getByText("Request budget exhausted.", { exact: true }).waitFor();
    assert.equal(await page.locator(".dast-coverage").getByText(/POST https:\/\/target.test\/duplicate-form · q · query #2/).count(), 4);
    await page.locator(".dast-observations").getByText("GET https://target.test/jsonp", { exact: true }).waitFor();
    await page.locator(".dast-observations").getByText("POST https://target.test/duplicate-form", { exact: true }).waitFor();
    await page.locator(".dast-observations").getByText("Selected request", { exact: true }).waitFor();
    assert.doesNotMatch(await page.locator(".dast-coverage").innerText(), /internal-uuid-not-for-display/);
    assert.doesNotMatch(await page.locator(".dast-observations").innerText(), /internal-uuid-not-for-display|missing-internal-id/);
    await page.getByText("Reproduced reflection · q · query #2", { exact: true }).waitFor();
    await page.getByText("Reproduced SQL error · (document root) · JSON pointer", { exact: true }).waitFor();
    await page.getByText("Baseline, mutation and confirmation", { exact: true }).first().click();
    await page.getByText(/Reflection does not establish script execution/).waitFor();
    await page.evaluate(() => {
      fixture.state.batches.at(-1).state = "unknown";
      fixture.calls = fixture.calls.filter(call => call.op !== "status");
      for (const listener of fixture.listeners) listener({ ki_dast_batches: {} }, "local");
    });
    await active.getByText(/State unknown/).waitFor();
    assert.equal(await active.getByRole("button", { name: "Stop", exact: true }).isEnabled(), true, "Uncertain starts must remain stoppable");
    assert.equal(await active.getByRole("button", { name: "Export report", exact: true }).isDisabled(), true);
    assert.equal(await page.getByRole("button", { name: "Review test plan", exact: true }).isDisabled(), true, "Uncertain starts must block another batch");
    await page.waitForFunction(() => fixture.calls.some(call => call.op === "status" && call.batchId === fixture.state.batches.at(-1).batchId));
    await active.getByRole("button", { name: "Stop", exact: true }).click(); await page.getByRole("button", { name: "Stopping…", exact: true }).waitFor();
    await active.getByText(/Completed/).waitFor();
    await active.getByRole("button", { name: "Export report", exact: true }).click(); await page.getByText("Report download did not finish.", { exact: true }).waitFor();
    assert.equal(await page.getByText("Saved 1 report to Outputs.", { exact: true }).count(), 0);
    await page.evaluate(() => fixture.failExport = false); await active.getByRole("button", { name: "Export report", exact: true }).click(); await page.getByText("Saved 1 report to Outputs.", { exact: true }).waitFor();
    await page.getByRole("button", { name: "Select GET https://target.test/search", exact: true }).click();
    await page.getByRole("button", { name: "Select POST https://target.test/json", exact: true }).click();
    for (const [pointer, type] of [["/count", "number"], ["/active", "boolean"], ["/empty", "null"]]) {
      const field = page.getByRole("switch", { name: `Test ${pointer} · JSON pointer · ${type}`, exact: true });
      assert.equal(await field.isDisabled(), true); assert.equal(await field.getAttribute("aria-checked"), "false");
    }
    await page.getByRole("switch", { name: "SQL errors", exact: true }).focus(); await page.keyboard.press("Space");
    await page.getByRole("switch", { name: "Open redirect", exact: true }).click();
    await page.getByRole("button", { name: "Review test plan", exact: true }).click();
    const jsonPlan = await page.evaluate(() => fixture.calls.filter(call => call.op === "prepare").at(-1));
    assert.deepEqual(jsonPlan.requests, [{ requestId: "json-1", parameters: [{ location: "json", name: "/profile/display~1name", index: 0 }], allowReplay: true }]);
    assert.deepEqual(jsonPlan.families, ["xss", "sql_injection", "open_redirect"]);
    await page.locator(".dast-plan").getByText("1 requests · Reflected XSS · SQL errors · Open redirect", { exact: true }).waitFor();
    await page.locator(".dast-plan").getByText("/profile/display~1name · JSON pointer", { exact: true }).waitFor();
    assert.equal(await page.locator(".dast-plan").getByText(/unknown type/).count(), 0, "Frozen selectors need no invented type label");
    await page.getByRole("switch", { name: "SQL errors", exact: true }).click();
    assert.equal(await page.locator(".dast-plan").isVisible(), false, "Changing checks invalidates the frozen plan");
    await page.getByRole("button", { name: "Review test plan", exact: true }).click();
    await page.evaluate(() => {
      fixture.state.requests.find(request => request.requestId === "json-1").parameters[0].compatibleFamilies = ["xss"];
      for (const listener of fixture.listeners) listener({ ki_dast_batches: {} }, "local");
    });
    await page.waitForFunction(() => document.querySelector('[role="switch"][aria-label="Open redirect"]').disabled);
    assert.equal(await page.getByRole("switch", { name: "Open redirect", exact: true }).getAttribute("aria-checked"), "false", "Stale incompatible checks are cleared");
    assert.equal(await page.locator(".dast-plan").isVisible(), false);
    await page.getByRole("button", { name: "Review test plan", exact: true }).click();
    assert.deepEqual(await page.evaluate(() => fixture.calls.filter(call => call.op === "prepare").at(-1).families), ["xss"]);
    await page.getByRole("button", { name: "Select POST https://target.test/json", exact: true }).click();
    await page.getByRole("button", { name: "Select GET https://target.test/no-inputs", exact: true }).click();
    assert.equal(await page.getByRole("switch", { name: "Reflected XSS", exact: true }).getAttribute("aria-checked"), "false");
    assert.equal(await page.getByRole("switch", { name: "Response checks", exact: true }).getAttribute("aria-checked"), "false", "Selecting an endpoint never enables response checks implicitly");
    assert.equal(await page.getByRole("button", { name: "Review test plan", exact: true }).isDisabled(), true);
    await page.getByRole("switch", { name: "Response checks", exact: true }).focus(); await page.keyboard.press("Space");
    await page.getByRole("button", { name: "Review test plan", exact: true }).click();
    const passivePlan = await page.evaluate(() => fixture.calls.filter(call => call.op === "prepare").at(-1));
    assert.deepEqual(passivePlan.families, ["response_checks"]); assert.deepEqual(passivePlan.requests, [{ requestId: "response-only", parameters: [], allowReplay: true }]);
    await page.getByRole("button", { name: "Select GET https://target.test/duplicate", exact: true }).click();
    assert.equal(await page.getByRole("switch", { name: "Boolean SQLi", exact: true }).isDisabled(), true, "A no-input request prevents active checks in a mixed selection");
    await page.getByRole("button", { name: "Select GET https://target.test/no-inputs", exact: true }).click();
    await page.getByRole("button", { name: "Select POST https://target.test/duplicate-form", exact: true }).click();
    await page.getByRole("switch", { name: "Test q · query #1", exact: true }).click(); await page.getByRole("switch", { name: "Test q · form #1", exact: true }).click();
    for (const name of ["Reflected XSS", "Boolean SQLi", "Server-side template injection", "JSONP callback control"]) await page.getByRole("switch", { name, exact: true }).click();
    await page.getByRole("button", { name: "Review test plan", exact: true }).click();
    const occurrencePlan = await page.evaluate(() => fixture.calls.filter(call => call.op === "prepare").at(-1));
    assert.deepEqual(occurrencePlan.families, ["xss", "sql_boolean", "ssti", "jsonp_callback_injection", "response_checks"]);
    assert.deepEqual(occurrencePlan.requests, [{ requestId: "duplicate", parameters: [{ location: "query", name: "q", index: 1 }], allowReplay: true }, { requestId: "duplicate-form", parameters: [{ location: "form", name: "q", index: 1 }], allowReplay: true }]);
    await page.getByRole("switch", { name: "Server-side template injection", exact: true }).click(); assert.equal(await page.locator(".dast-plan").isVisible(), false);
    await page.getByRole("switch", { name: "Test q · form #2", exact: true }).click();
    assert.equal(await page.getByRole("switch", { name: "Boolean SQLi", exact: true }).isDisabled(), true);
    assert.equal(await page.getByRole("button", { name: "Select POST https://target.test/duplicate-form", exact: true }).getAttribute("aria-pressed"), "true", "An empty field selection retains the request for passive checks");
    await page.getByRole("button", { name: "Review test plan", exact: true }).click();
    const mixedPassive = await page.evaluate(() => fixture.calls.filter(call => call.op === "prepare").at(-1)); assert.deepEqual(mixedPassive.families, ["response_checks"]); assert.equal(mixedPassive.requests[1].parameters.length, 0);
    await page.getByRole("button", { name: "Stop capture", exact: true }).click(); await page.getByRole("button", { name: "Capture requests", exact: true }).waitFor();
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)); await page.screenshot({ path: path.join(os.tmpdir(), "cert-x-dast-selected-420.png"), fullPage: true });
    await page.setViewportSize({ width: 720, height: 1000 });
    await page.evaluate(() => document.documentElement.dataset.theme = "light");
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), "Light theme fits the 720px settings layout");
    await page.evaluate(() => { fixture.state.scope = null; for (const listener of fixture.listeners) listener({ ki_contexts: {} }, "local"); });
    await page.getByText("Add target origins to this workspace before capturing requests.", { exact: true }).waitFor(); assert.equal(await page.getByRole("button", { name: "Capture requests", exact: true }).isDisabled(), true);
    await page.goto("http://127.0.0.1:" + server.address().port + "/"); await page.waitForFunction(() => window.ready); assert.equal(await page.getByRole("button", { name: "Capture requests", exact: true }).isDisabled(), true);
    assert.deepEqual(errors, []);
  } finally { await browser.close(); await new Promise(resolve => server.close(resolve)); }
});

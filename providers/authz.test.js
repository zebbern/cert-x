const test = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), os = require("node:os"), http = require("node:http");
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || "C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core");
test("Compare accounts renders explicit identities, frozen cases, uncertain stops and safe outcomes", async () => {
  const server = http.createServer((req, res) => { const file = { "/authz.js": "authz.js", "/authz.css": "authz.css", "/providers.css": "providers.css" }[req.url.split("?")[0]]; if (file) { res.setHeader("Content-Type", file.endsWith(".js") ? "text/javascript" : "text/css"); return res.end(fs.readFileSync(path.join(__dirname, file))); } res.setHeader("Content-Type", "text/html"); res.end('<!doctype html><html data-theme="dark"><head><link rel="stylesheet" href="/providers.css"></head><body><main class="page"><section id="authz-section"></section></main><script type="module">import {initAuthz} from "/authz.js"; await initAuthz(); window.ready=true;</script></body></html>'); });
  // Launch before listening: a failed launch must not leave the server holding the test process open.
  const browser = await chromium.launch({ executablePath: require("../tools/chromium-path.cjs"), headless: true });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  try {
    const page = await browser.newPage({ viewport: { width: 420, height: 1000 } }), errors = []; page.on("pageerror", error => errors.push(error.message));
    await page.addInitScript(() => {
      window.fixture = { calls: [], listeners: [], failExport: true, state: { workspace: { id: "w", name: "Example project" }, scope: { origins: ["https://app.test"], excludePaths: ["/logout"] }, capture: null, accounts: [], captures: [], batches: [], plans: [] } };
      const clone = value => JSON.parse(JSON.stringify(value));
      window.chrome = { storage: { onChanged: { addListener: fn => fixture.listeners.push(fn), removeListener: fn => fixture.listeners = fixture.listeners.filter(item => item !== fn) } }, runtime: { sendMessage: async message => {
        fixture.calls.push(clone(message)); let result;
        if (message.type === "KI_DAST") {
          if (message.op === "tabs") result = [{ tabId: 2, title: "Other page", origin: "https://other.test", active: true }, { tabId: 8, title: "Application", origin: "https://app.test", working: true }];
          else if (message.op === "capture") { fixture.state.capture = { active: message.action === "start", tabId: 8 }; fixture.state.captures = [{ requestId: "identity", method: "GET", url: "https://app.test/me", credentialHeaders: ["Authorization", "Cookie", "X-API-Key"], cookieNames: ["session", "tenant"], parameters: [] }, { requestId: "read", method: "GET", url: "https://app.test/objects/3", credentialHeaders: ["Authorization", "Cookie"], cookieNames: ["session"], parameters: [{ location: "path", name: "3", index: 1 }] }]; result = fixture.state.capture; }
        } else if (message.op === "state") result = fixture.state;
        else if (message.op === "save_account") { const account = { id: "account-" + fixture.state.accounts.length, label: message.label, role: message.role, tenant: message.tenant, revision: 1, workspaceId: "w", credentialHeaders: message.credentialHeaders, cookieNames: message.cookieNames, probe: { url: "https://app.test/me", method: "GET", claims: message.claims.map(({ pointer }) => ({ pointer })) } }; fixture.state.accounts.push(account); result = account; }
        else if (message.op === "verify") { const account = fixture.state.accounts.find(account => account.id === message.accountId); account.verification = { state: "verified" }; result = { state: "verified", reason: "Identity claims matched." }; }
        else if (message.op === "delete_account") { fixture.state.accounts = fixture.state.accounts.filter(account => account.id !== message.accountId); result = { deleted: true }; }
        else if (message.op === "prepare") { result = { planId: "plan-" + fixture.state.plans.length, planHash: "fixed-hash", state: "prepared", expiresAt: Date.now() + 60000, scope: fixture.state.scope, budget: message.budget, cases: message.cases.map(item => ({ requestId: item.requestId, method: "GET", url: "https://app.test/objects/3", ownerAccountId: item.ownerAccountId, expectations: item.expectations, evidence: { object: { pointer: item.evidence.object.pointer }, protected: { pointer: item.evidence.protected.pointer } }, ...(item.objectSwap ? { objectSwap: { location: item.objectSwap.location, name: item.objectSwap.name, index: item.objectSwap.index } } : {}) })) }; fixture.state.plans.push(result); }
        else if (message.op === "run") { const plan = fixture.state.plans.find(plan => plan.planId === message.planId); if (!plan || plan.planHash !== message.planHash) return { ok: false, error: "Plan mismatch" }; result = { batchId: "batch", state: "unknown", requestsSent: 0, reason: "Start acknowledgement was lost." }; fixture.state.batches.push(result); }
        else if (message.op === "status") { result = fixture.state.batches.find(batch => batch.batchId === message.batchId); if (result.state === "stopping") result.state = "stopped"; }
        else if (message.op === "stop") { result = fixture.state.batches.find(batch => batch.batchId === message.batchId); result.state = "stopping"; }
        else if (message.op === "findings") result = { batch: fixture.state.batches[0], cells: ["expected_access", "expected_denial", "unexpected_access", "inconclusive"].map(outcome => ({ outcome, accountLabel: "Owner", caseLabel: "Object", reason: outcome === "inconclusive" ? "Identity changed after request." : "Identity verified before and after.", identityVerified: outcome !== "inconclusive", title: '<img src=x onerror="window.unsafe=true">' })), warnings: [] };
        else if (message.op === "export") { if (fixture.failExport) return { ok: false, error: "Report download failed." }; result = { reports: [{ name: "comparison.json", downloadId: 3 }] }; }
        if (result === undefined) return { ok: false, error: "Unexpected fixture operation: " + message.op }; return { ok: true, result: clone(result) };
      } } };
    });
    await page.goto("http://127.0.0.1:" + server.address().port + "/?session=chat"); await page.waitForFunction(() => window.ready);
    assert.equal(await page.getByLabel("Capture target tab").inputValue(), "8");
    await page.getByRole("button", { name: "Capture requests", exact: true }).click(); await page.getByRole("button", { name: "Stop capture", exact: true }).waitFor();
    await page.getByLabel("Identity request", { exact: true }).selectOption("identity"); await page.getByLabel("Account label").fill("Owner"); await page.getByLabel("Expected account ID").fill("private-owner-id");
    await page.getByRole("button", { name: "Save account", exact: true }).click(); await page.getByText("Declare the identity request read-only before saving.", { exact: true }).waitFor();
    assert.equal(await page.evaluate(() => fixture.calls.filter(call => call.op === "save_account").length), 0);
    await page.getByText("Account details and credentials", { exact: true }).click();
    assert.equal(await page.getByRole("switch", { name: "Use headers Authorization", exact: true }).getAttribute("aria-checked"), "true");
    assert.equal(await page.getByRole("switch", { name: "Use headers X-API-Key", exact: true }).getAttribute("aria-checked"), "false");
    await page.getByRole("switch", { name: "Use cookies tenant", exact: true }).focus(); await page.keyboard.press("Space");
    await page.getByRole("switch", { name: "Identity request is read-only", exact: true }).click();
    await page.getByRole("button", { name: "Save account", exact: true }).click(); await page.getByRole("button", { name: "Verify Owner", exact: true }).waitFor();
    const saved = await page.evaluate(() => fixture.calls.find(call => call.op === "save_account"));
    assert.deepEqual(saved.credentialHeaders, ["Authorization"]); assert.deepEqual(saved.cookieNames, ["session"]); assert.deepEqual(saved.claims, [{ pointer: "/id", expected: "private-owner-id" }]); assert.equal(saved.readOnly, true);
    assert.equal(await page.getByLabel("Expected account ID").inputValue(), "");
    await page.getByRole("button", { name: "Verify Owner", exact: true }).click(); await page.getByText(/Identity claims matched/).waitFor();
    await page.getByLabel("Read request", { exact: true }).selectOption("read"); await page.getByLabel("Request owner", { exact: true }).selectOption("account-0");
    await page.getByLabel("Expected object value", { exact: true }).fill("private-object-id"); await page.getByLabel("Expected protected value", { exact: true }).fill("private-protected-canary");
    await page.getByLabel("Expected access for Anonymous", { exact: true }).selectOption("deny");
    await page.getByRole("button", { name: "Add request case", exact: true }).click(); await page.getByText("Choose a request and owner, then declare the request read-only.", { exact: true }).waitFor();
    await page.getByRole("switch", { name: "Request is read-only", exact: true }).focus(); await page.keyboard.press("Space");
    await page.getByText("Replace one object ID", { exact: true }).click(); await page.getByLabel("Object replacement location").selectOption("path"); await page.getByLabel("Object replacement index").fill("1"); await page.getByLabel("Object replacement value").fill("private-swap-id");
    await page.getByRole("button", { name: "Add request case", exact: true }).click(); await page.getByRole("button", { name: "Remove case 1", exact: true }).waitFor();
    await page.getByRole("button", { name: "Review comparison", exact: true }).click(); await page.locator(".authz-plan").waitFor();
    const prepared = await page.evaluate(() => fixture.calls.find(call => call.op === "prepare"));
    assert.equal(prepared.cases[0].readOnly, true); assert.deepEqual(prepared.cases[0].expectations, [{ accountId: "account-0", expected: "allow" }, { accountId: "anonymous", expected: "deny" }]); assert.deepEqual(prepared.cases[0].objectSwap, { location: "path", name: "", index: 1, value: "private-swap-id" }); assert.equal(prepared.budget.maxRequests, 100);
    assert.doesNotMatch(await page.locator(".authz-plan").innerText(), /private-(owner|object|protected|swap)/);
    await page.getByText("Test options", { exact: true }).click(); await page.getByLabel("Maximum comparison requests").fill("2500"); assert.equal(await page.locator(".authz-plan").isVisible(), false);
    await page.getByLabel("Maximum comparison minutes").fill("30"); await page.getByLabel("Comparison requests per second").fill("7");
    await page.getByRole("button", { name: "Review comparison", exact: true }).click();
    const expanded = await page.evaluate(() => fixture.calls.filter(call => call.op === "prepare").at(-1));
    assert.deepEqual(expanded.budget, { maxRequests: 2500, maxRequestsPerSecond: 7, concurrency: 1, durationSeconds: 1800 });
    await page.getByRole("button", { name: "Run comparison", exact: true }).click();
    await page.getByRole("heading", { name: "State unknown", exact: true }).waitFor();
    assert.equal(await page.getByRole("button", { name: "Stop", exact: true }).isEnabled(), true); assert.equal(await page.getByRole("button", { name: "Export report", exact: true }).isDisabled(), true); assert.equal(await page.getByRole("button", { name: "Review comparison", exact: true }).isDisabled(), true);
    await page.waitForFunction(() => fixture.calls.some(call => call.op === "status"));
    await page.getByRole("button", { name: "Results", exact: true }).click(); for (const name of ["Expected access", "Expected denial", "Unexpected access", "Inconclusive"]) await page.locator(".authz-results").getByRole("heading", { name, exact: true }).waitFor();
    await page.locator(".authz-results .authz-meta").getByText(/Identity changed after request/).waitFor(); assert.equal(await page.locator(".authz-results img").count(), 0); assert.equal(await page.evaluate(() => window.unsafe), undefined);
    await page.getByRole("button", { name: "Stop", exact: true }).click(); await page.getByRole("heading", { name: "Stopped", exact: true }).waitFor();
    await page.getByRole("button", { name: "Export report", exact: true }).click(); await page.getByText("Report download failed.", { exact: true }).waitFor();
    await page.evaluate(() => fixture.failExport = false); await page.getByRole("button", { name: "Export report", exact: true }).click(); await page.getByText("Saved 1 report(s) to Outputs.", { exact: true }).waitFor();
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)); await page.screenshot({ path: path.join(os.tmpdir(), "cert-x-authz-420.png"), fullPage: true });
    await page.setViewportSize({ width: 720, height: 1000 }); await page.evaluate(() => document.documentElement.dataset.theme = "light"); assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    await page.getByRole("button", { name: "Delete Owner", exact: true }).click(); assert.equal(await page.getByRole("button", { name: "Remove case 1", exact: true }).count(), 0);
    await page.goto("http://127.0.0.1:" + server.address().port + "/"); await page.waitForFunction(() => window.ready); assert.equal(await page.getByRole("button", { name: "Capture requests", exact: true }).isDisabled(), true); assert.deepEqual(errors, []);
  } finally { await browser.close(); await new Promise(resolve => server.close(resolve)); }
});

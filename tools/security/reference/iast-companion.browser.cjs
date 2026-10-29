// Actual PTK v10 + cert-x: agent browser actions, positive/negative controls and exports.
const fs = require("node:fs"), os = require("node:os"), path = require("node:path"), http = require("node:http"), zlib = require("node:zlib"), assert = require("node:assert/strict");
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || "C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core");
const root = path.resolve(__dirname, "../../.."), extension = process.env.PTK_EXTENSION || path.join(process.env.LOCALAPPDATA, "cert-x/ptk/v10/src");
const temp = fs.mkdtempSync(path.join(os.tmpdir(), "cert-x-iast-real-"));
const proof = '<img src="/missing.png" onerror="window.fixtureProof=1"><b>IAST-CONTROLLED-PROOF</b>';
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
let browser, server, outsideServer, phase = "attach", step = 0, targetId;
const pageErrors = [], modelErrors = [], toolResults = [], modelCalls = [];
async function main() {
  assert.equal(JSON.parse(fs.readFileSync(path.join(extension, "manifest.json"), "utf8")).version, "10.0.0");
  server = http.createServer((req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*"); res.setHeader("Access-Control-Allow-Headers", "*");
    if (req.method === "OPTIONS") return res.end();
    if (req.url.endsWith("/models")) { res.setHeader("Content-Type", "application/json"); return res.end(JSON.stringify({ data: [{ id: "mock/iast", name: "IAST browser fixture", context_length: 128000 }] })); }
    if (req.url.includes("/chat/completions")) {
      let body = ""; req.on("data", chunk => body += chunk); req.on("end", () => {
        try {
          const request = JSON.parse(body), names = (request.tools || []).map(tool => tool.function?.name); modelCalls.push({ phase, names });
          for (const item of request.messages || []) if (item.role === "tool") toolResults.push(typeof item.content === "string" ? item.content : JSON.stringify(item.content));
          const actions = phase === "attach" ? [{ name: "attach_tab", args: { tabId: targetId } }] : [{ name: "fill", args: { selector: "#input", value: proof } }, { name: "click", args: { selector: "#apply" } }];
          const action = actions[step++]; if (action) assert.ok(names.includes(action.name), "Browser tool advertised: " + action.name);
          res.writeHead(200, { "Content-Type": "text/event-stream" }); const send = value => res.write("data: " + JSON.stringify(value) + "\n\n");
          send({ id: "iast-agent", object: "chat.completion.chunk", choices: [{ index: 0, delta: action ? { role: "assistant", tool_calls: [{ index: 0, id: "iast-" + phase + "-" + step, type: "function", function: { name: action.name, arguments: JSON.stringify(action.args) } }] } : { role: "assistant", content: "IAST-AGENT-DONE " + phase } }] });
          send({ id: "iast-agent", object: "chat.completion.chunk", choices: [{ index: 0, delta: {}, finish_reason: action ? "tool_calls" : "stop" }] }); res.end("data: [DONE]\n\n");
        } catch (error) { modelErrors.push(error.message); res.statusCode = 500; res.end(); }
      }); return;
    }
    if (req.url === "/favicon.ico" || req.url === "/missing.png") { res.writeHead(204); return res.end(); }
    if (req.url.startsWith("/app.js")) { res.setHeader("Content-Type", "application/javascript"); return res.end(`document.getElementById('apply').onclick=()=>{const input=document.getElementById('input').value;history.pushState({},'',location.pathname+'#'+encodeURIComponent(input));const value=decodeURIComponent(location.hash.slice(1));const sink=document.getElementById('sink');if(location.pathname.includes('safe'))sink.textContent=value;else sink.innerHTML=value;};`); }
    res.setHeader("Content-Type", "text/html"); res.end(`<!doctype html><html><head><title>IAST workflow fixture</title><script>window.fixtureProof=0;</script></head><body><h1>IAST ${req.url.startsWith("/safe") ? "safe" : "vulnerable"} fixture</h1><label for="input">Test value</label><input id="input"><button id="apply">Apply</button><div id="sink"></div><script src="/app.js"></script></body></html>`);
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve)); const origin = "http://127.0.0.1:" + server.address().port;
  outsideServer = http.createServer((_req, res) => { res.setHeader("Content-Type", "text/html"); res.end("<!doctype html><title>Outside observation origin</title><h1>Outside origin</h1>"); });
  await new Promise(resolve => outsideServer.listen(0, "127.0.0.1", resolve)); const outsideOrigin = "http://127.0.0.1:" + outsideServer.address().port;
  const downloads = path.join(temp, "downloads"), profile = path.join(temp, "profile"); fs.mkdirSync(path.join(profile, "Default"), { recursive: true }); fs.mkdirSync(downloads);
  fs.writeFileSync(path.join(profile, "Default/Preferences"), JSON.stringify({ download: { default_directory: downloads, prompt_for_download: false } }));
  browser = await chromium.launchPersistentContext(profile, { headless: true, downloadsPath: downloads, viewport: { width: 720, height: 1000 }, executablePath: require("../../chromium-path.cjs"), args: ["--disable-extensions-except=" + root + "," + extension, "--load-extension=" + root + "," + extension] });
  for (let i = 0; i < 200 && browser.serviceWorkers().length < 2; i++) await sleep(50);
  const ptk = browser.serviceWorkers().find(worker => new URL(worker.url()).pathname === "/app.js"), cert = browser.serviceWorkers().find(worker => new URL(worker.url()).pathname === "/background/background.js"); assert.ok(ptk && cert);
  await ptk.evaluate(async () => { for (let i = 0; i < 200 && !self.ptk_app?.ready; i++) await new Promise(resolve => setTimeout(resolve, 50)); await self.ptk_app.ready; });
  for (let i = 0; i < 8; i++) { await cert.evaluate(origin => chrome.storage.local.set({ sidepanel_language: "en", sidepanel_theme: "dark", sidepanel_approval_mode: "full_access", sidepanel_connections: [{ id: "mock", label: "Mock", presetId: "openrouter", apiKey: "fixture", host: origin + "/api/v1" }] }), origin); await sleep(500); if ((await cert.evaluate(() => chrome.storage.local.get("sidepanel_connections"))).sidepanel_connections?.length) break; }
  const page = await browser.newPage(); page.on("pageerror", error => pageErrors.push(error.message)); await page.goto(origin + "/safe"); await page.waitForFunction(() => !!window.PTK_AUTOMATION);
  targetId = await cert.evaluate(async origin => (await chrome.tabs.query({})).find(tab => tab.url === origin + "/safe").id, origin);
  const base = "chrome-extension://" + new URL(cert.url()).host, panel = await browser.newPage(); panel.on("pageerror", error => pageErrors.push(error.message)); await panel.goto(base + "/pages/sidepanel.html?tabId=" + targetId);
  await panel.waitForFunction(() => document.querySelector('[aria-label="Profile"]')?.disabled === false); await panel.getByLabel("Profile", { exact: true }).selectOption("bugbounty"); await panel.locator(".ki-ptk-root").waitFor();
  const runAgent = async name => { phase = name; step = 0; await panel.locator(".wb-editor").first().click(); await panel.keyboard.type("Exercise the " + name + " workflow."); await panel.keyboard.press("Enter"); await panel.getByText("IAST-AGENT-DONE " + name, { exact: true }).waitFor(); await panel.waitForFunction(() => document.querySelector('[aria-label="Profile"]').disabled === false); };
  await runAgent("attach");
  const context = await cert.evaluate(() => chrome.storage.local.get("ki_contexts")), session = Object.keys(context.ki_contexts.chats).find(key => context.ki_contexts.chats[key].profileId === "bugbounty"); assert.ok(session);
  const settings = await browser.newPage(); settings.on("pageerror", error => pageErrors.push(error.message)); await settings.goto(base + "/providers/providers.html?section=ptk&session=" + session); await settings.waitForFunction(() => !document.querySelector("main").inert);
  const call = async (op, args = {}) => { const response = await settings.evaluate(message => chrome.runtime.sendMessage(message), { type: "KI_PTK", op, session, ...args }); assert.equal(response?.ok, true, JSON.stringify(response)); return response.result; };
  const checked = await call("check", { tabId: targetId }); assert.equal(checked.version, "10.0.0");
  const started = await call("start", { tabId: targetId, expectedOrigin: origin, engines: ["IAST"] }); assert.equal(started.mode, "observe"); assert.deepEqual(started.engines, ["IAST"]); assert.equal(started.deadline - started.startedAt, 600000);
  const statusUntil = async predicate => { let status; for (let i = 0; i < 100; i++) { status = await call("status", { scanId: started.scanId }); if (predicate(status)) return status; await sleep(200); } throw Error("IAST status did not converge: " + JSON.stringify(status)); };
  let status = await statusUntil(value => value.observationState === "observing"); const runtimeCounts = await page.evaluate(() => {const d=window.__PTK_IAST_DEBUG_STATE__?.();return {hooks:d?.enabledHookGroups?.length,modules:d?.activeModuleIds?.length,rules:d?.activeRuleIds?.length,revision:PTK_AGENT.describe().certXIntegrationRevision};}); assert.ok(runtimeCounts.hooks > 0 && runtimeCounts.modules > 0 && runtimeCounts.rules > 0); assert.ok(runtimeCounts.revision >= 1); console.log("Instrumentation counts",JSON.stringify(runtimeCounts));
  const extended = await call("extend", { scanId: started.scanId }); assert.equal(extended.deadline, started.deadline + 300000);
  const assignedOther = await settings.evaluate(() => chrome.runtime.sendMessage({ type: "KI_CONTEXT", op: "assign_chat", session: "another-chat", profileId: "bugbounty", modelExplicit: null })); assert.equal(assignedOther.ok, true);
  const popupPromise = browser.waitForEvent("page"); await page.evaluate(origin => window.open(origin + "/popup", "iast-scope-popup"), origin); const popup = await popupPromise; await popup.waitForLoadState(); await sleep(500);
  assert.equal(await popup.evaluate(() => !!window.__PTK_IAST_AGENT_LOADED__), false, "Same-origin popups must not silently join this observation");
  const popupTabId = await cert.evaluate(async origin => (await chrome.tabs.query({})).find(tab => tab.url === origin + "/popup").id, origin);
  const concurrent = await settings.evaluate(args => chrome.runtime.sendMessage({ type: "KI_PTK", op: "start", session: "another-chat", ...args }), { tabId: popupTabId, expectedOrigin: origin, engines: ["IAST"] }); assert.equal(concurrent.ok, false); assert.match(concurrent.error, /IAST|observation/i);
  const scopeRuntime = await page.evaluate(sessionId => PTK_AGENT.scanStatus({ sessionId }), started.sessionId); assert.deepEqual(scopeRuntime.engines.IAST.relatedTabIds, []); await popup.close();
  await runAgent("safe"); await sleep(800); assert.equal(await page.evaluate(() => fixtureProof), 0); assert.equal(await page.locator("#sink").textContent(), proof);
  const negative = await call("findings", { scanId: started.scanId, limit: 100 }); assert.ok(!negative.findings.some(item => item.ruleId === "dom_innerhtml_xss"), "textContent control must not produce an innerHTML finding");
  await page.goto(origin + "/vulnerable"); await page.waitForFunction(() => !!window.PTK_AGENT && PTK_AGENT.preflight().ready === true); status = await statusUntil(value => value.observationState === "observing");
  const runtime = await page.evaluate(sessionId => PTK_AGENT.scanStatus({ sessionId }), started.sessionId); assert.ok(runtime.engines.IAST.runtimeUrl.includes("/vulnerable"));
  await runAgent("vulnerable"); await page.waitForFunction(() => fixtureProof === 1);
  let positive; for (let i = 0; i < 40; i++) { positive = await call("findings", { scanId: started.scanId, limit: 100 }); if (positive.findings.some(item => item.ruleId === "dom_innerhtml_xss")) break; await sleep(200); }
  const xss = positive.findings.find(item => item.ruleId === "dom_innerhtml_xss"); assert.ok(xss, JSON.stringify(positive)); assert.ok(xss.url.includes("/vulnerable"));
  await page.goto(outsideOrigin + "/outside"); await sleep(300); assert.equal(await page.evaluate(() => !!window.__PTK_IAST_AGENT_LOADED__), false);
  const outsideStatus = await call("status", { scanId: started.scanId }); assert.notEqual(outsideStatus.observationState, "observing"); assert.match(outsideStatus.error || "", /origin/i);
  await page.goto(origin + "/vulnerable"); await page.waitForFunction(() => !!window.PTK_AGENT && PTK_AGENT.preflight().ready === true); await statusUntil(value => value.observationState === "observing");
  const changed = await call("findings", { scanId: started.scanId, limit: 100, changesOnly: true }); const unchanged = await call("findings", { scanId: started.scanId, limit: 100, changesOnly: true }); assert.equal(unchanged.findings.length, 0);
  status = await call("status", { scanId: started.scanId }); assert.ok((status.actions || status.activity || []).some(item => (item.tool || item.toolName || item.name) === "click"), "Actual agent tool actions must be retained"); assert.ok(!JSON.stringify(status.actions || status.activity || []).includes(proof));
  const stopped = await call("stop", { scanId: started.scanId }); assert.ok(["stopping", "completed"].includes(stopped.state)); status = await statusUntil(value => value.state === "completed"); assert.equal(status.cleanup?.reloadNeeded, true);
  const finalRuntime = await page.evaluate(sessionId => PTK_AGENT.scanStatus({ sessionId }), started.sessionId); assert.equal(finalRuntime.engines.IAST.pendingFindingReports, 0);
  const exported = await call("export", { scanId: started.scanId }), report = exported.reports.find(item => item.engine === "IAST"); assert.ok(report);
  const download = (await cert.evaluate(id => chrome.downloads.search({ id }), report.downloadId))[0]; assert.equal(download.state, "complete"); const file = path.resolve(download.filename); assert.ok(file.startsWith(path.resolve(temp) + path.sep));
  const bytes = fs.readFileSync(file); assert.equal(bytes.length, report.size); const artifact = JSON.parse(zlib.gunzipSync(bytes).toString("utf8")); assert.equal(artifact.engine, "IAST"); assert.match(JSON.stringify(artifact), /dom_innerhtml_xss/);
  assert.ok(await page.evaluate(() => !!window.__PTK_IAST_DEBUG_STATE__));
  // An independently started PTK session must remain owned by its caller.
  const foreign = await browser.newPage(); await foreign.goto(origin + "/manual"); await foreign.bringToFront(); await foreign.waitForFunction(() => !!window.PTK_AUTOMATION);
  const activation = await foreign.evaluate(() => PTK_AUTOMATION.requestActivation({ reason: "isolated foreign-session ownership test" })); assert.equal(activation.allowed, true); await foreign.waitForFunction(() => !!window.PTK_AGENT && PTK_AGENT.preflight().ready);
  const foreignScan = await foreign.evaluate(() => PTK_AGENT.startScan({ project: "foreign-manual-owner", engines: ["IAST"] })); assert.equal(foreignScan.ok, true, JSON.stringify(foreignScan));
  await foreign.locator("#input").fill(proof.replace("IAST-CONTROLLED-PROOF", "FOREIGN-OWNER-PROOF")); await foreign.locator("#apply").click(); await foreign.waitForFunction(() => fixtureProof === 1);
  let foreignFindings; for (let i = 0; i < 40; i++) { foreignFindings = await foreign.evaluate(sessionId => PTK_AGENT.getFindings({ sessionId, limit: 100 }), foreignScan.sessionId); if (foreignFindings.findings?.some(item => item.ruleId === "dom_innerhtml_xss")) break; await sleep(200); }
  assert.ok(foreignFindings.findings.some(item => item.ruleId === "dom_innerhtml_xss"));
  // PTK may discard an older engine result when another scan resets the singleton.
  // The contract is explicit unavailability plus preserved exports, never foreign fallback.
  const retained = await settings.evaluate(args => chrome.runtime.sendMessage({ type: "KI_PTK", op: "findings", ...args }), { session, scanId: started.scanId, limit: 100 });
  assert.equal(retained.ok, false); assert.match(retained.error, /session_result_unavailable|no longer retains|no longer.*available|not.*retained/i); assert.equal(retained.result, undefined);
  const oldRecord = (await call("state")).scans.find(item => item.scanId === started.scanId); assert.equal(oldRecord.sessionId, started.sessionId);
  assert.equal(Buffer.compare(fs.readFileSync(file), bytes), 0); assert.equal(JSON.parse(zlib.gunzipSync(fs.readFileSync(file)).toString("utf8")).engine, "IAST");
  const outputReply = await settings.evaluate(session => chrome.runtime.sendMessage({ type: "KI_WORKSPACE", op: "outputs", session }), session); assert.equal(outputReply.ok, true); assert.ok(outputReply.result.some(item => item.downloadId === report.downloadId && item.owner === session));
  const refused = await settings.evaluate(args => chrome.runtime.sendMessage({ type: "KI_PTK", op: "start", ...args }), { session, tabId: targetId, expectedOrigin: origin, engines: ["IAST"] }); assert.equal(refused.ok, false, "cert-x must not enroll into someone else's IAST session");
  const foreignStillRunning = await foreign.evaluate(sessionId => PTK_AGENT.scanStatus({ sessionId }), foreignScan.sessionId); assert.equal(foreignStillRunning.sessionId, foreignScan.sessionId); assert.equal(foreignStillRunning.status, "running");
  await foreign.evaluate(sessionId => PTK_AGENT.stopScan({ sessionId, wait: true }), foreignScan.sessionId); await foreign.close();
  await page.reload(); assert.equal(await page.evaluate(() => !!window.__PTK_IAST_DEBUG_STATE__), false);
  assert.deepEqual(pageErrors, []); assert.deepEqual(modelErrors, []); assert.ok(modelCalls.some(call => call.names.includes("ptk_extend_scan"))); assert.ok(!toolResults.some(result => /failed:|Permission denied|Tool operation denied/i.test(result)), JSON.stringify(toolResults));
  await settings.bringToFront(); await settings.reload(); await settings.waitForFunction(() => !document.querySelector("main").inert); await settings.screenshot({ path: path.join(os.tmpdir(), "cert-x-iast-real.png"), fullPage: true });
  console.log(JSON.stringify({ actualPtkVersion: "10.0.0", realAgentTools: ["attach_tab", "fill", "click"], debuggerCoexistence: true, readyBeforeActions: true, sanitizedControlNoDomXss: true, positiveRule: xss.ruleId, sameOriginNavigation: true, extension: true, singleton: true, popupExcluded: true, crossOriginExcluded: true, foreignSessionNotAdopted: true, retainedFindingsIsolated: true, oldFindingsExplicitlyUnavailable: true, savedArtifactPreserved: true, changesOnly: true, nearbyActivity: true, pendingReportsDrained: true, gzipReportParsed: true, reloadResetsInstrumentation: true, negativeCandidates: negative.findings.length, positiveCandidates: positive.findings.length, changedCandidates: changed.findings.length, reportBytes: bytes.length }));
}
main().catch(error => { console.error(error); process.exitCode = 1; }).finally(async () => { await browser?.close(); if (server) await new Promise(resolve => server.close(resolve)); if (outsideServer) await new Promise(resolve => outsideServer.close(resolve)); const absolute = path.resolve(temp); if (absolute.startsWith(path.resolve(os.tmpdir()) + path.sep) && path.basename(absolute).startsWith("cert-x-iast-real-")) fs.rmSync(absolute, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); });

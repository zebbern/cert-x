// Isolated Chromium: real settings, chat runtime and model traffic; no user profile/native registration.
const assert = require("node:assert/strict");
const fs = require("node:fs"), os = require("node:os"), path = require("node:path"), http = require("node:http");
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || "C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core");
const root = path.resolve(__dirname, "../../.."), temp = fs.mkdtempSync(path.join(os.tmpdir(), "cert-x-context-e2e-"));
let context, server;
const requests = [], errors = [], warnings = [], discoveries = [];
async function main() {
  server = http.createServer((req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*"); res.setHeader("Access-Control-Allow-Headers", "*");
    if (req.method === "OPTIONS") return res.end();
    if (req.url.endsWith("/models")) { res.setHeader("Content-Type", "application/json"); return res.end(JSON.stringify({ data: [{ id: "mock/research", name: "Research model" }, { id: "mock/coding", name: "Coding model" }] })); }
    if (req.url === "/fixture") { res.setHeader("Content-Type", "text/html"); return res.end("<!doctype html><title>Workspace reference</title><h1>Reference fixture</h1>"); }
    if (req.url === "/favicon.ico") { res.statusCode = 204; return res.end(); }
    let body = ""; req.on("data", data => body += data); req.on("end", () => {
      try {
        const value = JSON.parse(body);
        if (req.url.startsWith("/mcp/")) {
          res.setHeader("Content-Type", "application/json");
          const reply = result => res.end(JSON.stringify({ jsonrpc: "2.0", id: value.id, result }));
          if (value.method === "initialize") return reply({ protocolVersion: "2025-03-26", capabilities: { tools: {} }, serverInfo: { name: req.url, version: "1" } });
          if (value.method === "notifications/initialized") { res.statusCode = 202; return res.end(); }
          if (value.method === "tools/list") { discoveries.push(req.url); return reply({ tools: [{ name: "lookup", description: "Lookup fixture", inputSchema: { type: "object", properties: {} } }] }); }
          return reply({ content: [{ type: "text", text: "fixture" }] });
        }
        requests.push(value); res.writeHead(200, { "Content-Type": "text/event-stream" });
        const send = value => res.write("data: " + JSON.stringify(value) + "\n\n");
        send({ id: "contexts", object: "chat.completion.chunk", choices: [{ index: 0, delta: { role: "assistant", content: "CONTEXT-OK " + requests.length } }] });
        send({ id: "contexts", object: "chat.completion.chunk", choices: [{ index: 0, delta: {}, finish_reason: "stop" }] }); res.end("data: [DONE]\n\n");
      } catch (error) { errors.push(error.message); res.statusCode = 500; res.end(); }
    });
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const origin = "http://127.0.0.1:" + server.address().port;
  context = await chromium.launchPersistentContext(path.join(temp, "profile"), { executablePath: require("../../chromium-path.cjs"), headless: true, viewport: { width: 720, height: 980 }, args: [`--disable-extensions-except=${root}`, `--load-extension=${root}`] });
  let [worker] = context.serviceWorkers(); if (!worker) worker = await context.waitForEvent("serviceworker");
  const id = new URL(worker.url()).host, base = "chrome-extension://" + id;
  for (let attempt = 0; attempt < 8; attempt++) {
    await worker.evaluate(async origin => chrome.storage.local.set({ sidepanel_language: "en", sidepanel_theme: "dark", sidepanel_connections: [{ id: "mock", label: "Mock", presetId: "openrouter", apiKey: "fixture", host: origin + "/api/v1" }], ki_native_settings: { enabled: true, servers: [] } }), origin);
    await new Promise(resolve => setTimeout(resolve, 700));
    if ((await worker.evaluate(() => chrome.storage.local.get("sidepanel_connections"))).sidepanel_connections?.length) break;
  }
  const page = await context.newPage(); page.on("pageerror", error => errors.push(error.message));
  page.on("console", message => { if (message.type() === "error") errors.push(message.text()); if (message.type() === "warning") warnings.push(message.text()); });
  const open = async section => { await page.goto(base + "/providers/providers.html?section=" + section); await page.waitForFunction(() => !document.querySelector("main").inert); };
  const api = async (op, extra = {}) => {
    const response = await page.evaluate(message => chrome.runtime.sendMessage(message), { type: "KI_CONTEXT", op, ...extra }); assert.equal(response?.ok, true, response?.error); return response.result;
  };
  await open("profiles"); assert.equal(await page.title(), "Profiles");
  assert.deepEqual(await page.locator(".context-saved-row h3").allTextContents(), ["Default", "Research", "Coding", "Bug bounty"]);
  await page.locator(".context-saved-row").filter({ has: page.getByRole("heading", { name: "Research", exact: true }) }).getByRole("button", { name: "Edit", exact: true }).click();
  await page.getByText("Model, tools & permissions", { exact: true }).click();
  await page.getByLabel("Preferred model", { exact: true }).selectOption(JSON.stringify(["mock", "mock/research"]));
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await page.getByText("Saved · applies to the next message", { exact: true }).waitFor();
  await page.locator(".context-saved-row").filter({ has: page.getByRole("heading", { name: "Research", exact: true }) }).getByRole("button", { name: "Duplicate" }).click();
  await page.locator(".context-editor").getByLabel("Name", { exact: true }).fill("Research custom");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await page.getByRole("heading", { name: "Research custom", exact: true }).waitFor();
  await page.screenshot({ path: path.join(os.tmpdir(), "cert-x-profiles.png") });
  const fixture = await context.newPage(); await fixture.goto(origin + "/fixture");
  await open("workspaces"); assert.equal(await page.title(), "Workspaces");
  await page.getByRole("button", { name: "New workspace", exact: true }).click();
  await page.locator(".context-editor").getByLabel("Name", { exact: true }).fill("Evidence workspace");
  await page.getByLabel("Default profile", { exact: true }).selectOption("research");
  await page.getByLabel("Working folder", { exact: true }).fill(temp);
  await page.getByLabel("Shared notes", { exact: false }).fill("WORKSPACE-EVIDENCE: compare source dates; keep hypotheses separate.");
  await page.getByText("Testing scope", {exact:true}).click();
  await page.getByLabel("Allowed origins", {exact:false}).fill(origin);
  const hostScope=page.getByRole('switch',{name:'Same host',exact:true});await hostScope.focus();await page.keyboard.press('Space');
  assert.equal(await hostScope.getAttribute('aria-checked'),'true');
  const subdomainScope=page.getByRole('switch',{name:'Subdomains',exact:true});await subdomainScope.focus();await page.keyboard.press('Space');
  assert.equal(await subdomainScope.getAttribute('aria-checked'),'true');
  await page.getByText("Pinned files & pages", { exact: true }).click();
  await page.getByLabel("Pinned file path", { exact: true }).fill(path.join(temp, "notes.txt"));
  await page.getByRole("button", { name: "Pin file", exact: true }).click();
  await page.getByLabel("Page to pin", { exact: true }).selectOption({ label: "Workspace reference" });
  await page.getByRole("button", { name: "Pin page", exact: true }).click();
  await page.screenshot({ path: path.join(os.tmpdir(), "cert-x-workspace-editor.png") });
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await page.getByRole("heading", { name: "Evidence workspace", exact: true }).waitFor();
  let state = await api("state"), workspace = state.workspaces[0]; assert.equal(workspace.pins.length, 2);
  assert.equal(workspace.dastScope.matchMode,'host');assert.equal(workspace.dastScope.includeSubdomains,true);
  const panel = await context.newPage(); panel.on("pageerror", error => errors.push(error.message));
  await panel.goto(base + "/pages/sidepanel.html");
  await panel.getByLabel("Workspace", { exact: true }).waitFor();
  await panel.waitForFunction(() => !document.querySelector('[aria-label="Workspace"]').disabled);
  await panel.getByLabel("Workspace", { exact: true }).selectOption(workspace.id);
  await panel.waitForFunction(id => document.querySelector('[aria-label="Workspace"]').value === id, workspace.id);
  await panel.getByRole("option", { name: "Research", exact: true }).waitFor({ state: "attached" });
  async function send(text) {
    const before = requests.length; await panel.locator(".wb-editor").first().click(); await panel.keyboard.type(text); await panel.keyboard.press("Enter");
    try { await panel.getByText("CONTEXT-OK " + (before + 1), { exact: true }).waitFor(); }
    catch(error) { console.error(JSON.stringify({ modelCalls: requests.length, errors, panel: (await panel.locator('body').innerText()).slice(-7000) })); throw error; }
    await panel.waitForFunction(() => !document.querySelector('[aria-label="Profile"]').disabled); return requests.at(-1);
  }
  let request = await send("Research context proof");
  assert.equal(request.model, "mock/research");
  assert.match(JSON.stringify(request.messages), /WORKSPACE-EVIDENCE/); assert.match(JSON.stringify(request.messages), /notes\.txt/);
  assert.ok(request.tools.some(tool => tool.function.name === "local_read_file"));
  assert.ok(!request.tools.some(tool => tool.function.name === "local_run_command"));
  assert.ok(!request.tools.some(tool => /^(ptk_|security_)/.test(tool.function.name)), "Research does not implicitly enable security testing");
  state = await api("state"); const session = Object.keys(state.chats).find(id => state.chats[id].workspaceId === workspace.id); assert.ok(session);
  // Workspace-specific MCP selection must not discover unrelated servers.
  await worker.evaluate(async origin => chrome.storage.local.set({ ki_mcp_servers: [{ id: "chosen", label: "Chosen", url: origin + "/mcp/chosen" }, { id: "unused", label: "Unused", url: origin + "/mcp/unused" }] }), origin);
  const inventory = await page.evaluate(() => chrome.runtime.sendMessage({ type: "KI_PERMISSIONS", op: "inventory" }));
  const chosen = inventory.result.groups.find(group => group.label === "Chosen"); assert.ok(chosen);
  await api("save_workspace", { workspace: { ...workspace, mcp: [chosen.id] } });
  discoveries.length = 0;
  request = await send("Selected connection proof");
  assert.ok(request.tools.some(tool => tool.function.description.includes("[Chosen]")));
  assert.ok(!request.tools.some(tool => tool.function.description.includes("[Unused]")));
  assert.deepEqual(discoveries, ["/mcp/chosen"]);
  await panel.getByLabel("Profile", { exact: true }).selectOption("coding");
  request = await send("Coding context proof"); assert.ok(request.tools.some(tool => tool.function.name === "local_run_command"));
  const command = request.tools.find(tool => tool.function.name === "local_run_command"); assert.ok(!command.function.parameters.required.includes("cwd"));
  assert.match(JSON.stringify(request.messages), /targeted, maintainable edits/);
  // Missing preference blocks the model call and provides a visible recovery path.
  workspace = (await api("state")).workspaces[0];
  await api("save_workspace", { workspace: { ...workspace, model: { connectionId: "mock", modelId: "missing/model" } } });
  await panel.getByText("Preferred model unavailable. Choose an available model to continue.", { exact: true }).waitFor();
  const beforeMissing = requests.length;
  await panel.locator(".wb-editor").first().click(); await panel.keyboard.type("Must not reach a missing model"); await panel.keyboard.press("Enter");
  await new Promise(resolve => setTimeout(resolve, 400)); assert.equal(requests.length, beforeMissing);
  await panel.locator(".wb-editor").first().fill("");
  await panel.locator(".wb-composer-model .wb-mode-toggle").click();
  await panel.getByRole("menuitemradio").filter({ hasText: "Coding model" }).click();
  // Preserve the existing model-switch flow, including its explicit new-chat confirmation.
  const confirm = panel.getByRole("alertdialog").locator(".wb-btn--primary");
  await confirm.waitFor(); await confirm.click();
  // This Playwright version tests predicate truthiness before awaiting a Promise.
  // Await API reads explicitly instead of passing an async waitForFunction predicate.
  for (let attempt = 0; attempt < 100; attempt++) {
    state = await api("state");
    if (Object.values(state.chats).some(chat => chat.modelExplicit?.modelId === "mock/coding")) break;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  await panel.locator(".wb-model-name").filter({ hasText: "Coding model" }).waitFor();
  await panel.waitForFunction(() => !document.querySelector('[aria-label="Profile"]').disabled);
  state = await api("state"); assert.ok(Object.values(state.chats).some(chat => chat.modelExplicit?.modelId === "mock/coding"));
  const nextSession = Object.keys(state.chats).find(id => state.chats[id].modelExplicit?.modelId === "mock/coding");
  assert.equal(state.chats[nextSession].workspaceId, workspace.id);
  request = await send("Explicit model override proof"); assert.equal(request.model, "mock/coding"); assert.match(JSON.stringify(request.messages), /WORKSPACE-EVIDENCE/);
  assert.ok(!request.tools.some(tool => tool.function.name === "local_run_command"), "New workspace chat inherits Research, not the old chat's Coding override");
  await panel.reload(); await panel.getByLabel("Workspace", { exact: true }).waitFor();
  await panel.waitForFunction(id => document.querySelector('[aria-label="Workspace"]').value === id, workspace.id);
  await panel.getByRole("button", { name: /history/i }).click();
  await panel.getByLabel("Filter chats by workspace").selectOption(workspace.id);
  await panel.waitForFunction(() => document.querySelectorAll(".wb-history-row").length === 2);
  await panel.getByLabel("Filter chats by workspace").selectOption("none");
  await panel.waitForFunction(() => document.querySelectorAll(".wb-history-row").length === 0);
  await panel.getByLabel("Filter chats by workspace").selectOption("all");
  await panel.waitForFunction(() => document.querySelectorAll(".wb-history-row").length === 2);
  await panel.locator(".wb-history-page .wb-settings-back").click();
  await worker.evaluate(async owner => chrome.storage.local.set({ ki_task_outputs: [{ id: "shared-fixture", owner, at: Date.now(), name: "evidence.txt", data: btoa("SHARED-OUTPUT-EVIDENCE"), encoding: "base64", mime: "text/plain", kind: "file" }] }), session);
  await panel.locator(".ki-output-tray > summary").click();
  await panel.locator(".ki-output-scope").getByRole("button", { name: "Workspace", exact: true }).click();
  await panel.locator(".ki-output-row").filter({ hasText: "evidence.txt" }).getByRole("button", { name: "Preview", exact: true }).click();
  await panel.locator(".ki-output-preview").getByText("SHARED-OUTPUT-EVIDENCE", { exact: true }).waitFor();
  await panel.locator(".ki-output-row").filter({ hasText: "evidence.txt" }).getByRole("button", { name: "Use in chat", exact: true }).click();
  request = await send("Use the shared evidence"); assert.match(JSON.stringify(request.messages), /SHARED-OUTPUT-EVIDENCE/);
  await panel.screenshot({ path: path.join(os.tmpdir(), "cert-x-workspace-chat.png") });
  await api("assign_chat", { session, workspaceId: null });
  const aggregated = await page.evaluate(workspaceId => chrome.runtime.sendMessage({ type: "KI_WORKSPACE", op: "outputs", workspaceId }), workspace.id);
  assert.equal(aggregated.result.length, 0); assert.equal((await worker.evaluate(() => chrome.storage.local.get("ki_task_outputs"))).ki_task_outputs.length, 1);
  await api("delete_workspace", { id: workspace.id });
  await panel.waitForFunction(() => document.querySelector('[aria-label="Workspace"]').value === "");
  assert.equal((await api("state")).workspaces.length, 0);
  await panel.getByLabel("Profile", { exact: true }).selectOption("bugbounty");
  await panel.locator(".ki-security-panel > summary").click();
  await panel.getByLabel("Security target page", { exact: true }).waitFor();
  await panel.waitForFunction(() => [...document.querySelectorAll('.ki-security-panel button')].some(button => button.textContent.trim() === 'Start scan' && !button.disabled), null, { timeout: 10000 });
  assert.equal(await panel.locator(".ki-security-panel").getByRole("button", { name: "Start scan", exact: true }).isDisabled(), false);
  request = await send("Native security tool discovery proof");
  const securityNames = request.tools.filter(tool => tool.function.name.startsWith("security_")).map(tool => tool.function.name).sort();
  assert.deepEqual(securityNames, ["security_capabilities","security_list_runs","security_start_scan","security_scan_status","security_stop_scan","security_get_findings","security_get_evidence","security_export_report","security_capture","security_list_requests","security_replay_request","security_macro","security_utility","security_clear_cookie_policy","security_import","security_export","security_candidates","security_evidence_package","security_api","security_browser","security_raw","security_oast","security_zap"].sort());
  assert.ok(!securityNames.includes("security_capture_requests"), "Workspace-scoped request tools should not be advertised without target origins");
  assert.ok(!request.tools.some(tool => tool.function.name.startsWith("ptk_")), "Legacy aliases are callable but not duplicated in model schemas");
  assert.ok(request.tools.find(tool => tool.function.name === "security_start_scan").function.parameters.required.includes("tabId"));
  assert.match(JSON.stringify(request.messages), /security-testing/, "Built-in testing skill is discoverable by the agent");
  assert.equal((await worker.evaluate(() => chrome.storage.local.get("ki_security_runs"))).ki_security_runs?.length || 0, 0, "Profile selection/readiness does not start a scan");
  await panel.setViewportSize({ width: 420, height: 980 });
  assert.ok(await panel.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
  await panel.screenshot({ path: path.join(os.tmpdir(), "cert-x-security-available.png") });
  for (const theme of ["dark", "light"]) {
    await page.goto(base + "/providers/providers.html?section=profiles&theme=" + theme); await page.waitForFunction(() => !document.querySelector("main").inert);
    await page.setViewportSize({ width: 420, height: 900 }); assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
  }
  await open("tools"); await page.getByText("Page controls", { exact: true }).click();
  await page.getByRole("switch", { name: "Unblock CSP", exact: true }).waitFor();
  assert.deepEqual(errors, []);
  const expectedWarnings = warnings.filter(message => /preload|isolated world|execution world/i.test(message));
  assert.deepEqual(warnings.filter(message => !expectedWarnings.includes(message)), []);
  console.log(JSON.stringify({ profiles: true, workspaceContext: true, selectedMcp: true, commandDefault: true, missingModel: true, explicitModel: true, persistence: true, historyFiltering: true, sharedOutputAttachment: true, metadataDeletion: true, responsive: true, cspSettings: true, securityProfileTools: true, nativeSecurityIncluded: true, modelCalls: requests.length, expectedChromiumWarnings: expectedWarnings.length }));
}
main().catch(error => { console.error(error); process.exitCode = 1; }).finally(async () => { await context?.close(); await new Promise(resolve => server ? server.close(resolve) : resolve()); fs.rmSync(temp, { recursive: true, force: true }); });

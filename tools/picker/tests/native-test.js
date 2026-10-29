// Windows end-to-end test: real Chromium native messaging, approvals, files,
// command execution, and stdio MCP. Uses only temp files and mock model traffic.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const { execFileSync } = require("node:child_process");
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || "C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core");
const root = path.resolve(__dirname, "../../..");
const registry = "HKCU\\Software\\Chromium\\NativeMessagingHosts\\com.cert_x.host";
const screenshot = process.env.NATIVE_SCREENSHOT || path.join(os.tmpdir(), "cert-x-native-settings.png");
const temp = fs.mkdtempSync(path.join(os.tmpdir(), "cert-x-native-e2e-"));
const outputFile = path.join(temp, "agent-output.txt"), deniedFile = path.join(temp, "must-not-exist.txt");
const jobFile = path.join(temp, "job-output.txt");
const pdfName = "cert-x-ui-" + path.basename(temp) + ".pdf", downloadPaths = [];
let ctx, llm, registered = false, step = 0, initialTurnWithoutLocalTools = false, modePhase = "approval", backgroundJobId, outputAttached = false;
const results = [], errors = [], warnings = [];
function consoleMessage(message) {
  if (message.type() === "error") errors.push(message.text());
  if (message.type() === "warning") warnings.push(message.text());
}
const steps = [
  { name: "local_run_command", args: { command: "Write-Output 'NATIVE-COMMAND-OK'", cwd: temp } },
  { name: "local_write_file", args: { path: outputFile, content: "NATIVE-FILE-OK" } },
  { name: "local_read_file", args: { path: outputFile } },
  { name: "local_mcp_0_0_echo", args: { text: "NATIVE-MCP-OK" } },
  { name: "local_run_command", args: { command: `Set-Content -LiteralPath '${deniedFile.replaceAll("'", "''")}' -Value 'should not happen'`, cwd: temp } },
  { name: "remote_echo", args: { text: "REMOTE-MCP-OK" } },
];
async function main() {
  // Avoid overwriting a real installation. Chromium test registration is separate
  // from the user's Google Chrome / Edge registration.
  try { execFileSync("reg.exe", ["query", registry], { stdio: "ignore" }); registered = true; } catch {}
  if (registered) { registered = false; throw Error("A Chromium cert-x host is already registered; use a clean test account to preserve it."); }
  llm = http.createServer((req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*"); res.setHeader("Access-Control-Allow-Headers", "*");
    if (req.method === "OPTIONS") return res.end();
    if (req.url === "/favicon.ico") { res.statusCode = 204; return res.end(); }
    if (req.url === "/output-page") { res.setHeader("Content-Type", "text/html"); return res.end("<!doctype html><title>Output fixture</title><h1>Task output fixture</h1><p>PDF and screenshot verification.</p>"); }
    if (req.url.endsWith("/models")) { res.setHeader("Content-Type", "application/json"); return res.end(JSON.stringify({ data: [{ id: "mock/agent", name: "Mock agent", context_length: 128000 }] })); }
    let body = ""; req.on("data", d => body += d);
    req.on("end", () => {
      try {
        const request = JSON.parse(body);
        if (req.url.startsWith("/mcp")) {
          res.setHeader("Content-Type", "application/json");
          const reply = result => res.end(JSON.stringify({ jsonrpc: "2.0", id: request.id, result }));
          if (request.method === "initialize") return reply({ protocolVersion: "2025-03-26", capabilities: { tools: {} }, serverInfo: { name: "remote fixture", version: "1" } });
          if (request.method === "notifications/initialized") { res.statusCode = 202; return res.end(); }
          if (request.method === "tools/list") return reply({ tools: [{ name: "echo", description: "Remote echo", inputSchema: { type: "object", properties: { text: { type: "string" } } } }] });
          if (request.method === "tools/call") return reply({ content: [{ type: "text", text: "echo:" + request.params.arguments.text }] });
          throw Error("Unexpected remote MCP method");
        }
        const names = (request.tools || []).map(t => t.function?.name);
        if (JSON.stringify(request.messages || []).includes("JOB-FILE")) outputAttached = true;
        for (const message of request.messages || []) if (message.role === "tool" && typeof message.content === "string") {
          try { const value = JSON.parse(message.content); if (value.jobId) backgroundJobId = value.jobId; } catch {}
        }
        if (names.length && !names.includes("local_run_command")) initialTurnWithoutLocalTools = true;
        for (const message of request.messages || []) if (message.role === "tool") results.push(JSON.stringify(message.content));
        const phaseSteps = ["approvalAgain", "groupAllow"].includes(modePhase) ? [{ name: "local_list_directory", args: { path: temp } }]
          : modePhase === "features" ? [
            { name: "get_capabilities", args: {} },
            { name: "local_run_command", args: { background: true, cwd: temp, command: `Write-Output 'JOB-START'; Start-Sleep -Seconds 5; Set-Content -LiteralPath '${jobFile}' -Value 'JOB-FILE'; Write-Output 'JOB-DONE'`, outputs: [jobFile] } },
            { name: "local_read_job", args: { job_id: backgroundJobId, cursor: 0 } },
            { name: "local_run_command", args: { background: true, cwd: temp, command: "Write-Output 'STOP-ME'; Start-Sleep -Seconds 30" } },
          ] : modePhase === "artifacts" ? [
            { name: "navigate", args: { url: `http://127.0.0.1:${port}/output-page`, newTab: true } },
            { name: "screenshot", args: {} },
            { name: "save_as_pdf", args: { file_name: pdfName } },
          ] : modePhase === "policy" ? [{ name: "local_read_file", args: { path: outputFile } }] : modePhase === "browser" ? [{ name: "list_browser_tabs", args: {} }] : modePhase === "hidden" ? [] : steps;
        if (modePhase === "hidden" && names.length) assert.equal(names.includes("local_read_file"), false, "Disabled tool must be omitted on the next turn");
        const current = names.includes("local_run_command") ? phaseSteps[step++] : null;
        const completed = { full: "Full access smoke complete.", approvalAgain: "Approval restored.", policy: "Policy override checked.", hidden: "Disabled tool hidden.", groupAllow: "Group default allowed.", browser: "Browser dispatch checked.", features: "Workspace features checked.", artifacts: "Artifact outputs checked." }[modePhase] || "Native smoke complete.";
        const toolName = current?.name === "remote_echo" ? names.find(name => /^mcp_.+_echo$/.test(name)) : current?.name;
        if (current) assert.ok(names.includes(toolName), "Tool must be advertised: " + current.name);
        res.writeHead(200, { "Content-Type": "text/event-stream" });
        const send = value => res.write("data: " + JSON.stringify(value) + "\n\n");
        send({ id: "native-test", object: "chat.completion.chunk", choices: [{ index: 0, delta: current
          ? { role: "assistant", tool_calls: [{ index: 0, id: "native-" + step, type: "function", function: { name: toolName, arguments: JSON.stringify(current.args) } }] }
          : { role: "assistant", content: names.includes("local_run_command") ? completed : "Local tools are disabled." } }] });
        send({ id: "native-test", object: "chat.completion.chunk", choices: [{ index: 0, delta: {}, finish_reason: current ? "tool_calls" : "stop" }] });
        res.end("data: [DONE]\n\n");
      } catch (error) { errors.push(error.message); res.statusCode = 500; res.end(); }
    });
  });
  await new Promise(resolve => llm.listen(0, "127.0.0.1", resolve));
  const port = llm.address().port;
  ctx = await chromium.launchPersistentContext(path.join(temp, "profile"), {
    executablePath: require("../../chromium-path.cjs"),
    headless: true, viewport: { width: 720, height: 900 }, downloadsPath: path.join(temp, "downloads"),
    args: [`--disable-extensions-except=${root}`, `--load-extension=${root}`],
  });
  let [sw] = ctx.serviceWorkers(); if (!sw) sw = await ctx.waitForEvent("serviceworker");
  const id = new URL(sw.url()).host;
  execFileSync("powershell.exe", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path.join(root, "tools/host/install.ps1"), "-ExtensionId", id,
    "-Browser", "Chromium", "-OutputDirectory", path.join(temp, "installed host")], { windowsHide: true, stdio: "pipe" });
  registered = true;
  // A fresh extension's install handler initializes storage asynchronously.
  // Match the existing integration harness: wait until fixture storage survives it.
  for (let attempt = 0; attempt < 8; attempt++) {
    await sw.evaluate(async port => {
      await chrome.storage.local.set({ sidepanel_language: "en", sidepanel_theme: "dark", sidepanel_connections: [{ id: "mock", label: "Mock", presetId: "openrouter", apiKey: "x", host: `http://127.0.0.1:${port}/api/v1` }] });
    }, port);
    await new Promise(resolve => setTimeout(resolve, 1000));
    if (await sw.evaluate(() => chrome.storage.local.get("sidepanel_connections").then(s => s.sidepanel_connections?.length))) break;
  }
  const page = await ctx.newPage(); page.on("pageerror", e => errors.push(e.message));
  page.on("console", consoleMessage);
  await page.goto(`chrome-extension://${id}/providers/providers.html?section=mcp`);
  await page.waitForFunction(() => !document.querySelector("main").inert);
  assert.equal(await page.title(), "MCP servers");
  await page.locator("#mcp-add").click();
  await page.evaluate(() => {
    const original = chrome.runtime.sendMessage.bind(chrome.runtime);
    chrome.runtime.sendMessage = message => message.type === "KI_MCP" && message.op === "test" && message.server.url.endsWith("/reject")
      ? Promise.resolve({ ok: false, error: "Fixture connection rejected" }) : original(message);
  });
  await page.locator("#mcp-url").fill(`http://127.0.0.1:${port}/reject`);
  await page.locator("#mcp-save").click();
  await page.locator("#mcp-status").filter({ hasText: "Fixture connection rejected" }).waitFor();
  assert.equal((await sw.evaluate(() => chrome.storage.local.get("ki_mcp_servers"))).ki_mcp_servers?.length || 0, 0);
  assert.equal(await page.locator("#mcp-form").isVisible(), true);
  await page.locator("#mcp-options > summary").click();
  await page.locator("#mcp-name").fill("Remote fixture");
  await page.locator("#mcp-url").fill(`http://127.0.0.1:${port}/mcp`);
  await page.locator("#mcp-save").click();
  await page.locator("#mcp-list h3", { hasText: "Remote fixture" }).waitFor();
  const localPage = await ctx.newPage();
  localPage.on("pageerror", e => errors.push(e.message)); localPage.on("console", consoleMessage);
  await localPage.goto(`chrome-extension://${id}/providers/providers.html?section=local`);
  await localPage.waitForFunction(() => !document.querySelector("main").inert);
  await localPage.waitForFunction(() => document.getElementById("native-status").textContent === "Connected");
  assert.equal(await localPage.locator("#native-setup").getAttribute("open"), null);
  const panel = await ctx.newPage(); panel.on("pageerror", e => errors.push(e.message));
  panel.on("console", consoleMessage);
  await panel.goto(`chrome-extension://${id}/pages/sidepanel.html`);
  await panel.waitForFunction(() => {
    const button = document.querySelector(".wb-composer-model .wb-mode-toggle");
    return button && !button.disabled;
  });
  await panel.locator(".wb-editor").first().click();
  await panel.keyboard.type("Check local tools before enabling them.");
  await panel.keyboard.press("Enter");
  await panel.getByText("Local tools are disabled.", { exact: true }).first().waitFor();
  assert.equal(initialTurnWithoutLocalTools, true);
  await localPage.locator("#native-enabled").check();
  await localPage.waitForFunction(() => document.getElementById("native-access-status").textContent.startsWith("On ·"));
  assert.equal((await sw.evaluate(() => chrome.storage.local.get("ki_native_settings"))).ki_native_settings.enabled, true);
  await page.locator("#local-add").click();
  await page.locator("#local-command").fill(process.execPath);
  await page.locator("#local-args").fill(path.join(root, "tools/host/tests/fixture-mcp.js"));
  await page.locator("#local-options > summary").click();
  await page.locator("#local-name").fill("Fixture");
  await page.locator("#local-cwd").fill(temp);
  await page.locator("#local-env").fill("invalid entry");
  await page.locator("#local-form button[type=submit]").click();
  await page.locator("#local-status").filter({ hasText: "NAME=value" }).waitFor();
  assert.equal((await sw.evaluate(() => chrome.storage.local.get("ki_native_settings"))).ki_native_settings.servers?.length || 0, 0);
  await page.locator("#local-env").fill("FIXTURE_SETTING=value=with=equals");
  await page.locator("#local-test").click();
  await page.waitForFunction(() => /Connected · 2 tools/.test(document.getElementById("local-status").textContent));
  await page.locator("#local-form button[type=submit]").click();
  await page.locator("#local-list h3", { hasText: "Fixture" }).waitFor();
  await page.locator("#local-list button", { hasText: "Edit" }).click();
  assert.equal(await page.locator("#local-env").inputValue(), "FIXTURE_SETTING=value=with=equals");
  await page.locator("#local-form button[type=submit]").click();
  await page.locator("#local-form").waitFor({ state: "hidden" });
  await localPage.screenshot({ path: screenshot, fullPage: true });
  for (const target of [page, localPage]) {
    await target.setViewportSize({ width: 420, height: 820 });
    assert.ok(await target.evaluate(() => document.documentElement.scrollWidth <= innerWidth), "Settings must fit the side panel");
  }
  // Reuse the exact panel and conversation: no reload or new chat.
  await panel.locator(".wb-editor").first().click();
  await panel.keyboard.type("Run the local integration test tools.");
  await panel.keyboard.press("Enter");
  for (let index = 0; index < steps.length; index++) {
    const match = steps[index].name === "remote_echo" ? "REMOTE-MCP-OK" : steps[index].name.startsWith("local_mcp_") ? "NATIVE-MCP-OK" : steps[index].name;
    const permission = panel.locator(".wb-permission").filter({ hasText: match });
    await permission.waitFor({ timeout: 45000 });
    assert.equal(await permission.locator("button").count(), 2, "Local approvals must not offer a persistent browser grant");
    if (index === 4) await permission.locator("button").first().click();
    else await permission.locator("button").nth(1).click();
    await permission.waitFor({ state: "detached" });
  }
  await panel.getByText("Native smoke complete.", { exact: true }).first().waitFor({ timeout: 45000 });
  assert.equal(await panel.getByText("Check local tools before enabling them.", { exact: true }).count(), 1);
  assert.equal(fs.readFileSync(outputFile, "utf8"), "NATIVE-FILE-OK");
  assert.equal(fs.existsSync(deniedFile), false);
  for (const expected of ["NATIVE-COMMAND-OK", "NATIVE-FILE-OK", "echo:NATIVE-MCP-OK", "echo:REMOTE-MCP-OK", "denied by user"]) assert.ok(results.some(r => r.includes(expected)), expected);
  // Change the actual approval UI, then run the same local tools without a
  // reload. Do not resolve any permission cards during this phase.
  await panel.locator(".wb-approval-toggle").click();
  await panel.getByRole("menuitemradio", { name: /Full access/ }).click();
  const confirm = panel.getByRole("alertdialog");
  await confirm.getByText(/local commands, file operations/).waitFor({ timeout: 10000 });
  await confirm.getByRole("button", { name: "Enable", exact: true }).click();
  await panel.waitForFunction(async () => (await chrome.storage.local.get("sidepanel_approval_mode")).sidepanel_approval_mode === "full_access");
  await panel.evaluate(() => {
    globalThis.nativeApprovalCount = 0;
    globalThis.nativeApprovalObserver = new MutationObserver(() => {
      if (document.querySelector(".wb-permission")) globalThis.nativeApprovalCount++;
    });
    globalThis.nativeApprovalObserver.observe(document.body, { childList: true, subtree: true });
  });
  modePhase = "full"; step = 0; steps[1].args.overwrite = true;
  await panel.locator(".wb-editor").first().click();
  await panel.keyboard.type("Repeat the local tests with Full access.");
  await panel.keyboard.press("Enter");
  await panel.getByText("Full access smoke complete.", { exact: true }).first().waitFor({ timeout: 45000 });
  assert.equal(fs.existsSync(deniedFile), true, "Full access executes the previously denied fixture command");
  assert.equal(await panel.evaluate(() => { globalThis.nativeApprovalObserver.disconnect(); return globalThis.nativeApprovalCount; }), 0);
  modePhase = "features"; step = 0;
  await panel.locator(".wb-editor").first().click(); await panel.keyboard.type("Check capabilities and run a background job."); await panel.keyboard.press("Enter");
  await panel.getByText("Workspace features checked.", { exact: true }).waitFor({ timeout: 30000 });
  assert.ok(backgroundJobId, "Model receives a background job handle");
  await page.locator("summary", { hasText: "Import configuration" }).click();
  await page.locator("#mcp-import-json").fill(JSON.stringify({ mcpServers: {
    duplicate: { url: `http://127.0.0.1:${port}/mcp`, token: "must-not-replace" },
    importedRemote: { url: `http://127.0.0.1:${port}/mcp-import` },
    importedLocal: { command: process.execPath, args: [path.join(root, "tools/host/tests/fixture-mcp.js")], cwd: temp },
    unsupported: { command: "node", disabled: true },
  } }));
  await page.locator("#mcp-import-preview").click();
  assert.equal(await page.locator("#mcp-import-list input:disabled").count(), 1);
  await page.screenshot({ path: path.join(os.tmpdir(), "cert-x-mcp-import.png"), fullPage: true });
  await page.locator("#mcp-import-save").click();
  await page.locator("#mcp-import-status").filter({ hasText: "Added 2 · skipped 1" }).waitFor();
  const imported = await sw.evaluate(() => chrome.storage.local.get(["ki_mcp_servers", "ki_native_settings"]));
  assert.equal(imported.ki_mcp_servers.length, 2); assert.equal(imported.ki_native_settings.servers.length, 2);
  assert.notEqual(imported.ki_mcp_servers[0].token, "must-not-replace");
  await panel.locator(".ki-output-tray > summary").click();
  const jobOutput = panel.locator(".ki-output-row").filter({ hasText: "job-output.txt" });
  await jobOutput.waitFor({ timeout: 15000 });
  await panel.getByText("Background command completed.", { exact: true }).first().waitFor();
  await jobOutput.getByRole("button", { name: "Preview", exact: true }).click();
  await panel.locator(".ki-output-preview pre").filter({ hasText: "JOB-FILE" }).waitFor();
  await panel.screenshot({ path: path.join(os.tmpdir(), "cert-x-task-outputs.png"), fullPage: true });
  await panel.getByRole("button", { name: "Close preview", exact: true }).click();
  const openedFilePromise = ctx.waitForEvent("page");
  await jobOutput.getByRole("button", { name: "Open", exact: true }).click();
  const openedFile = await openedFilePromise;
  await openedFile.waitForURL(/^file:/);
  await openedFile.waitForLoadState("domcontentloaded");
  assert.equal(new URL(openedFile.url()).protocol, "file:");
  assert.match(await openedFile.locator("body").innerText(), /JOB-FILE/);
  await openedFile.close();
  await jobOutput.getByRole("button", { name: "Use in chat", exact: true }).click();
  await localPage.locator("#jobs-section > summary").click();
  const stopJob = localPage.locator("#jobs-list .row").filter({ hasText: "STOP-ME" });
  await stopJob.getByRole("button", { name: "Stop", exact: true }).click();
  await stopJob.filter({ hasText: "cancelled" }).waitFor();
  await localPage.locator("#jobs-list .row").filter({ hasText: "completed" }).first().waitFor();
  await localPage.locator("#jobs-list .row").filter({ hasText: "completed" }).first().getByRole("button", { name: "Output", exact: true }).click();
  await localPage.locator("#job-output").filter({ hasText: "JOB-DONE" }).waitFor();
  await localPage.screenshot({ path: path.join(os.tmpdir(), "cert-x-background-jobs.png"), fullPage: true });
  const health = await ctx.newPage(); health.on("pageerror", error => errors.push(error.message));
  await health.goto(`chrome-extension://${id}/providers/providers.html?section=health`);
  await health.waitForFunction(() => !document.querySelector("main").inert);
  await health.locator("#health-status").filter({ hasText: "Checked" }).waitFor();
  assert.ok((await health.locator("#health-list").innerText()).includes("Ready"));
  await health.screenshot({ path: path.join(os.tmpdir(), "cert-x-capability-health.png"), fullPage: true });
  modePhase = "artifacts"; step = 0;
  await panel.locator(".wb-editor").first().click(); await panel.keyboard.type("Create a PDF and screenshot of the fixture page."); await panel.keyboard.press("Enter");
  await panel.getByText("Artifact outputs checked.", { exact: true }).waitFor({ timeout: 45000 });
  if (!(await panel.locator(".ki-output-tray").evaluate(element => element.open))) await panel.locator(".ki-output-tray > summary").click();
  await panel.locator(".ki-output-row").filter({ hasText: "Screenshot." }).waitFor();
  await panel.locator(".ki-output-row").filter({ hasText: pdfName }).waitFor();
  const savedPdf = await sw.evaluate(async name => (await chrome.storage.local.get("ki_task_outputs")).ki_task_outputs.find(item => item.name === name), pdfName);
  assert.ok(savedPdf?.downloadId); downloadPaths.push(savedPdf.path);
  assert.equal(fs.readFileSync(savedPdf.path).subarray(0, 4).toString(), "%PDF");
  modePhase = "browser"; step = 0;
  await panel.locator(".wb-editor").first().click(); await panel.keyboard.type("Verify the browser tool dispatcher."); await panel.keyboard.press("Enter");
  await panel.getByText("Browser dispatch checked.", { exact: true }).waitFor();
  assert.equal(results.some(result => /Missing tool permission context|Tool list_browser_tabs failed|list_browser_tabs failed/.test(result)), false);
  const permissions = await ctx.newPage(); permissions.on("pageerror", e => errors.push(e.message));
  await permissions.goto(`chrome-extension://${id}/providers/providers.html?section=tools`);
  await permissions.waitForFunction(() => !document.querySelector("main").inert);
  await permissions.getByLabel("Search tools").fill("local_read_file");
  await permissions.getByLabel("Read files permission", { exact: true }).selectOption("ask");
  await permissions.locator("#permissions-status").filter({ hasText: "Saved" }).waitFor();
  await panel.locator(".wb-approval-toggle").filter({ hasText: "Overrides" }).waitFor();
  modePhase = "policy"; step = 0;
  await panel.locator(".wb-editor").first().click(); await panel.keyboard.type("Check Always ask in Full access."); await panel.keyboard.press("Enter");
  const explicitPermission = panel.locator(".wb-permission").filter({ hasText: "local_read_file" });
  await explicitPermission.waitFor();
  // The old Full access effect auto-approved every pending card. Explicit
  // Always ask must survive switching out of Full access and back into it.
  await panel.locator(".wb-approval-toggle").click();
  await panel.getByRole("menuitemradio", { name: /Requires approval/ }).click();
  await panel.locator(".wb-approval-toggle").click();
  await panel.getByRole("menuitemradio", { name: /Full access/ }).click();
  await panel.getByRole("alertdialog").getByRole("button", { name: "Enable", exact: true }).click();
  await panel.waitForFunction(async () => (await chrome.storage.local.get("sidepanel_approval_mode")).sidepanel_approval_mode === "full_access");
  assert.equal(await explicitPermission.isVisible(), true);
  await permissions.getByLabel("Read files permission", { exact: true }).selectOption("disabled");
  await permissions.locator("#permissions-status").filter({ hasText: "Saved" }).waitFor();
  await explicitPermission.getByRole("button").nth(1).click();
  await panel.getByText("Policy override checked.", { exact: true }).waitFor();
  assert.equal(outputAttached, true, "Use in chat adds output contents to the next model request");
  assert.ok(results.some(result => result.includes("disabled in Tools & permissions")));
  modePhase = "hidden"; step = 0;
  await panel.locator(".wb-editor").first().click(); await panel.keyboard.type("Check the updated tool list."); await panel.keyboard.press("Enter");
  await panel.getByText("Disabled tool hidden.", { exact: true }).waitFor();
  const resetPermissions = async () => {
    await permissions.getByRole("button", { name: "Reset defaults", exact: true }).click();
    await permissions.getByRole("dialog").getByRole("button", { name: "Reset defaults", exact: true }).click();
    await permissions.locator("#permissions-status").filter({ hasText: "Defaults restored" }).waitFor();
  };
  await resetPermissions();
  await panel.locator(".wb-approval-toggle").click();
  await panel.getByRole("menuitemradio", { name: /Requires approval/ }).click();
  await panel.waitForFunction(async () => (await chrome.storage.local.get("sidepanel_approval_mode")).sidepanel_approval_mode === "approve_for_me");
  await permissions.getByLabel("Search tools").fill("");
  await permissions.getByLabel("Local computer permission", { exact: true }).selectOption("allow");
  await permissions.locator("#permissions-status").filter({ hasText: "Saved" }).waitFor();
  modePhase = "groupAllow"; step = 0;
  await panel.locator(".wb-editor").first().click(); await panel.keyboard.type("Check the Allow group default."); await panel.keyboard.press("Enter");
  await panel.getByText("Group default allowed.", { exact: true }).waitFor();
  assert.equal(await panel.locator(".wb-permission").count(), 0);
  await resetPermissions();
  modePhase = "approvalAgain"; step = 0;
  await panel.locator(".wb-editor").first().click();
  await panel.keyboard.type("Verify approval is required again.");
  await panel.keyboard.press("Enter");
  const restoredPermission = panel.locator(".wb-permission").filter({ hasText: "local_list_directory" });
  await restoredPermission.waitFor({ timeout: 45000 });
  await restoredPermission.locator("button").first().click();
  await panel.getByText("Approval restored.", { exact: true }).first().waitFor();
  // Verify the actual settings entry points and embedded routing, including
  // leaving/reopening Settings so message listeners cannot retain stale state.
  await panel.locator(".wb-topnav-settings > button").click();
  const standardSwitchSize = await panel.locator(".wb-toggle--sm").first().evaluate(element => [element.offsetWidth, element.offsetHeight]);
  const settingsRows = panel.locator(".wb-set-navrow");
  assert.equal(await settingsRows.filter({ hasText: "Browser control" }).count(), 1);
  assert.equal(await panel.getByText("Remote control", { exact: true }).count(), 0);
  await settingsRows.filter({ hasText: "MCP servers" }).click();
  let frame = panel.frameLocator(".wb-models-frame");
  await frame.locator("#mcp-add").waitFor();
  assert.equal(await frame.locator("#models-panel").isVisible(), false);
  assert.equal(await frame.locator("#native-section").isVisible(), false);
  await panel.screenshot({ path: path.join(os.tmpdir(), "cert-x-mcp-settings.png"), fullPage: true });
  await panel.locator(".wb-settings-back").click();
  await settingsRows.filter({ hasText: "Local computer" }).click();
  frame = panel.frameLocator(".wb-models-frame");
  await frame.locator("#native-status").filter({ hasText: "Connected" }).waitFor();
  assert.deepEqual(await frame.locator("#native-enabled").evaluate(element => [element.offsetWidth, element.offsetHeight]), standardSwitchSize);
  assert.equal(await frame.locator("#mcp").isVisible(), false);
  assert.equal(await frame.locator("#native-setup").getAttribute("open"), null);
  await frame.getByRole("link", { name: /Manage MCP servers/ }).click();
  await panel.locator(".wb-settings-title").filter({ hasText: "MCP servers" }).waitFor();
  await panel.frameLocator(".wb-models-frame").locator("#mcp-add").waitFor();
  await panel.locator(".wb-settings-back").click();
  await settingsRows.filter({ hasText: "Models" }).click();
  frame = panel.frameLocator(".wb-models-frame");
  await frame.locator("#saved").waitFor();
  assert.equal(await frame.locator("#mcp").isVisible(), false);
  await panel.locator(".wb-settings-back").click();
  await panel.setViewportSize({ width: 420, height: 820 });
  await panel.screenshot({ path: path.join(os.tmpdir(), "cert-x-settings-home.png"), fullPage: true });
  await panel.locator(".wb-settings-back").click();
  await panel.locator(".wb-topnav-settings > button").click();
  await settingsRows.filter({ hasText: "Local computer" }).click();
  await panel.frameLocator(".wb-models-frame").getByRole("link", { name: /Manage MCP servers/ }).click();
  await panel.locator(".wb-settings-title").filter({ hasText: "MCP servers" }).waitFor();
  assert.ok(await panel.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
  await localPage.locator("#native-enabled").uncheck();
  await localPage.waitForFunction(() => document.getElementById("native-access-status").textContent.startsWith("Off ·"));
  assert.equal((await sw.evaluate(() => chrome.storage.local.get("ki_native_settings"))).ki_native_settings.enabled, false);
  assert.deepEqual(errors, []);
  // Existing modulepreload tags produce cross-world mismatch warnings, followed
  // by unused-preload warnings once a test spans multiple turns. Modules load
  // normally; fail on any other warning and report these existing ones.
  const knownPreloadWarning = message => /^A preload for 'chrome-extension:\/\/[^']+' is found, but is not used because it is a cross-world extension resource mismatch\.$/.test(message)
    || /^The resource chrome-extension:\/\/[^ ]+\/chunks\/[^ ]+\.js was preloaded using link preload but not used within a few seconds from the window's load event\. Please make sure it has an appropriate `as` value and it is preloaded intentionally\.$/.test(message);
  assert.deepEqual(warnings.filter(message => !knownPreloadWarning(message)), []);
  console.log(JSON.stringify({ passed: true, sameConversationEnable: true, fullAccessWithoutPrompts: true, approvalRestored: true, extensionId: id, viewport: [720, 420], steps: steps.length, existingPreloadWarnings: warnings.length, screenshot }));
}
main().catch(error => { console.error(error); process.exitCode = 1; }).finally(async () => {
  if (ctx?.serviceWorkers()[0]) {
    try {
      const downloads = await ctx.serviceWorkers()[0].evaluate(name => chrome.downloads.search({ query: [name] }), pdfName);
      for (const download of downloads) if (path.basename(download.filename).startsWith("cert-x-ui-" + path.basename(temp))) downloadPaths.push(download.filename);
    } catch {}
  }
  await ctx?.close();
  if (llm) await new Promise(resolve => llm.close(resolve));
  if (registered) execFileSync("reg.exe", ["delete", registry, "/f"], { windowsHide: true, stdio: "ignore" });
  for (const file of downloadPaths) if (fs.existsSync(file) && (path.resolve(file).startsWith(path.resolve(temp) + path.sep) || path.basename(file).startsWith("cert-x-ui-" + path.basename(temp)))) fs.unlinkSync(file);
  // temp is created by this test under os.tmpdir; never remove a user path.
  fs.rmSync(temp, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
});

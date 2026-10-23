const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const http = require("node:http");
const playwrightPath = process.env.PLAYWRIGHT_MODULE || "C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core";
const { chromium } = require(playwrightPath);
const { wsServer } = require(path.join(playwrightPath, "lib/utilsBundle.js"));
const root = path.resolve(__dirname, "../../..");
const directory = fs.mkdtempSync(path.join(os.tmpdir(), "cert-x-browser-control-"));
let context, server, websocket, mode = "valid", connections = 0, active;
const responses = new Map(), errors = [];
async function main() {
  server = http.createServer((req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ running: true, version: "2.0.24", name: "Fixture controller" }));
  });
  websocket = new wsServer({ server });
  websocket.on("connection", socket => {
    connections++; active = socket;
    if (mode === "busy") { socket.close(4409, "Already in use"); return; }
    socket.on("message", data => {
      const message = JSON.parse(data);
      if (message.type === "hello") {
        socket.send(JSON.stringify({ type: "tool_call", requestId: "early", payload: { name: "list_browser_tabs", args: {} } }));
        socket.send(JSON.stringify({ type: "hello_ack", payload: { daemonVersion: mode === "mismatch" ? "99.0.0" : "2.0.24", name: "Fixture controller" } }));
      } else if (message.type === "ping") socket.send(JSON.stringify({ type: "pong" }));
      else if (message.type === "tool_result") responses.set(message.responseToRequestId, message.payload);
    });
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const address = `ws://127.0.0.1:${server.address().port}/ws`;
  context = await chromium.launchPersistentContext(path.join(directory, "profile"), {
    executablePath: process.env.CHROMIUM_PATH || path.join(process.env.LOCALAPPDATA, "ms-playwright/chromium-1234/chrome-win64/chrome.exe"),
    headless: true, viewport: { width: 720, height: 900 }, args: [`--disable-extensions-except=${root}`, `--load-extension=${root}`],
  });
  let [worker] = context.serviceWorkers(); if (!worker) worker = await context.waitForEvent("serviceworker");
  const id = new URL(worker.url()).host;
  await worker.evaluate(() => chrome.storage.local.set({ sidepanel_language: "en", sidepanel_theme: "dark" }));
  const page = await context.newPage(); page.on("pageerror", error => errors.push(error.message));
  await page.goto(`chrome-extension://${id}/providers/providers.html?section=browser`);
  await page.waitForFunction(() => !document.querySelector("main").inert);
  assert.equal(await page.title(), "Browser control");
  await page.locator("#browser-status").filter({ hasText: "Not connected" }).waitFor();
  await page.locator("#browser-advanced > summary").click();
  await page.locator("#browser-url").fill(address);
  await page.locator("#browser-connect").click();
  await page.getByRole("dialog").waitFor(); assert.equal(connections, 0);
  await page.locator("#browser-cancel").click(); assert.equal(connections, 0);
  const connect = async () => {
    await page.locator("#browser-connect").click();
    await page.locator("#browser-allow").click();
  };
  await connect();
  await page.waitForFunction(() => document.getElementById("browser-status").textContent === "Connected");
  assert.match(await page.locator("#browser-controller").innerText(), /Fixture controller 2.0.24/);
  assert.match(responses.get("early")?.error, /not authorized and verified/);
  active.send(JSON.stringify({ type: "tool_call", requestId: "verified", payload: { name: "list_browser_tabs", args: {} } }));
  for (let i = 0; i < 100 && !responses.has("verified"); i++) await new Promise(resolve => setTimeout(resolve, 20));
  assert.ok(Object.hasOwn(responses.get("verified") || {}, "data"));
  const permissions = await context.newPage(); permissions.on("pageerror", error => errors.push(error.message));
  await permissions.goto(`chrome-extension://${id}/providers/providers.html?section=tools`);
  await permissions.waitForFunction(() => !document.querySelector("main").inert);
  await permissions.getByLabel("Browser permission", { exact: true }).selectOption("disabled");
  await permissions.locator("#permissions-status").filter({ hasText: "Saved" }).waitFor();
  await permissions.reload();
  assert.equal(await permissions.getByLabel("Browser permission", { exact: true }).inputValue(), "disabled");
  const toolCall = async id => {
    active.send(JSON.stringify({ type: "tool_call", requestId: id, payload: { name: "list_browser_tabs", args: {} } }));
  };
  const result = async id => {
    for (let i = 0; i < 150 && !responses.has(id); i++) await new Promise(resolve => setTimeout(resolve, 20));
    assert.ok(responses.has(id)); return responses.get(id);
  };
  await toolCall("disabled"); assert.match((await result("disabled")).error, /disabled/);
  await permissions.getByLabel("Search tools").fill("list_browser_tabs");
  await permissions.getByLabel("List browser tabs permission", { exact: true }).selectOption("allow");
  await permissions.locator("#permissions-status").filter({ hasText: "Saved" }).waitFor();
  await toolCall("allowed-override"); assert.ok(Object.hasOwn(await result("allowed-override"), "data"));
  await permissions.getByLabel("List browser tabs permission", { exact: true }).selectOption("ask");
  await permissions.locator("#permissions-status").filter({ hasText: "Saved" }).waitFor();
  await worker.evaluate(() => chrome.storage.local.set({ sidepanel_approval_mode: "full_access" }));
  await toolCall("ask-denied");
  await permissions.locator("#permissions-section .tool-approval-requests").getByRole("button", { name: "Deny", exact: true }).click();
  assert.match((await result("ask-denied")).error, /denied/);
  await toolCall("ask-allowed");
  await page.waitForFunction(async () => (await chrome.runtime.sendMessage({ type: "KI_PERMISSIONS", op: "pending" })).result.length === 1);
  const pendingId = await page.evaluate(async () => (await chrome.runtime.sendMessage({ type: "KI_PERMISSIONS", op: "pending" })).result[0].id);
  await page.locator(`[data-approval-id="${pendingId}"]`).getByRole("button", { name: "Allow once", exact: true }).click();
  assert.ok(Object.hasOwn(await result("ask-allowed"), "data"));
  await permissions.locator("#permissions-section .tool-approval-requests").waitFor({ state: "hidden" });
  await permissions.getByLabel("Search tools").fill("");
  await permissions.locator("#permissions-groups details").evaluateAll(elements => elements.forEach(element => { element.open = false; }));
  await permissions.setViewportSize({ width: 420, height: 820 });
  assert.ok(await permissions.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
  await permissions.screenshot({ path: path.join(os.tmpdir(), "cert-x-tool-permissions.png"), fullPage: true });
  await permissions.getByRole("button", { name: "Reset defaults", exact: true }).click();
  await permissions.getByRole("dialog").getByRole("button", { name: "Reset defaults", exact: true }).click();
  await permissions.locator("#permissions-status").filter({ hasText: "Defaults restored" }).waitFor();
  assert.equal(await permissions.getByLabel("Browser permission", { exact: true }).inputValue(), "inherit");
  await page.locator("#browser-advanced > summary").click();
  await page.screenshot({ path: path.join(os.tmpdir(), "cert-x-browser-control.png"), fullPage: true });
  await page.locator("#browser-connect").click();
  assert.notEqual(await page.locator("#browser-advanced").getAttribute("open"), null);
  assert.equal(await page.getByRole("dialog").isVisible(), false);
  assert.equal(connections, 1);
  await page.locator("#browser-disconnect").click();
  await page.waitForFunction(async () => (await chrome.storage.local.get("ws_should_connect")).ws_should_connect === false);
  assert.equal((await worker.evaluate(() => chrome.storage.local.get("ki_browser_control_grant"))).ki_browser_control_grant, null);
  await page.evaluate(() => chrome.runtime.sendMessage({ type: "RECONCILE_NOW" }));
  assert.equal(connections, 1);
  mode = "busy"; await connect();
  await page.locator("#browser-error").filter({ hasText: "another browser" }).waitFor();
  await page.locator("#browser-disconnect").click();
  await page.locator("#browser-disconnect").waitFor({ state: "hidden" });
  mode = "mismatch"; await connect();
  await page.locator("#browser-error").filter({ hasText: "versions do not match" }).waitFor();
  assert.notEqual(await page.locator("#browser-status").innerText(), "Connected");
  await page.locator("#browser-disconnect").click();
  await page.locator("#browser-disconnect").waitFor({ state: "hidden" });
  await page.setViewportSize({ width: 420, height: 820 });
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
  assert.deepEqual(errors, []);
  console.log(JSON.stringify({ passed: true, connectAndAuthorize: true, handshakeGate: true, disconnectRevokes: true, busyAndMismatchStates: true, viewports: [720, 420] }));
}
main().catch(error => { console.error(error); process.exitCode = 1; }).finally(async () => {
  await context?.close();
  for (const client of websocket?.clients || []) client.terminate();
  if (websocket) await new Promise(resolve => websocket.close(resolve));
  if (server) await new Promise(resolve => server.close(resolve));
  fs.rmSync(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
});

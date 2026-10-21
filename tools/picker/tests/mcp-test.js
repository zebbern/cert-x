const http = require("http");
const path = require("path");
const os = require("os");
const fs = require("fs");
const { chromium } = require("C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core");

const ext = path.join(__dirname, "..", "..", "..");
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
let advertised = null;
let toolResult = null;
let called = false;

const mcp = http.createServer((req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "*");
  if (req.method === "OPTIONS") return res.end();
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    const msg = JSON.parse(body || "{}");
    res.setHeader("Content-Type", "application/json");
    if (msg.method === "initialize") {
      res.setHeader("mcp-session-id", "sess-1");
      return res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-03-26", capabilities: { tools: {} }, serverInfo: { name: "mock", version: "0" } } }));
    }
    if (msg.method === "notifications/initialized") {
      res.statusCode = 202;
      return res.end();
    }
    if (req.headers["mcp-session-id"] !== "sess-1") {
      return res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, error: { code: -32000, message: "missing session" } }));
    }
    if (msg.method === "tools/list") {
      return res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { tools: [{ name: "echo", description: "Echo the text back", inputSchema: { type: "object", properties: { text: { type: "string" } }, required: ["text"] } }] } }));
    }
    if (msg.method === "tools/call") {
      return res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: "echo:" + ((msg.params && msg.params.arguments && msg.params.arguments.text) || "") }] } }));
    }
    res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: "nope" } }));
  });
});

const llm = http.createServer((req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "*");
  if (req.method === "OPTIONS") return res.end();
  if (req.url.endsWith("/models")) {
    res.setHeader("Content-Type", "application/json");
    return res.end(JSON.stringify({ data: [{ id: "mock/agent", name: "Mock: Agent", context_length: 128000 }] }));
  }
  if (req.method === "POST" && req.url.endsWith("/chat/completions")) {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", async () => {
      const j = JSON.parse(body);
      const names = (j.tools || []).map((t) => t.function && t.function.name).filter(Boolean);
      const echo = names.find((n) => /mcp_.+_echo$/.test(n));
      if (names.length && !advertised) advertised = names;
      for (const m of j.messages || []) {
        const c = typeof m.content === "string" ? m.content : JSON.stringify(m.content || "");
        if (m.role === "tool" && c.includes("echo:")) toolResult = c;
      }
      res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache" });
      const send = (o) => res.write(`data: ${JSON.stringify(o)}\n\n`);
      await wait(300);
      if (echo && !called) {
        called = true;
        send({ id: "m", object: "chat.completion.chunk", choices: [{ index: 0, delta: { role: "assistant", content: null, tool_calls: [{ index: 0, id: "c1", type: "function", function: { name: echo, arguments: JSON.stringify({ text: "ping" }) } }] } }] });
        send({ id: "m", object: "chat.completion.chunk", choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }] });
      } else {
        send({ id: "m", object: "chat.completion.chunk", choices: [{ index: 0, delta: { role: "assistant", content: "Done." } }] });
        send({ id: "m", object: "chat.completion.chunk", choices: [{ index: 0, delta: {}, finish_reason: "stop" }], usage: { prompt_tokens: 5, completion_tokens: 1, total_tokens: 6 } });
      }
      res.write("data: [DONE]\n\n");
      res.end();
    });
    return;
  }
  res.statusCode = 404;
  res.end();
});

async function main() {
  await new Promise((r) => mcp.listen(8791, "127.0.0.1", r));
  await new Promise((r) => llm.listen(8788, "127.0.0.1", r));
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "ki-ui-"));
  const ctx = await chromium.launchPersistentContext(profile, {
    executablePath: path.join(process.env.LOCALAPPDATA, "ms-playwright/chromium-1234/chrome-win64/chrome.exe"),
    headless: false,
    viewport: { width: 720, height: 900 },
    colorScheme: "dark",
    args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`],
  });
  let [sw] = ctx.serviceWorkers();
  if (!sw) sw = await ctx.waitForEvent("serviceworker");
  const id = new URL(sw.url()).host;
  await wait(1500);
  const page = await ctx.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  await page.goto(`chrome-extension://${id}/providers/providers.html`);
  await page.locator("#mcp-heading").waitFor();
  console.log("section:", await page.locator("#mcp-heading").innerText(), "|", (await page.locator("#mcp-note").innerText()).slice(0, 48));
  await page.locator("#mcp-add").click();
  await page.locator("#mcp-name").fill("Mock");
  await page.locator("#mcp-url").fill("http://127.0.0.1:8791/mcp");
  await page.locator("#mcp-test").click();
  await page.waitForFunction(() => /Tools: echo/.test(document.getElementById("mcp-status").textContent || ""));
  const testStatus = await page.locator("#mcp-status").innerText();
  console.log("test connection:", testStatus);
  await page.locator("#mcp-save").click();
  await page.locator("#mcp-list h3", { hasText: "Mock" }).waitFor();
  const stored = await sw.evaluate(() => chrome.storage.local.get("ki_mcp_servers"));
  console.log("stored:", JSON.stringify((stored.ki_mcp_servers || []).map((s) => ({ id: s.id, label: s.label, url: s.url }))));

  for (let i = 0; i < 8; i++) {
    await sw.evaluate(() => chrome.storage.local.set({ sidepanel_connections: [{ id: "mock", label: "Mock", presetId: "openrouter", apiKey: "x", host: "http://127.0.0.1:8788/api/v1" }] }));
    await wait(700);
    if (await sw.evaluate(() => chrome.storage.local.get("sidepanel_connections").then((s) => (s.sidepanel_connections || []).length))) break;
  }
  const panel = await ctx.newPage();
  panel.on("pageerror", (e) => errors.push(String(e)));
  await panel.goto(`chrome-extension://${id}/pages/sidepanel.html`);
  await panel.waitForTimeout(2500);
  const pill = panel.locator(".wb-composer-model .wb-mode-toggle");
  for (let i = 0; i < 15 && (await pill.isDisabled()); i++) await panel.waitForTimeout(1000);
  await panel.locator(".wb-editor").first().click();
  await panel.keyboard.type("Use the mock echo tool.");
  await panel.keyboard.press("Enter");
  for (let i = 0; i < 40 && !toolResult; i++) await wait(500);

  console.log("echo tool advertised:", (advertised || []).filter((n) => /mcp_/.test(n)).join(", ") || "NO");
  console.log("tool result:", toolResult ? JSON.stringify(toolResult.slice(0, 180)) : "NONE");
  console.log("errors:", errors.length ? errors : "none");
  await ctx.close();
  mcp.close();
  llm.close();
  process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });

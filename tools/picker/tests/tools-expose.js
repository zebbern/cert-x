// Verifies the newly exposed daemon tools are (1) advertised to the model in the
// chat `tools` array and (2) actually executable end-to-end via the model path,
// using list_browser_tabs (read_page => auto-allowed, needs no working tab).
const http = require("http");
const path = require("path");
const os = require("os");
const fs = require("fs");
const { chromium } = require("C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core");

const ext = path.join(__dirname, "..", "..", "..");
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const EXPECT = ["list_browser_tabs", "attach_tab", "activate_tab", "set_checked", "cdp", "inspect_region", "highlight_region", "clear_highlight", "save_file", "browse"];

let advertised = null;
let toolsFull = null;
let toolResult = null;
let calledTool = false;
// browse is advertised because the seeded OpenRouter connection is a decision backend.
const TAB_YES = ["cdp", "set_checked", "inspect_region", "highlight_region", "clear_highlight", "browse"];
const TAB_NO = ["list_browser_tabs", "attach_tab", "activate_tab", "save_file"];

const server = http.createServer((req, res) => {
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
      if (names.length && !advertised) { advertised = names; toolsFull = j.tools; }
      // capture any tool-result message that carries our list_browser_tabs output
      for (const m of j.messages || []) {
        const c = typeof m.content === "string" ? m.content : JSON.stringify(m.content || "");
        if (m.role === "tool" && /"tabs"/.test(c)) toolResult = c.slice(0, 160);
      }
      res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache" });
      const send = (o) => res.write(`data: ${JSON.stringify(o)}\n\n`);
      await wait(300);
      if (names.includes("list_browser_tabs") && !calledTool) {
        calledTool = true;
        send({ id: "m", object: "chat.completion.chunk", choices: [{ index: 0, delta: { role: "assistant", content: null, tool_calls: [{ index: 0, id: "call_1", type: "function", function: { name: "list_browser_tabs", arguments: "{}" } }] } }] });
        send({ id: "m", object: "chat.completion.chunk", choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }] });
      } else {
        send({ id: "m", object: "chat.completion.chunk", choices: [{ index: 0, delta: { role: "assistant", content: "Done." } }] });
        send({ id: "m", object: "chat.completion.chunk", choices: [{ index: 0, delta: {}, finish_reason: "stop" }], usage: { prompt_tokens: 10, completion_tokens: 2, total_tokens: 12 } });
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
  await new Promise((r) => server.listen(8788, "127.0.0.1", r));
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "ki-ui-"));
  const ctx = await chromium.launchPersistentContext(profile, {
    executablePath: path.join(process.env.LOCALAPPDATA, "ms-playwright/chromium-1234/chrome-win64/chrome.exe"),
    headless: false,
    viewport: { width: 560, height: 820 },
    colorScheme: "dark",
    args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`],
  });
  let [sw] = ctx.serviceWorkers();
  if (!sw) sw = await ctx.waitForEvent("serviceworker");
  const id = new URL(sw.url()).host;
  await wait(2000);
  for (let i = 0; i < 10; i++) {
    await sw.evaluate(() => chrome.storage.local.set({ sidepanel_connections: [{ id: "mock", label: "Mock", presetId: "openrouter", apiKey: "x", host: "http://127.0.0.1:8788/api/v1" }] }));
    await wait(1000);
    if (await sw.evaluate(() => chrome.storage.local.get("sidepanel_connections").then((s) => (s.sidepanel_connections || []).length))) break;
  }
  const page = await ctx.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  await page.goto(`chrome-extension://${id}/pages/sidepanel.html`);
  await page.waitForTimeout(2500);
  for (const p of ctx.pages()) if (p !== page) await p.close().catch(() => {});
  await page.reload();
  await page.waitForTimeout(2000);
  const pill = page.locator(".wb-composer-model .wb-mode-toggle");
  for (let i = 0; i < 15 && (await pill.isDisabled()); i++) await page.waitForTimeout(1000);
  await page.locator(".wb-editor").first().click();
  await page.keyboard.type("List all my browser tabs.");
  await page.keyboard.press("Enter");
  for (let i = 0; i < 30 && !toolResult; i++) await wait(500);
  await wait(1000);

  const missing = EXPECT.filter((n) => !(advertised || []).includes(n));
  console.log("tools advertised to model:", advertised ? advertised.length : 0);
  console.log("new tools present:", missing.length === 0 ? "ALL " + EXPECT.length + " OK" : "MISSING " + missing.join(", "));
  console.log("list_browser_tabs executed & round-tripped:", toolResult ? "YES -> " + JSON.stringify(toolResult) : "NO");
  const hasTab = (n) => {
    const t = (toolsFull || []).find((x) => x.function && x.function.name === n);
    return !!(t && t.function.parameters && t.function.parameters.properties && t.function.parameters.properties.tab);
  };
  const yesOk = TAB_YES.filter(hasTab);
  const noBad = TAB_NO.filter(hasTab);
  console.log("tab arg present on working-tab tools:", yesOk.length === TAB_YES.length ? "ALL " + TAB_YES.length + " OK" : "MISSING " + TAB_YES.filter((n) => !hasTab(n)).join(", "));
  console.log("tab arg correctly absent on tab-mgmt tools:", noBad.length === 0 ? "OK" : "WRONGLY PRESENT " + noBad.join(", "));
  console.log("errors:", errors.length ? errors : "none");
  await ctx.close();
  server.close();
  process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });

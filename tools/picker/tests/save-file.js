// Verifies save_file is advertised and writes the given bytes into Downloads.
const http = require("http");
const path = require("path");
const os = require("os");
const fs = require("fs");
const { chromium } = require("C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core");

const ext = path.join(__dirname, "..", "..", "..");
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const TOKEN = "SAVE-FILE-TOKEN-" + Date.now();
const NAME = "ki-save-file-test-" + Date.now() + ".txt";

let called = false;
let result = null;
let advertised = false;

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
      const names = (j.tools || []).map((t) => t.function && t.function.name);
      if (names.includes("save_file")) advertised = true;
      for (const m of j.messages || []) {
        const c = typeof m.content === "string" ? m.content : JSON.stringify(m.content || "");
        if (m.role === "tool" && /downloadId|save_file/.test(c)) result = c;
      }
      res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache" });
      const send = (o) => res.write(`data: ${JSON.stringify(o)}\n\n`);
      await wait(300);
      if (names.includes("save_file") && !called) {
        called = true;
        send({ id: "m", object: "chat.completion.chunk", choices: [{ index: 0, delta: { role: "assistant", content: null, tool_calls: [{ index: 0, id: "c1", type: "function", function: { name: "save_file", arguments: JSON.stringify({ filename: NAME, content: TOKEN }) } }] } }] });
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
  await new Promise((r) => server.listen(8788, "127.0.0.1", r));
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "ki-ui-"));
  const ctx = await chromium.launchPersistentContext(profile, {
    executablePath: require("../../chromium-path.cjs"),
    headless: false,
    viewport: { width: 560, height: 820 },
    colorScheme: "dark",
    acceptDownloads: true,
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
  await page.keyboard.type("Save a short file into Downloads.");
  await page.keyboard.press("Enter");
  for (let i = 0; i < 40 && !result; i++) await wait(500);
  await wait(800);

  let parsed = null;
  try { parsed = JSON.parse(result); } catch {}
  const filePath = parsed && parsed.filename;
  let onDisk = "";
  if (filePath && fs.existsSync(filePath)) {
    onDisk = fs.readFileSync(filePath, "utf8");
    fs.unlinkSync(filePath);
  }
  console.log("save_file advertised:", advertised ? "YES" : "NO");
  console.log("tool result:", result ? JSON.stringify(parsed) : "NONE");
  console.log("file on disk matches token:", onDisk === TOKEN ? "EXACT MATCH" : "NO (" + JSON.stringify(onDisk.slice(0, 80)) + ")");
  console.log("errors:", errors.length ? errors : "none");
  await ctx.close();
  server.close();
  process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });

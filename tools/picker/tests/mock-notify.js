const http = require("http");
const path = require("path");
const os = require("os");
const fs = require("fs");
const { chromium } = require("C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core");

const ext = path.join(__dirname, "..", "..", "..");
const shots = path.join(__dirname, "shots");
fs.mkdirSync(shots, { recursive: true });
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const ANSWER = "You have **3 tabs** open:\n\n- `zebbern` (this panel)\n- [GitHub](https://github.com) pull requests\n- Gmail inbox\n\nWant me to close any of them?";
let n = 0;

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
      const tool = (j.tools || []).map((t) => t.function?.name).find((x) => /list_tabs/.test(x || ""));
      const k = ++n;
      res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache" });
      const send = (o) => res.write(`data: ${JSON.stringify(o)}\n\n`);
      await wait(700);
      if (k <= 3 && tool) {
        send({ id: "m" + k, object: "chat.completion.chunk", choices: [{ index: 0, delta: { role: "assistant", content: null, tool_calls: [{ index: 0, id: "call_" + k, type: "function", function: { name: tool, arguments: "{}" } }] } }] });
        send({ id: "m" + k, object: "chat.completion.chunk", choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }] });
      } else {
        send({ id: "m" + k, object: "chat.completion.chunk", choices: [{ index: 0, delta: { role: "assistant", content: ANSWER } }] });
        send({ id: "m" + k, object: "chat.completion.chunk", choices: [{ index: 0, delta: {}, finish_reason: "stop" }], usage: { prompt_tokens: 10, completion_tokens: 3, total_tokens: 13 } });
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
  await sw.evaluate(() => {
    globalThis.kiSent = [];
    globalThis.kiCleared = [];
    const create = chrome.notifications.create.bind(chrome.notifications), clear = chrome.notifications.clear.bind(chrome.notifications);
    chrome.notifications.create = (id, o, cb) => { kiSent.push({ id, ...o }); return create(id, o, cb); };
    chrome.notifications.clear = (id, cb) => { kiCleared.push(id); return clear(id, cb); };
  });
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
  await page.keyboard.type("Check which tabs I have open and tell me what they are");
  await page.keyboard.press("Enter");
  await page.waitForTimeout(1500);
  await sw.evaluate(() => kiTest.kiFocus.forEach((v) => (v.visible = false)));
  for (let i = 0; i < 40 && !(await sw.evaluate(() => kiSent.length)); i++) await wait(500);

  const session = await sw.evaluate(() => [...kiTest.kiFocus.keys()][0]);
  await sw.evaluate((s) => kiTest.kiFocus.set(s, { visible: false }), session);
  await sw.evaluate((s) => kiTest.kiNotify(s, "ask", { request: { domain: "github.com", action: "interact", toolCallId: "call_x" } }), session);
  await sw.evaluate((s) => kiTest.kiNotify(s, "handoff", { text: "Please sign in to GitHub, then I'll keep going.", request: { id: "h1" } }), session);
  await sw.evaluate((s) => kiTest.kiNotify(s, "done", { finish: "error", ms: 42000 }), session);
  await sw.evaluate((s) => kiTest.kiNotify(s, "done", { finish: "stopped", ms: 69000 }), session);
  await wait(800);
  const sent = await sw.evaluate(() => kiSent);
  for (const o of sent) console.log(JSON.stringify({ title: o.title, message: o.message, context: o.contextMessage, buttons: o.buttons?.map((b) => b.title), icon: o.iconUrl.slice(0, 22) }));
  console.log("errors:", errors.length ? errors : "none");
  const esc = (s) => String(s || "").replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]);
  const cards = sent.map((o) => `<div class="t"><div class="h"><span class="cr"></span>zebbern <span class="d">• now</span><span class="x">⚙ ✕</span></div>
<div class="b"><div class="tx"><div class="ti">${esc(o.title)}</div><div class="m">${esc(o.message)}</div><div class="c">${esc(o.contextMessage)}</div></div><img src="${o.iconUrl}"></div>
${o.buttons ? `<div class="bt">${o.buttons.map((b) => `<span>${esc(b.title)}</span>`).join("")}</div>` : ""}</div>`).join("");
  const prev = await ctx.newPage();
  await prev.setViewportSize({ width: 420, height: 900 });
  await prev.setContent(`<style>body{margin:0;padding:14px;background:#5a2b2b;font:14px 'Segoe UI Variable','Segoe UI',sans-serif;display:flex;flex-direction:column;gap:12px}
.t{background:#2c2c2c;border:1px solid #3b3b3b;border-radius:8px;width:364px;color:#fff;padding:12px 14px 14px;box-shadow:0 8px 24px #0007}
.h{display:flex;align-items:center;gap:8px;font-size:12px;color:#ccc}.cr{width:14px;height:14px;border-radius:50%;background:conic-gradient(#ea4335 0 33%,#fbbc05 0 66%,#34a853 0)}.d{color:#999}.x{margin-left:auto;color:#aaa}
.b{display:flex;gap:12px;margin-top:10px}.tx{flex:1;min-width:0}.ti{font-weight:600;line-height:20px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.m{color:#d0d0d0;line-height:20px;display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden}.c{color:#9a9a9a;font-size:12px;margin-top:4px}
img{width:48px;height:48px}.bt{display:flex;gap:8px;margin-top:12px}.bt span{flex:1;text-align:center;background:#3c3c3c;border-radius:4px;padding:6px 0}</style>${cards}`);
  await prev.screenshot({ path: path.join(shots, "notify-preview.png"), fullPage: true });
  await ctx.close();
  server.close();
  process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });

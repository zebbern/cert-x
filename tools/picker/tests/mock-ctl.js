const http = require("http");
const path = require("path");
const os = require("os");
const fs = require("fs");
const { chromium } = require("C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core");

const ext = path.join(__dirname, "..", "..", "..");
const shots = path.join(__dirname, "shots");
fs.mkdirSync(shots, { recursive: true });
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const STEPS = 8;
const requests = [];

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
      requests.push({ at: Date.now(), text: JSON.stringify(j.messages) });
      const tool = (j.tools || []).map((t) => t.function?.name).find((n) => /list_tabs/.test(n || ""));
      const n = requests.length;
      res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache" });
      const send = (o) => res.write(`data: ${JSON.stringify(o)}\n\n`);
      await wait(1200);
      if (n <= STEPS && tool) {
        send({ id: "m" + n, object: "chat.completion.chunk", choices: [{ index: 0, delta: { role: "assistant", content: null, tool_calls: [{ index: 0, id: "call_" + n, type: "function", function: { name: tool, arguments: "{}" } }] } }] });
        send({ id: "m" + n, object: "chat.completion.chunk", choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }] });
      } else {
        send({ id: "m" + n, object: "chat.completion.chunk", choices: [{ index: 0, delta: { role: "assistant", content: "All done." } }] });
        send({ id: "m" + n, object: "chat.completion.chunk", choices: [{ index: 0, delta: {}, finish_reason: "stop" }], usage: { prompt_tokens: 10, completion_tokens: 3, total_tokens: 13 } });
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

  const row = page.locator(".wb-livebar > .ki-live-row");
  const barText = () => row.innerText().then((t) => t.replace(/\s+/g, " ").trim()).catch(() => "");
  await page.locator(".wb-editor").first().click();
  await page.keyboard.type("List my tabs a few times.");
  await page.keyboard.press("Enter");
  await row.waitFor({ timeout: 15000 });
  await page.waitForTimeout(2600);
  await row.click();
  await page.locator(".ki-steps .ki-chip", { hasText: /pause/i }).click();
  const pausedAt = requests.length;
  console.log("clicked pause at request", pausedAt, "| bar:", await barText());
  let heldText = "";
  for (let i = 0; i < 12; i++) { await wait(500); heldText = await barText(); if (/^Paused/.test(heldText)) break; }
  const stepsHeld = await page.locator(".ki-step").count(), reqHeld = requests.length;
  console.log("bar once holding:", heldText, "| steps:", stepsHeld, "| model requests:", reqHeld);
  await wait(5000);
  console.log("after 5s more -> steps:", await page.locator(".ki-step").count(), "| requests:", requests.length, (await page.locator(".ki-step").count()) === stepsHeld && requests.length === reqHeld ? "(HELD)" : "(MOVED)");
  await page.screenshot({ path: path.join(shots, "mock-paused.png") });

  await page.locator(".ki-steer-input").fill("STEER-TOKEN-42 please hurry");
  await page.keyboard.press("Enter");
  await page.waitForTimeout(400);
  await page.locator(".ki-steps .ki-chip", { hasText: /resume/i }).click();
  console.log("resumed | bar:", await barText());
  for (let i = 0; i < 40 && !(await page.locator(".wb-livebar.is-summary").count()); i++) await wait(500);
  const steered = requests.findIndex((r) => r.text.includes("STEER-TOKEN-42"));
  console.log("steer reached model in request #", steered + 1, "of", requests.length, "| paused at request", pausedAt);
  console.log("summary:", (await page.locator(".wb-livebar.is-summary .ki-live-row").innerText().catch(() => "none")).replace(/\s+/g, " "));
  await page.locator(".wb-livebar.is-summary .ki-live-row").click().catch(() => {});
  await page.locator(".ki-step").nth(2).click().catch(() => {});
  await page.waitForTimeout(300);
  console.log("detail of step 3:", JSON.stringify((await page.locator(".ki-step-detail").innerText().catch(() => "none")).slice(0, 120)));
  console.log("tuck:", JSON.stringify(await page.evaluate(() => {
    const bar = document.querySelector(".wb-livebar").getBoundingClientRect(), box = document.querySelector(".wb-inputbox").getBoundingClientRect();
    const hit = document.elementFromPoint(bar.left + 60, box.top + 6);
    return hit?.closest(".wb-inputbox") ? "inputbox on top" : "LIVEBAR ON TOP";
  })));
  await page.screenshot({ path: path.join(shots, "mock-detail.png") });
  console.log("errors:", errors.length ? errors : "none");
  await ctx.close();
  server.close();
  process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });

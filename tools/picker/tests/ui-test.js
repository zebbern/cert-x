const http = require("http");
const path = require("path");
const os = require("os");
const fs = require("fs");
const { chromium } = require("C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core");

const ext = path.join(__dirname, "..", "..", "..");
const shots = path.join(__dirname, "shots");
fs.mkdirSync(shots, { recursive: true });
fs.mkdirSync(shots, { recursive: true });

const catalog = [
  ["minimax/minimax-m3.1", "MiniMax: MiniMax M3.1", 1000000],
  ["minimax/minimax-m2", "MiniMax: MiniMax M2", 204800],
  ["deepseek/deepseek-v4.1-flash", "DeepSeek: DeepSeek V4.1 Flash", 163840],
  ["deepseek/deepseek-r2", "DeepSeek: DeepSeek R2", 131072],
  ["elorian/glimpse", "Elorian: Glimpse", 0],
  ["xingchen/xing4.0-29b-a4b", "XingChen: Xing4.0 29B A4B Instruct", 65536],
  ["reflection/beam-1.0-501b", "Reflection: Beam 1.0 501B A22B", 131072],
  ["anthropic/claude-opus-4.8", "Anthropic: Claude Opus 4.8", 1000000],
  ["anthropic/claude-sonnet-4.6", "Anthropic: Claude Sonnet 4.6", 1000000],
  ["openai/gpt-5.5", "OpenAI: GPT-5.5", 400000],
  ["moonshotai/kimi-k3", "MoonshotAI: Kimi K3", 262144],
];

const server = http.createServer((req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "*");
  if (req.method === "OPTIONS") return res.end();
  if (req.url.endsWith("/models")) {
    res.setHeader("Content-Type", "application/json");
    return res.end(JSON.stringify({ data: catalog.map(([id, name, ctx]) => ({ id, name, ...(ctx ? { context_length: ctx } : {}) })) }));
  }
  if (req.method === "POST" && req.url.endsWith("/chat/completions")) {
    res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache" });
    res.write(`data: ${JSON.stringify({ id: "t", object: "chat.completion.chunk", choices: [{ index: 0, delta: { role: "assistant", content: "" } }] })}\n\n`);
    return;
  }
  res.statusCode = 404;
  res.end();
});

async function main() {
  await new Promise((r) => server.listen(8787, "127.0.0.1", r));
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "ki-ui-"));
  const ctx = await chromium.launchPersistentContext(profile, {
    executablePath: path.join(process.env.LOCALAPPDATA, "ms-playwright/chromium-1234/chrome-win64/chrome.exe"),
    headless: false,
    viewport: { width: Number(process.env.W || 420), height: 820 },
    colorScheme: process.env.SCHEME || "dark",
    args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`],
  });
  let [sw] = ctx.serviceWorkers();
  if (!sw) sw = await ctx.waitForEvent("serviceworker");
  const id = new URL(sw.url()).host;
  await new Promise((r) => setTimeout(r, 2000));
  for (let i = 0; i < 10; i++) {
    await sw.evaluate(() => chrome.storage.local.set({
      sidepanel_connections: [{ id: "or-test", label: "OpenRouter", presetId: "openrouter", apiKey: "test", host: "http://127.0.0.1:8787/api/v1" }],
    }));
    await new Promise((r) => setTimeout(r, 1000));
    const n = await sw.evaluate(() => chrome.storage.local.get("sidepanel_connections").then((s) => (s.sidepanel_connections || []).length));
    if (n) break;
  }

  const page = await ctx.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
  await page.goto(`chrome-extension://${id}/pages/sidepanel.html`);
  await page.waitForTimeout(2500);
  for (const p of await ctx.pages()) if (p !== page) await p.close().catch(() => {});
  await page.reload();
  await page.waitForTimeout(1500);

  const tag = process.env.TAG || "dark";
  const shot = (name) => page.screenshot({ path: path.join(shots, `${tag}-${name}.png`) });

  if (process.env.LIVE) {
    const pill = page.locator(".wb-composer-model .wb-mode-toggle");
    for (let i = 0; i < 15 && (await pill.isDisabled()); i++) await page.waitForTimeout(1000);
    const box = page.locator(".wb-editor, .wb-inputbox [contenteditable], .wb-inputbox textarea").first();
    await box.click();
    await page.keyboard.type("Fill in the form on this page");
    await page.keyboard.press("Enter");
    await page.locator(".wb-livebar").waitFor({ timeout: 15000 });
    await page.waitForTimeout(800);
    console.log("livebar:", JSON.stringify(await page.locator(".wb-livebar").innerText()));
    console.log("geometry:", JSON.stringify(await page.evaluate(() => {
      const bar = document.querySelector(".wb-livebar"), box = document.querySelector(".wb-inputbox"), cs = getComputedStyle(bar);
      return { parent: bar.parentElement.className, margin: cs.margin, padding: cs.padding, barBottom: bar.getBoundingClientRect().bottom, boxTop: box.getBoundingClientRect().top, parentGap: getComputedStyle(bar.parentElement).gap, parentDisplay: getComputedStyle(bar.parentElement).display };
    })));
    await shot("l1-livebar");
    await box.click();
    await page.keyboard.type("/");
    await page.waitForTimeout(500);
    console.log("quick actions open:", await page.locator(".wb-command-menu").count(), "| livebar visible:", await page.locator(".wb-livebar").count());
    await shot("l2-quick-actions");
    await page.keyboard.press("Backspace");
    await page.waitForTimeout(400);
    console.log("after closing menu, livebar visible:", await page.locator(".wb-livebar").count());
    await page.evaluate(() => {
      const bar = document.querySelector(".wb-livebar");
      bar.querySelector(".wb-livebar-label").textContent = "Fill";
      const step = document.createElement("span");
      step.className = "wb-livebar-step";
      step.textContent = "14 steps";
      bar.insertBefore(step, bar.querySelector(".wb-livebar-track"));
    });
    await page.waitForTimeout(300);
    await page.locator(".wb-composer").screenshot({ path: path.join(shots, `${tag}-l3-livebar-steps.png`) });
    console.log("errors:", errors.length ? errors : "none");
    await ctx.close();
    process.exit(0);
  }
  await shot("0-composer");

  const pill = page.locator(".wb-composer-model .wb-mode-toggle");
  console.log("pill text:", await pill.innerText().catch((e) => "ERR " + e.message));
  await pill.click();
  await page.waitForTimeout(400);
  await shot("1-providers");
  console.log("rows:", await page.locator(".ki-mm-row").allInnerTexts());

  await page.locator(".ki-mm-row", { hasText: "DeepSeek" }).click();
  await page.waitForTimeout(300);
  await page.locator(".ki-mm-row", { hasText: "V4.1" }).hover();
  await page.waitForTimeout(300);
  await shot("2-models-card");
  console.log("card:", await page.locator(".ki-mm-card").innerText().catch(() => "none"));

  await page.keyboard.press("Escape");
  await page.waitForTimeout(200);
  console.log("after Esc (back) rows:", (await page.locator(".ki-mm-row").allInnerTexts()).length);
  await page.keyboard.type("claude");
  await page.waitForTimeout(300);
  await shot("3-search");
  console.log("search rows:", await page.locator(".ki-mm-row").allInnerTexts());
  await page.keyboard.press("ArrowDown");
  await page.keyboard.press("Enter");
  await page.waitForTimeout(500);
  console.log("menu open after Enter:", await page.locator(".ki-mm").count(), "pill:", await pill.innerText());
  await shot("4-selected");

  await page.keyboard.type("zzz");
  await pill.click();
  await page.waitForTimeout(300);
  await page.keyboard.type("nothing-here");
  await page.waitForTimeout(200);
  await shot("5-empty");
  await page.keyboard.press("Escape");
  await page.keyboard.press("Escape");
  await page.waitForTimeout(200);
  console.log("menu open after 2x Esc:", await page.locator(".ki-mm").count());

  const approval = page.locator(".wb-approval-toggle");
  if (await approval.count()) {
    await approval.click();
    await page.waitForTimeout(300);
    await shot("6-approval");
    await page.keyboard.press("Escape");
  }
  console.log("errors:", errors.length ? errors : "none");
  await ctx.close();
  server.close();
}

main().catch((e) => { console.error(e); server.close(); process.exit(1); });

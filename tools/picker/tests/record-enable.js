const http = require("http");
const path = require("path");
const os = require("os");
const fs = require("fs");
const { chromium } = require("C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core");

const ext = path.join(__dirname, "..", "..", "..");
const shots = path.join(__dirname, "shots");
fs.mkdirSync(shots, { recursive: true });
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

const server = http.createServer((req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "*");
  if (req.method === "OPTIONS") return res.end();
  if (req.url.endsWith("/models")) {
    res.setHeader("Content-Type", "application/json");
    return res.end(JSON.stringify({ data: [{ id: "mock/agent", name: "Mock: Agent", context_length: 128000 }] }));
  }
  res.setHeader("Content-Type", "text/html");
  res.end("<title>Shop</title><h1>A normal web page</h1><button>Buy</button>");
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
  const web = await ctx.newPage();
  await web.goto("http://127.0.0.1:8788/shop");
  for (const p of ctx.pages()) if (p !== web) await p.close().catch(() => {});
  const page = await ctx.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  await page.goto(`chrome-extension://${id}/pages/sidepanel.html`);
  await page.waitForTimeout(3000);
  const rec = page.locator(".ki-topnav-record");
  const state = async () => ((await rec.getAttribute("aria-disabled")) ? "BLOCKED" : "enabled") + " | tooltip: " + (await rec.locator(".wb-sk-tip").innerText());
  console.log("panel tab active (extension page):", await state());
  await web.bringToFront();
  await wait(1200);
  console.log("web page active, nothing typed:", await state());
  await page.bringToFront();
  await wait(1200);
  console.log("back on panel tab:", await state());
  await web.bringToFront();
  await wait(1200);
  console.log("web page again:", await state());
  console.log("editor text (never typed /):", JSON.stringify(await page.locator(".wb-editor").first().innerText()));
  console.log("errors:", errors.length ? errors : "none");
  await ctx.close();
  server.close();
  process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });

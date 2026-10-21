const http = require("http");
const path = require("path");
const os = require("os");
const fs = require("fs");
const { chromium } = require("C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core");

const ext = path.join(__dirname, "..", "..", "..");
const shots = path.join(__dirname, "shots");
fs.mkdirSync(shots, { recursive: true });
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const models = fs.readFileSync(path.join(process.env.TEMP, "kiicons", "models.json"));

const server = http.createServer((req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "*");
  if (req.method === "OPTIONS") return res.end();
  if (req.url.endsWith("/models")) {
    res.setHeader("Content-Type", "application/json");
    return res.end(models);
  }
  res.statusCode = 404;
  res.end();
});

async function main() {
  await new Promise((r) => server.listen(8788, "127.0.0.1", r));
  const theme = process.env.THEME || "dark";
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "ki-ui-"));
  const ctx = await chromium.launchPersistentContext(profile, {
    executablePath: path.join(process.env.LOCALAPPDATA, "ms-playwright/chromium-1234/chrome-win64/chrome.exe"),
    headless: false,
    viewport: { width: 420, height: 820 },
    colorScheme: theme,
    args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`],
  });
  let [sw] = ctx.serviceWorkers();
  if (!sw) sw = await ctx.waitForEvent("serviceworker");
  const id = new URL(sw.url()).host;
  await wait(2000);
  for (let i = 0; i < 10; i++) {
    await sw.evaluate(() => chrome.storage.local.set({ sidepanel_connections: [{ id: "mock", label: "OpenRouter", presetId: "openrouter", apiKey: "x", host: "http://127.0.0.1:8788/api/v1" }] }));
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
  await pill.click();
  await page.waitForTimeout(600);
  await page.screenshot({ path: path.join(shots, `logos-${theme}-1.png`) });
  const list = page.locator(".ki-mm-list, .ki-mm-scroll, .ki-mm [role=listbox]").first();
  const stats = await page.evaluate(() => {
    const rows = [...document.querySelectorAll(".ki-mm-row")];
    const letters = rows.filter((r) => r.querySelector(".ki-glyph:not(.ki-glyph-logo)")).map((r) => r.querySelector(".ki-mm-name")?.textContent);
    const broken = [...document.querySelectorAll(".ki-logo-img")].filter((i) => i.complete && i.naturalWidth === 0).length;
    return { rows: rows.length, logos: rows.length - letters.length, letters, broken };
  });
  console.log(JSON.stringify(stats));
  await page.mouse.move(200, 400);
  await page.mouse.wheel(0, 600);
  await page.waitForTimeout(400);
  await page.screenshot({ path: path.join(shots, `logos-${theme}-2.png`) });
  await page.locator(".ki-mm-row", { hasText: "Anthropic" }).first().click();
  await page.waitForTimeout(400);
  await page.screenshot({ path: path.join(shots, `logos-${theme}-3.png`) });
  console.log("errors:", errors.length ? errors : "none");
  await ctx.close();
  server.close();
  process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });

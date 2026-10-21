const path = require("path");
const os = require("os");
const fs = require("fs");
const { chromium } = require("C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core");

const ext = path.join(__dirname, "..", "..", "..");

async function main() {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "ki-ui-"));
  const ctx = await chromium.launchPersistentContext(profile, {
    executablePath: path.join(process.env.LOCALAPPDATA, "ms-playwright/chromium-1234/chrome-win64/chrome.exe"),
    headless: false,
    viewport: { width: 560, height: 820 },
    args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`],
  });
  let [sw] = ctx.serviceWorkers();
  if (!sw) sw = await ctx.waitForEvent("serviceworker");
  const id = new URL(sw.url()).host;
  console.log("service worker:", new URL(sw.url()).pathname);
  console.log("side panel path:", JSON.stringify(await sw.evaluate(() => chrome.sidePanel.getOptions({}).then((o) => o.path))));
  const failed = [];
  ctx.on("requestfailed", (r) => !/\.mp4$/.test(r.url()) && failed.push(r.url()));
  ctx.on("response", (r) => r.status() >= 400 && failed.push(r.status() + " " + r.url()));
  for (const p of ["pages/sidepanel.html", "pages/options.html", "pages/install-welcome.html", "providers/providers.html?embed=1&theme=dark"]) {
    const page = await ctx.newPage();
    const errors = [];
    page.on("pageerror", (e) => errors.push(String(e).slice(0, 120)));
    page.on("console", (m) => m.type() === "error" && errors.push(m.text().slice(0, 120)));
    await page.goto(`chrome-extension://${id}/${p}`);
    await page.waitForTimeout(2000);
    const body = (await page.locator("body").innerText()).replace(/\s+/g, " ").slice(0, 60);
    console.log(p.padEnd(44), "| text:", JSON.stringify(body), "| errors:", errors.length ? errors : "none");
    await page.close();
  }
  const page = await ctx.newPage();
  await page.goto(`chrome-extension://${id}/pages/sidepanel.html`);
  const urls = ["media/welcome/browser-intro.mp4", "media/welcome/browser-intro-en.mp4", "media/welcome/browser-intro-en-poster.jpg", "icon/zebbern-avatar.svg", "icon/vendors/claude-color.svg", "providers/providers-catalog.js", "background/background.js"];
  for (const u of urls) console.log(u.padEnd(44), await page.evaluate((u) => fetch(chrome.runtime.getURL(u)).then((r) => r.status, () => "FAIL"), u));
  console.log("failed requests:", failed.length ? failed : "none");
  await ctx.close();
  process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });

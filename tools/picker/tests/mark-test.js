const path = require("path");
const os = require("os");
const fs = require("fs");
const { chromium } = require("C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core");

const ext = path.join(__dirname, "..", "..", "..");
const shots = path.join(__dirname, "shots");
fs.mkdirSync(shots, { recursive: true });

async function main() {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "ki-ui-"));
  const ctx = await chromium.launchPersistentContext(profile, {
    executablePath: require("../../chromium-path.cjs"),
    headless: false,
    viewport: { width: 900, height: 500 },
    args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`],
  });
  let [sw] = ctx.serviceWorkers();
  if (!sw) sw = await ctx.waitForEvent("serviceworker");
  const site = await ctx.newPage();
  await site.goto("https://zebbern.com");
  await site.bringToFront();
  for (const p of ctx.pages()) if (p !== site) await p.close().catch(() => {});
  console.log("hooks:", await sw.evaluate(() => typeof globalThis.kiTest?.kiMark));
  const tabId = await sw.evaluate(() => chrome.tabs.query({ url: "https://zebbern.com/*" }).then((t) => t[0].id));
  await sw.evaluate((id) => globalThis.kiTest.setTab(id), tabId);
  const job = sw.evaluate(() => { const t0 = Date.now(); return globalThis.kiTest.kiMark("click", { selector: "a" }).then(() => Date.now() - t0, (e) => "error " + e); });
  let n = 0;
  const t0 = Date.now();
  while (Date.now() - t0 < 2500) await site.screenshot({ path: path.join(shots, `mark-${String(++n).padStart(2, "0")}.png`) });
  console.log("frames:", n, "| kiMark took ms:", await job);
  if (process.env.HOLD) {
    console.log("looping highlight for desktop capture");
    const until = Date.now() + Number(process.env.HOLD);
    while (Date.now() < until) await sw.evaluate(() => globalThis.kiTest.kiMark("click", { selector: "a" }));
  }
  await ctx.close();
  process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });

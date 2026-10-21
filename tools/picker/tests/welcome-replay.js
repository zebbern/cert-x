const path = require("path");
const os = require("os");
const fs = require("fs");
const { chromium } = require("C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core");

const ext = path.join(__dirname, "..", "..", "..");
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
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
  await sw.evaluate(() => chrome.storage.local.set({ wb_video_welcome_first_message_v1: true }));
  await wait(300);
  const page = await ctx.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  await page.goto(`chrome-extension://${id}/pages/sidepanel.html`);
  await page.waitForTimeout(2000);
  await page.locator(".wb-empty-title").waitFor();
  const title = (await page.locator(".wb-empty-title").innerText()).replace(/\s+/g, " ");
  const video = page.locator(".wb-home-welcome-video");
  console.log("title:", title);
  console.log("welcome layout:", await page.locator(".wb-empty--welcome").count());
  console.log("welcome rows:", await page.locator(".wb-welcome-prompt").count());
  if (title !== "Hi, what can I do for you?") throw new Error("unexpected title");
  console.log("video:", await video.count());
  if (await video.count()) {
    const box = await video.boundingBox();
    const chips = await page.locator(".wb-welcome-prompts").boundingBox();
    console.log("video above chips:", box && chips ? box.y < chips.y : "no");
  }
  console.log("errors:", errors.length ? errors : "none");
  await ctx.close();
  process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });

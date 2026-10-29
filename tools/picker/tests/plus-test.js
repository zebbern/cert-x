const path = require("path");
const os = require("os");
const fs = require("fs");
const { chromium } = require("C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core");

const ext = path.join(__dirname, "..", "..", "..");
const shots = path.join(__dirname, "shots");
fs.mkdirSync(shots, { recursive: true });
const tag = process.env.TAG || "dark";

async function main() {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "ki-ui-"));
  const ctx = await chromium.launchPersistentContext(profile, {
    executablePath: require("../../chromium-path.cjs"),
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
      sidepanel_connections: [{ id: "or-test", label: "OpenRouter", presetId: "openrouter", apiKey: "test", modelIds: ["openai/gpt-5.5"] }],
    }));
    await new Promise((r) => setTimeout(r, 1000));
    if (await sw.evaluate(() => chrome.storage.local.get("sidepanel_connections").then((s) => (s.sidepanel_connections || []).length))) break;
  }

  const site = await ctx.newPage();
  await site.goto("https://zebbern.com");
  const page = await ctx.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  await page.goto(`chrome-extension://${id}/pages/sidepanel.html`);
  await page.waitForTimeout(2500);
  for (const p of ctx.pages()) if (p !== page && p !== site) await p.close().catch(() => {});
  await page.reload();
  await page.waitForTimeout(2000);

  const shot = (name) => page.screenshot({ path: path.join(shots, `plus-${tag}-${name}.png`) });
  const editor = page.locator(".wb-editor").first();
  const text = () => editor.innerText().then((t) => JSON.stringify(t.replace(/\u00a0/g, " ")));
  const plus = page.locator(".ki-plus");

  console.log("left buttons:", await page.locator(".wb-input-bar > .wb-icon-button").count(), "| plus:", await plus.count());
  await shot("closed");
  console.log("approval label:", JSON.stringify(await page.evaluate(() => {
    const l = document.querySelector(".wb-approval-label");
    if (!l) return null;
    const cs = getComputedStyle(l), b = getComputedStyle(l.parentElement);
    return { w: l.getBoundingClientRect().width, maxW: cs.maxWidth, overflow: cs.overflow, flex: cs.flex, pillW: l.parentElement.getBoundingClientRect().width, pillMax: b.maxWidth,
      row: [...document.querySelector(".wb-input-bar").children].map((c) => c.className.split(" ")[0] + ":" + Math.round(c.getBoundingClientRect().width)) };
  })));

  await editor.click();
  await page.keyboard.type("hello ");
  await plus.click();
  await page.waitForTimeout(400);
  console.log("menu open:", await page.locator(".wb-command-menu").count(), "| text:", await text(),
    "| headers:", JSON.stringify(await page.locator(".wb-command-label").allInnerTexts()));
  console.log("first items:", JSON.stringify((await page.locator(".wb-command-title").allInnerTexts()).slice(0, 4)));
  await shot("open");

  await page.getByText("Select tabs", { exact: true }).dispatchEvent("mousedown");
  await page.waitForTimeout(500);
  console.log("after mention -> text:", await text(), "| quick actions:", await page.locator(".wb-command-menu").count(),
    "| tab menu items:", await page.locator(".wb-tab-mention-name").count());
  await shot("mention");
  await page.keyboard.press("Escape");

  await editor.click();
  await page.keyboard.press("Control+A");
  await page.keyboard.press("Backspace");
  await plus.click();
  await page.waitForTimeout(300);
  const chooser = page.waitForEvent("filechooser", { timeout: 3000 });
  await page.getByText("Add a file or image", { exact: true }).dispatchEvent("mousedown");
  const fc = await chooser.catch(() => null);
  console.log("file chooser opened:", !!fc, "| text:", await text(), "| menu:", await page.locator(".wb-command-menu").count());
  if (fc) await fc.setFiles({ name: "notes.txt", mimeType: "text/plain", buffer: Buffer.from("hi") });
  await page.waitForTimeout(600);
  await shot("attached");

  await plus.click();
  await page.waitForTimeout(300);
  await plus.click();
  await page.waitForTimeout(300);
  console.log("plus toggles closed:", (await page.locator(".wb-command-menu").count()) === 0);

  await editor.click();
  await page.keyboard.type("/");
  await page.waitForTimeout(300);
  console.log("typing / headers:", JSON.stringify(await page.locator(".wb-command-label").allInnerTexts()));
  await page.keyboard.type("comp");
  await page.waitForTimeout(300);
  console.log("typing /comp items:", JSON.stringify(await page.locator(".wb-command-title").allInnerTexts()));

  console.log("errors:", errors.length ? errors : "none");
  await ctx.close();
  process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });

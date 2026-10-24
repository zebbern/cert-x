// Dumbest possible login helper: opens a visible window on the target with
// the persistent runner profile and waits until YOU close the window (up to
// 10 minutes). No detection heuristics — you decide when you're done, then
// close the window; the profile keeps whatever session you created.
// Usage: node tools/picker/tests/gs-login.cjs [url]
const fs = require('node:fs'), path = require('node:path');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const profile = process.env.M4_PROFILE || 'C:/Users/zeb/.certx-runner-profile';
const target = process.argv[2] || 'https://app.grayswan.ai/challenges';
(async () => {
  fs.mkdirSync(path.join(profile, 'Default'), { recursive: true });
  const browser = await chromium.launchPersistentContext(profile, { headless: false, viewport: { width: 1200, height: 900 },
    executablePath: process.env.CHROMIUM_PATH || path.join(process.env.LOCALAPPDATA, 'ms-playwright/chromium-1234/chrome-win64/chrome.exe') });
  const page = await browser.newPage();
  await page.goto(target, { waitUntil: 'domcontentloaded', timeout: 45000 }).catch(error => console.log('goto:', error.message));
  console.log('WINDOW OPEN — log in (Google if offered; if the site emails a sign-in link, copy that link and open it IN THIS WINDOW\'s address bar). CLOSE THIS WINDOW when done.');
  const closed = new Promise(resolve => browser.on('close', resolve));
  const timeout = new Promise(resolve => setTimeout(() => resolve('timeout'), 10 * 60 * 1000));
  const result = await Promise.race([closed, timeout]);
  console.log(result === 'timeout' ? 'TIMEOUT — window will close; rerun if needed.' : 'WINDOW-CLOSED-BY-USER — profile saved.');
  try { await browser.close(); } catch {}
  process.exit(result === 'timeout' ? 1 : 0);
})();

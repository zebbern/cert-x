// Real extension UI persistence/routing checks, separate from engine parity fixtures.
// Browser plugin not available: use the repository's isolated Chromium workflow.
const fs = require('node:fs'), path = require('node:path'), os = require('node:os'), http = require('node:http'), assert = require('node:assert/strict');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const root = path.resolve(__dirname, '../../..'), temp = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-x-security-ui-'));
let browser, server;
async function main() {
  server = http.createServer((req, res) => { res.setHeader('Content-Type', 'text/html'); res.end('<!doctype html><title>Security UI fixture</title><h1>Application</h1>'); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = 'http://127.0.0.1:' + server.address().port;
  browser = await chromium.launchPersistentContext(path.join(temp, 'profile'), { headless: true, viewport: { width: 420, height: 950 }, executablePath: process.env.CHROMIUM_PATH || path.join(process.env.LOCALAPPDATA, 'ms-playwright/chromium-1234/chrome-win64/chrome.exe'), args: ['--disable-extensions-except=' + root, '--load-extension=' + root] });
  const worker = browser.serviceWorkers()[0] || await browser.waitForEvent('serviceworker', { timeout: 15000 });
  await worker.evaluate(async () => { if (!globalThis.certXSecurity) throw Error('Security runtime missing'); await globalThis.certXSecurity.ready; });
  const id = new URL(worker.url()).host, session = 'security-ui-browser';
  await worker.evaluate(() => chrome.storage.local.set({ sidepanel_theme: 'dark', sidepanel_language: 'en' }));
  const app = await browser.newPage(); await app.goto(origin);
  const page = await browser.newPage(), errors = [];
  page.on('pageerror', error => errors.push(error.message));
  const url = 'chrome-extension://' + id + '/providers/providers.html?section=security&session=' + session;
  await page.goto(url); await page.waitForFunction(() => !document.querySelector('main').inert);
  const assigned = await page.evaluate(session => chrome.runtime.sendMessage({ type: 'KI_CONTEXT', op: 'assign_chat', session, profileId: 'bugbounty', modelExplicit: null }), session); assert.equal(assigned.ok, true, JSON.stringify(assigned));
  await page.reload(); await page.waitForFunction(() => !document.querySelector('main').inert);
  await page.getByRole('heading', { name: 'Security testing', exact: true }).waitFor();
  assert.equal(await page.title(), 'Security testing');
  await page.getByText('Local runtime & connections', { exact: true }).click();
  await page.getByText('Local computer access is off.', { exact: true }).waitFor();
  assert.equal(await page.getByRole('button', { name: 'Set up browser', exact: true }).isDisabled(), true);
  const deniedSetup = await page.evaluate(session => chrome.runtime.sendMessage({ type: 'KI_SECURITY', op: 'local_setup', session, components: ['browser'] }), session);
  assert.equal(deniedSetup.ok, false); assert.match(deniedSetup.error, /local computer access/i);
  assert.equal(await page.getByLabel('Reproduction browser backend', { exact: true }).count(), 0);
  await page.getByRole('switch', { name: 'Include ZAP in Thorough' }).focus(); await page.keyboard.press('Space');
  await page.getByRole('button', { name: 'Save connections', exact: true }).click(); await page.getByText('Testing connections saved.', { exact: true }).waitFor();
  const preferences = await worker.evaluate(async () => (await chrome.storage.local.get('ki_security_integrations')).ki_security_integrations);
  assert.equal(preferences.zapEnabled, true); assert.equal(preferences.oastConnectionId, null);
  await page.reload(); await page.waitForFunction(() => !document.querySelector('main').inert); await page.getByText('Local runtime & connections', { exact: true }).click();
  assert.equal(await page.getByLabel('Callback connection', { exact: true }).inputValue(), ''); assert.equal(await page.getByRole('switch', { name: 'Include ZAP in Thorough' }).getAttribute('aria-checked'), 'true');
  await page.getByText('Local runtime & connections', { exact: true }).click();
  await page.getByText('Scan options', { exact: true }).click();
  await page.getByLabel('Run request budget', { exact: true }).fill('2500');
  await page.getByLabel('Run duration in seconds', { exact: true }).fill('3600');
  await page.getByLabel('Requests per second', { exact: true }).fill('7');
  await page.getByRole('button', { name: 'Save defaults', exact: true }).click();
  await page.getByText('Defaults saved.', { exact: true }).waitFor();
  const persisted = await worker.evaluate(async () => (await chrome.storage.local.get('ki_security_settings')).ki_security_settings);
  assert.equal(persisted.defaults.maxRequests, 2500); assert.equal(persisted.defaults.durationSeconds, 3600); assert.equal(persisted.defaults.maxRequestsPerSecond, 7);
  await page.reload(); await page.waitForFunction(() => !document.querySelector('main').inert);
  await page.getByText('Scan options', { exact: true }).click(); assert.equal(await page.getByLabel('Run request budget', { exact: true }).inputValue(), '2500');
  await page.getByText('Your limits', { exact: true }).click(); await page.getByLabel('Maximum allowed run requests', { exact: true }).fill('3000');
  await page.getByRole('button', { name: 'Save limits', exact: true }).click(); await page.getByText('Limits saved.', { exact: true }).waitFor();
  const limits = await worker.evaluate(async () => (await chrome.storage.local.get('ki_security_settings')).ki_security_settings.limits); assert.equal(limits.maxRequests, 3000);
  const afterLimits = await worker.evaluate(async () => (await chrome.storage.local.get('ki_security_settings')).ki_security_settings); assert.equal(afterLimits.defaults.maxRequests, 2500, 'Saving limits preserves defaults');
  for (const alias of ['ptk', 'dast']) {
    await page.goto(url.replace('section=security', 'section=' + alias)); await page.waitForFunction(() => !document.querySelector('main').inert);
    await page.getByRole('heading', { name: 'Security testing', exact: true }).waitFor();
    assert.equal(await page.getByText(/Set up PTK|Copy build command|Check connection/).count(), 0);
  }
  await page.getByRole('button', { name: 'Manage accounts', exact: true }).click(); await page.getByRole('heading', { name: 'Compare accounts', exact: true }).waitFor();
  await page.getByRole('button', { name: 'Back to security testing', exact: true }).click(); await page.getByRole('heading', { name: 'Security testing', exact: true }).waitFor();
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
  await page.screenshot({ path: path.join(os.tmpdir(), 'cert-x-security-native-420.png'), fullPage: true });
  await page.setViewportSize({ width: 720, height: 950 }); await page.goto(url + '&theme=light'); await page.waitForFunction(() => !document.querySelector('main').inert);
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
  await page.screenshot({ path: path.join(os.tmpdir(), 'cert-x-security-native-720.png'), fullPage: true });
  await page.goto('chrome-extension://' + id + '/providers/providers.html?section=security'); await page.waitForFunction(() => !document.querySelector('main').inert);
  assert.equal(await page.getByRole('button', { name: 'Start scan', exact: true }).isDisabled(), true);
  await page.getByText('Scan options', { exact: true }).click(); await page.getByLabel('Run request budget', { exact: true }).fill('1500');
  await page.getByRole('button', { name: 'Save defaults', exact: true }).click(); await page.getByText('Defaults saved.', { exact: true }).waitFor({ timeout: 5000 });
  const afterDefaults = await worker.evaluate(async () => (await chrome.storage.local.get('ki_security_settings')).ki_security_settings); assert.equal(afterDefaults.limits.maxRequests, 3000, 'Saving defaults preserves explicit user limits');
  assert.deepEqual(errors, []);
  console.log(JSON.stringify({ singleExtension: true, settingsPersistence: true, localSetupGate: true, backendPreferences: true, configurableLimits: true, legacyRoutes: true, accountsSubview: true, noChatDefaults: true, viewports: [420, 720], themes: ['dark', 'light'], errors }));
}
main().catch(error => { console.error(error); process.exitCode = 1; }).finally(async () => {
  await browser?.close(); if (server) await new Promise(resolve => server.close(resolve));
  const absolute = path.resolve(temp); if (absolute.startsWith(path.resolve(os.tmpdir()) + path.sep) && path.basename(absolute).startsWith('cert-x-security-ui-')) fs.rmSync(absolute, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

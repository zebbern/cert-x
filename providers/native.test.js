const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");
const source = fs.readFileSync(path.join(__dirname, "native.js"), "utf8");
async function settingsPage(initial, hostError) {
  const nodes = new Map();
  let stored = initial, failWrites = false, copied = "";
  const get = id => {
    if (!nodes.has(id)) nodes.set(id, { value: id === "native-browser" ? "Chrome" : "[]", attributes: {}, setAttribute(key, value) { this.attributes[key] = value; }, getAttribute(key) { return this.attributes[key]; }, classList: { toggle() {} }, disabled: true, textContent: "", className: "", open: false, handlers: {}, addEventListener(type, handler) { this.handlers[type] = handler; } });
    return nodes.get(id);
  };
  const context = vm.createContext({ document: { getElementById: get }, navigator: { userAgent: "Chrome", clipboard: { writeText: async value => { copied = value; } } }, chrome: { runtime: { id: "test", sendMessage: async () => hostError ? { ok: false, error: hostError } : ({ ok: true, result: { platform: "win32", node: "v24", home: "C:\\Users\\test", features: ["command_jobs"] } }) }, storage: { local: {
    get: async () => ({ ki_native_settings: stored }),
    set: async value => { if (failWrites) throw Error("storage unavailable"); stored = value.ki_native_settings; },
  } } } });
  await vm.runInContext("(async () => {" + source + "\n})()", context);
  await new Promise(resolve => setImmediate(resolve)); // The automatic host check no longer blocks the settings UI.
  return { get, stored: () => stored, copied: () => copied, failWrites: () => failWrites = true,
    async toggle(enabled) { if ((get("native-enabled").getAttribute("aria-checked") === "true") !== enabled) await get("native-enabled").handlers.click(); } };
}
test("enabling saves immediately and preserves saved MCP servers", async () => {
  const servers = [{ command: "node", args: ["server.js"] }];
  const page = await settingsPage({ enabled: false, servers });
  await page.toggle(true);
  assert.equal(page.stored().enabled, true);
  assert.equal(page.stored().servers, servers);
  assert.match(page.get("native-access-status").textContent, /On · available next message/);
  assert.equal(page.get("native-enabled").disabled, false);
});
test("disabling saves immediately and reports persisted state", async () => {
  const page = await settingsPage({ enabled: true, servers: [] });
  assert.match(page.get("native-access-status").textContent, /On · available next message/);
  await page.toggle(false);
  assert.equal(page.stored().enabled, false);
  assert.match(page.get("native-access-status").textContent, /Off · local tools disabled/);
});
test("failed enable restores switch and reports failure instead of claiming enabled", async () => {
  const page = await settingsPage({ enabled: false, servers: [] });
  page.failWrites();
  await page.toggle(true);
  assert.equal(page.stored().enabled, false);
  assert.equal(page.get("native-enabled").getAttribute("aria-checked"), "false");
  assert.equal(page.get("native-enabled").disabled, false);
  assert.match(page.get("native-access-status").textContent, /Could not save: storage unavailable/);
});
test("host check is automatic and missing-host setup offers the correct copyable command", async () => {
  const page = await settingsPage({}, "Specified native messaging host not found.");
  assert.equal(page.get("native-status").textContent, "Setup needed");
  assert.equal(page.get("native-setup").open, true);
  page.get("native-browser").value = "Edge";
  page.get("native-browser").handlers.change();
  await page.get("native-copy").handlers.click();
  assert.match(page.copied(), /-File \.\\tools\\host\\install\.ps1 -ExtensionId test -Browser Edge$/);
  assert.equal(page.get("native-copy-status").textContent, "Copied");
  const connected = await settingsPage({});
  assert.equal(connected.get("native-status").textContent, "Connected");
  assert.equal(connected.get("native-setup").open, false);
});

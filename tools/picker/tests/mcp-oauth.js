const http = require("http");
const path = require("path");
const os = require("os");
const fs = require("fs");
const { chromium } = require("C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core");

const ext = path.join(__dirname, "..", "..", "..");
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const base = "http://127.0.0.1:8793";

const server = http.createServer((req, res) => {
  const url = new URL(req.url, base);
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Headers", "*");
    if (req.method === "OPTIONS") return res.end();
    if (url.pathname === "/prm") {
      res.setHeader("Content-Type", "application/json");
      return res.end(JSON.stringify({ resource: base + "/mcp", authorization_servers: [base] }));
    }
    if (url.pathname === "/.well-known/oauth-authorization-server") {
      res.setHeader("Content-Type", "application/json");
      return res.end(JSON.stringify({
        issuer: base,
        authorization_endpoint: base + "/authorize",
        token_endpoint: base + "/token",
        registration_endpoint: base + "/register",
        code_challenge_methods_supported: ["S256"],
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "refresh_token"],
      }));
    }
    if (url.pathname === "/register") {
      res.setHeader("Content-Type", "application/json");
      return res.end(JSON.stringify({ client_id: "client-1", redirect_uris: JSON.parse(body).redirect_uris }));
    }
    if (url.pathname === "/token") {
      res.setHeader("Content-Type", "application/json");
      const params = new URLSearchParams(body);
      if (!params.get("code") && params.get("grant_type") !== "refresh_token") {
        res.statusCode = 400;
        return res.end(JSON.stringify({ error: "invalid_grant" }));
      }
      return res.end(JSON.stringify({ access_token: "test-access", refresh_token: "test-refresh", expires_in: 3600, token_type: "Bearer" }));
    }
    if (url.pathname === "/mcp") {
      const auth = req.headers.authorization || "";
      if (auth !== "Bearer test-access") {
        res.statusCode = 401;
        res.setHeader("WWW-Authenticate", `Bearer resource_metadata="${base}/prm"`);
        res.setHeader("Content-Type", "application/json");
        return res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32600, message: "Sign in required" }, id: null }));
      }
      const msg = JSON.parse(body || "{}");
      res.setHeader("Content-Type", "application/json");
      res.setHeader("mcp-session-id", "sess");
      if (msg.method === "notifications/initialized") {
        res.statusCode = 202;
        return res.end();
      }
      if (msg.method === "tools/list") {
        return res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { tools: [{ name: "echo", description: "Echo", inputSchema: { type: "object", properties: {} } }] } }));
      }
      return res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-03-26", capabilities: {}, serverInfo: { name: "mock", version: "0" } } }));
    }
    res.statusCode = 404;
    res.end();
  });
});

async function main() {
  await new Promise((r) => server.listen(8793, "127.0.0.1", r));
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "ki-ui-"));
  const ctx = await chromium.launchPersistentContext(profile, {
    executablePath: path.join(process.env.LOCALAPPDATA, "ms-playwright/chromium-1234/chrome-win64/chrome.exe"),
    headless: false,
    viewport: { width: 720, height: 900 },
    args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`],
  });
  let [sw] = ctx.serviceWorkers();
  if (!sw) sw = await ctx.waitForEvent("serviceworker");
  const id = new URL(sw.url()).host;
  await wait(1200);
  const page = await ctx.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  await page.goto(`chrome-extension://${id}/providers/providers.html`);
  await page.locator("#mcp-known h3", { hasText: "Postman (US)" }).waitFor();
  console.log("known:", (await page.locator("#mcp-known").innerText()).replace(/\s+/g, " ").slice(0, 180));
  await page.locator("#mcp-known button", { hasText: "Add with key" }).click();
  console.log("EU form url:", await page.locator("#mcp-url").inputValue());

  const started = await page.evaluate(async (url) => chrome.runtime.sendMessage({ type: "KI_MCP", op: "auth-start", server: { url, label: "Mock OAuth" } }), base + "/mcp");
  console.log("auth-start:", started.ok ? "ok" : started.error, started.url ? new URL(started.url).pathname : "");
  const redirect = new URL(started.url).searchParams.get("redirect_uri");
  const state = started.state;
  const done = await page.evaluate(async ({ state, responseUrl }) => chrome.runtime.sendMessage({ type: "KI_MCP", op: "auth-finish", state, responseUrl, server: { url: "http://127.0.0.1:8793/mcp", label: "Mock OAuth" } }), { state, responseUrl: redirect + "?code=abc&state=" + encodeURIComponent(state) });
  console.log("auth-finish:", done.ok ? "ok " + done.label : done.error);
  const stored = await sw.evaluate(() => chrome.storage.local.get("ki_mcp_servers"));
  const saved = (stored.ki_mcp_servers || [])[0] || {};
  console.log("saved oauth:", saved.oauth && saved.oauth.accessToken === "test-access" ? "token stored" : "MISSING");
  const tested = await page.evaluate(async () => chrome.runtime.sendMessage({ type: "KI_MCP", op: "test", server: { url: "http://127.0.0.1:8793/mcp" } }));
  console.log("tools after sign-in:", tested.ok ? tested.tools.join(", ") : tested.error);
  console.log("errors:", errors.length ? errors : "none");
  await ctx.close();
  server.close();
  process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });

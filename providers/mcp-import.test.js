import { test } from "node:test";
import assert from "node:assert/strict";
import { parseMcpImport, mergeMcpImport } from "./mcp-import.js";
test("imports common local and HTTP configurations without executing or expanding values", () => {
  const entries = parseMcpImport(JSON.stringify({ mcpServers: { local: { command: "npx", args: ["-y", "package", "with spaces"], env: { TOKEN: "${TOKEN}" } }, remote: { url: "https://example.com/mcp", headers: { Authorization: "Bearer abc" } } } }));
  assert.equal(entries[0].server.env.TOKEN, "${TOKEN}"); assert.equal(entries[1].server.token, "abc");
  assert.deepEqual(entries[0].server.args, ["-y", "package", "with spaces"]);
});
test("unsupported fields and transports are reported instead of silently discarded", () => {
  const entries = parseMcpImport(JSON.stringify([{ command: "node", disabled: true }, { url: "https://example.com", headers: { "X-Key": "secret" } }, { url: "https://example.com", type: "sse" }, null]));
  assert.ok(entries.every(entry => entry.error));
  assert.throws(() => parseMcpImport("{}"), /mcpServers/);
});
test("merging preserves existing credentials, ignores duplicate servers and preserves limits", () => {
  const existing = [{ id: "keep", label: "Existing", url: "https://example.com/mcp", token: "keep-secret" }];
  const entries = parseMcpImport(JSON.stringify({ mcpServers: { duplicate: { url: "https://example.com/mcp", token: "replace" }, newLocal: { command: "node", args: ["server.js"] } } }));
  const result = mergeMcpImport(entries, existing, []);
  assert.equal(result.skipped, 1); assert.equal(result.added, 1); assert.equal(result.remote[0].token, "keep-secret"); assert.equal(existing.length, 1);
  assert.throws(() => mergeMcpImport(entries.slice(1), [], Array.from({ length: 8 }, (_, i) => ({ command: "node", args: [String(i)] }))), /8 local/);
});

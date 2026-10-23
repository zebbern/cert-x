// Dependency-free stdio fixture. Never logs on stdout except JSON-RPC.
const readline = require("node:readline");
const fs = require("node:fs");
if (process.env.PID_FILE) fs.writeFileSync(process.env.PID_FILE, String(process.pid));
let initialized = false;
function send(id, result, error) { process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id, ...(error ? { error } : { result }) }) + "\n"); }
readline.createInterface({ input: process.stdin }).on("line", line => {
  const m = JSON.parse(line);
  if (m.method === "initialize") {
    if (process.env.HANG_INIT) return;
    return send(m.id, { protocolVersion: "2025-03-26", capabilities: { tools: {} }, serverInfo: { name: "fixture", version: "1" } });
  }
  if (m.method === "notifications/initialized") { initialized = true; return; }
  if (!initialized) return send(m.id, null, { code: -32000, message: "Not initialized" });
  if (m.method === "tools/list") return send(m.id, m.params.cursor ? { tools: [{ name: "fail", inputSchema: { type: "object" } }] }
    : { tools: [{ name: "echo", description: "Echo a value", inputSchema: { type: "object", properties: { text: { type: "string" } } } }], nextCursor: "second" });
  if (m.method === "tools/call") {
    const name = m.params.name;
    if (name === "hang") return;
    if (name === "env_present") return send(m.id, { content: [{type:'text',text:process.env.WEBHOOK_SITE_API_KEY?'configured':'missing'}] });
    if (name === "secret_error") return send(m.id, null, {code:-32001,message:'Fixture private credential: '+process.env.WEBHOOK_SITE_API_KEY});
    if (name === "crash") return process.exit(7);
    if (name === "malformed") return process.stdout.write("not json\n");
    if (name === "rpc_error") return send(m.id, null, { code: -32001, message: "Fixture RPC error" });
    if (name === "large") return send(m.id, { content: [{ type: "text", text: "x".repeat(950000) }] });
    return send(m.id, { content: [{ type: "text", text: name === "fail" ? "Fixture tool error" : "echo:" + m.params.arguments.text }], ...(name === "fail" ? { isError: true } : {}) });
  }
});

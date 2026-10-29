const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const source = fs.readFileSync(path.join(__dirname, "../src/ki-workspace.js"), "utf8");
function fixture() {
  const data = { ki_native_settings: { enabled: true, servers: [] }, ki_mcp_servers: [{ url: "https://example.com", token: "PRIVATE-TOKEN" }], sidepanel_connections: [{ apiKey: "PRIVATE-KEY" }] };
  let host = { version: 1, revision: 2, features: ["command_jobs"], node: "v24", platform: "win32" };
  const files = new Map(), listeners = [];
  const context = vm.createContext({ console, URL, Date, crypto: require("node:crypto").webcrypto, atob, btoa,
    chrome: { runtime: { id: "test", getManifest: () => ({ version: "1.0.0" }), getURL: path => "chrome-extension://test/" + path, onMessage: { addListener: fn => listeners.push(fn) } },
      storage: { local: { get: async () => ({ ...data }), set: async update => Object.assign(data, update) } } },
    KI_POLICY_KEY: "ki_tool_permissions", kiMcpCache: { tools: [], errors: [] }, kiNativeCache: { tools: [], errors: [] },
    kiNativeSettings: async () => data.ki_native_settings,
    kiPolicyClean: () => ({ groups: {}, tools: {} }), kiPolicyRule: () => "inherit", kiPolicyBrowserMeta: name => ({ name, family: "browser" }),
    kiPolicyInventory: async () => ({ tools: [{ name: "echo", group: "mcp", family: "mcp" }, { name: "local_read_job", family: "local" }] }),
    XB: { snapshot: async () => ({ connected: false }) },
    kiNativeRpc: async (op, params) => {
      if (op === "status") { if (host instanceof Error) throw host; return host; }
      if (op === "read_file") { const bytes = files.get(params.path); if (!bytes) throw Error("ENOENT"); const chunk = bytes.subarray(params.offset, params.offset + params.max_bytes); return { content: chunk.toString("base64"), size: bytes.length, nextOffset: params.offset + chunk.length, bytesRead: chunk.length, truncated: params.offset + chunk.length < bytes.length }; }
      if (op === "job_list") return [];
      throw Error(op);
    },
  });
  vm.runInContext(source, context);
  return { context, data, files, host: value => host = value, request: (message, sender) => new Promise(resolve => listeners[0]({ type: "KI_WORKSPACE", ...message }, sender, resolve)) };
}
test("capabilities distinguish configured from ready, detect host upgrades and omit credentials", async () => {
  const f = fixture(); f.host({ version: 1, node: "v22", platform: "win32" });
  const health = await f.context.kiWorkspaceHealth();
  assert.equal(health.local.host.updateNeeded, true); assert.equal(health.mcp.discoveredTools, 0);
  assert.equal(health.permissions.tools.find(tool => tool.name === "echo").available, false);
  assert.equal(JSON.stringify(health).includes("PRIVATE-"), false);
  f.host(Error("Specified native messaging host not found"));
  assert.equal((await f.context.kiWorkspaceHealth()).local.host.state, "unavailable");
});
test("outputs are scoped to task and retain exact bytes across read chunks", async () => {
  const f = fixture(), bytes = Buffer.alloc(300001); for (let i = 0; i < bytes.length; i++) bytes[i] = i % 256;
  f.files.set("C:\\output.bin", bytes);
  await f.context.kiWorkspaceCapture({ family: "local", name: "local_write_file" }, {}, { output: JSON.stringify({ path: "C:\\output.bin", bytesWritten: bytes.length }) }, "task-a");
  const [item] = f.data.ki_task_outputs; assert.equal(item.owner, "task-a"); assert.equal(item.data, undefined);
  const content = await f.context.kiWorkspaceReadOutput(item.id);
  assert.deepEqual(Buffer.from(content.content, "base64"), bytes);
  f.data.ki_native_settings.enabled = false;
  await assert.rejects(f.context.kiWorkspaceReadOutput(item.id), /Enable Local computer/);
});
test("MCP results cannot register arbitrary local paths as native file outputs", async () => {
  const f = fixture();
  await f.context.kiWorkspaceCapture({ family: "mcp", name: "local_write_file" }, {}, { output: JSON.stringify({ path: "C:\\secret" }) }, "task");
  assert.equal(f.data.ki_task_outputs, undefined);
});
test("completed jobs cannot regress, output IDs stay stable and disconnect marks running jobs", async () => {
  const f = fixture(), job = { jobId: "job", owner: "task", state: "completed", outputs: [{ path: "C:\\file.txt", size: 4 }] };
  await f.context.kiWorkspaceJob(job); const id = f.data.ki_task_outputs[0].id;
  await f.context.kiWorkspaceJob({ ...job, state: "running", outputs: [] });
  assert.equal(f.data.ki_command_jobs[0].state, "completed");
  await f.context.kiWorkspaceJob(job); assert.equal(f.data.ki_task_outputs[0].id, id);
  await f.context.kiWorkspaceJob({ jobId: "active", owner: "task", state: "running" });
  await f.context.kiWorkspaceHostLost();
  assert.equal(f.data.ki_command_jobs.find(job => job.jobId === "active").state, "interrupted");
});
test("workspace UI APIs reject web-page and content-script senders", async () => {
  const f = fixture();
  const result = await f.request({ op: "output_read", id: "anything" }, { id: "test", url: "https://example.com" });
  assert.equal(result.ok, false);
});

"use strict";

// stdout is exclusively Chrome's length-prefixed native messaging protocol.
const fs = require("node:fs");
const fsp = fs.promises;
const path = require("node:path");
const os = require("node:os");
const { spawn, spawnSync } = require("node:child_process");
const { StringDecoder } = require("node:string_decoder");

// Chrome native messaging caps one message at 1 MiB; 900 KiB leaves room for
// the JSON envelope around the payload.
const MAX_FRAME = 900 * 1024;
// FIXME(justified-limits): unverified default. Reads paginate, but the real
// per-message ceiling (~900 KiB) would allow much larger chunks per call;
// confirm against real usage and raise, or document why small is right.
const MAX_FILE = 128 * 1024;
const processes = new Set();
const requests = new Map();
const servers = new Map();
let stopping = false;

function integer(value, fallback, min, max) {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || value < min || value > max) throw Error(`Expected integer ${min}..${max}`);
  return value;
}
function text(value, name) {
  if (typeof value !== "string" || !value.trim() || value.includes("\0")) throw Error(`${name} is required and must be a nonempty string`);
  return value;
}
function localPath(value) {
  const p = text(value, "Absolute path");
  if (!path.isAbsolute(p)) throw Error("Use an absolute local path");
  if (process.platform === "win32" && (/^\\\\[.?]\\/.test(p) || /:/.test(p.slice(2)))) throw Error("Device paths and alternate data streams are unsupported");
  return path.normalize(p);
}
function send(message) {
  let body = Buffer.from(JSON.stringify(message));
  if (body.length > MAX_FRAME) body = Buffer.from(JSON.stringify({ id: message.id, ok: false, error: "Result exceeds native message limit; request a smaller result" }));
  const header = Buffer.alloc(4);
  header.writeUInt32LE(body.length);
  process.stdout.write(Buffer.concat([header, body]));
}
function launch(command, args, options = {}) {
  const child = spawn(command, args, { windowsHide: true, detached: process.platform !== "win32", stdio: ["pipe", "pipe", "pipe"], ...options });
  processes.add(child);
  child.once("close", () => processes.delete(child));
  return child;
}
async function killTree(child) {
  if (!child.pid) return;
  if (process.platform === "win32") {
    await new Promise(resolve => {
      const killer = spawn("taskkill.exe", ["/pid", String(child.pid), "/t", "/f"], { windowsHide: true, stdio: "ignore" });
      killer.once("error", () => { child.kill(); resolve(); });
      killer.once("close", resolve);
    });
  } else {
    try { process.kill(-child.pid, "SIGKILL"); } catch { child.kill("SIGKILL"); }
  }
}
function abortCheck(signal) { signal?.throwIfAborted(); }
function commandLine(command) {
  return process.platform === "win32"
    ? ["powershell.exe", ["-NoLogo", "-NoProfile", "-NonInteractive", "-OutputFormat", "Text", "-EncodedCommand", Buffer.from("$ProgressPreference='SilentlyContinue'; [Console]::OutputEncoding = New-Object Text.UTF8Encoding($false); $OutputEncoding=[Console]::OutputEncoding;\n" + command, "utf16le").toString("base64")]]
    : ["/bin/sh", ["-c", command]];
}
async function collectOutputs(paths = []) {
  if (!Array.isArray(paths) || paths.length > 16) throw Error("outputs must contain up to 16 absolute paths");
  const outputs = [], outputWarnings = [];
  for (const value of paths) {
    try { const target = localPath(value), stat = await fsp.stat(target); if (!stat.isFile()) throw Error("not a regular file"); outputs.push({ path: target, size: stat.size }); }
    catch (error) { outputWarnings.push(String(value) + ": " + error.message); }
  }
  return { outputs, outputWarnings };
}
const jobs = require("./jobs")({ launch, killTree, localPath, integer, text, commandLine, collectOutputs, onUpdate: result => send({ event: "job_update", result }) });
async function managedMcpCall(config,name,args,signal){const server=await getServer(config,signal);const timeout=Math.max(120000,(Number(args?.timeoutSeconds||args?.timeout_seconds||args?.timeout||0)+30)*1000);return server.rpc('tools/call',{name,arguments:args??{}},signal,timeout,{preserveServer:true});}
const security = require('./security/client.cjs').createClient({onAdmission:send,onEvent:send,mcpCall:managedMcpCall});

async function runCommand(p, signal) {
  const command = text(p.command, "command");
  const cwd = localPath(p.cwd);
  // FIXME(justified-limits): the 30 s default / 120 s max foreground timeout and
  // 64 KiB default output cap are unverified defaults; longer work is meant to
  // use background jobs, but confirm these numbers against real usage.
  const timeout = integer(p.timeout_ms, 30000, 100, 120000);
  const cap = integer(p.max_output_bytes, 65536, 1, 131072);
  const [executable, args] = commandLine(command);
  abortCheck(signal);
  return new Promise((resolve, reject) => {
    const child = launch(executable, args, { cwd });
    child.stdin.end();
    const output = { stdout: [], stderr: [] };
    let size = 0, truncated = false, timedOut = false, cancelled = false, killing;
    const stop = () => killing ||= killTree(child);
    const abort = () => { cancelled = true; stop(); };
    signal?.addEventListener("abort", abort, { once: true });
    const timer = setTimeout(() => { timedOut = true; stop(); }, timeout);
    for (const stream of ["stdout", "stderr"]) child[stream].on("data", data => {
      const keep = Math.max(0, cap - size);
      if (keep) output[stream].push(data.subarray(0, keep));
      size += Math.min(data.length, keep);
      if (data.length > keep) truncated = true;
    });
    child.once("error", reject);
    child.once("close", async (code, exitSignal) => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
      if (killing) await killing;
      resolve({ exitCode: code, signal: exitSignal, timedOut, cancelled, truncated,
        stdout: Buffer.concat(output.stdout).toString("utf8"), stderr: Buffer.concat(output.stderr).toString("utf8") });
    });
    if (signal?.aborted) abort();
  });
}

async function readFile(p) {
  const target = localPath(p.path);
  const offset = integer(p.offset, 0, 0, Number.MAX_SAFE_INTEGER);
  const count = integer(p.max_bytes, MAX_FILE, 1, MAX_FILE);
  if (p.encoding !== undefined && !["text", "base64"].includes(p.encoding)) throw Error("encoding must be text or base64");
  const handle = await fsp.open(target, "r");
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) throw Error("Path must be a regular file");
    const buffer = Buffer.alloc(count);
    const { bytesRead } = await handle.read(buffer, 0, count, offset);
    return { path: target, size: stat.size, offset, bytesRead, nextOffset: offset + bytesRead,
      truncated: offset + bytesRead < stat.size, encoding: p.encoding || "text",
      content: buffer.subarray(0, bytesRead).toString(p.encoding === "base64" ? "base64" : "utf8") };
  } finally { await handle.close(); }
}
async function writeFile(p) {
  const target = localPath(p.path);
  if (typeof p.content !== "string") throw Error("content must be a string");
  if (p.encoding !== undefined && !["text", "base64"].includes(p.encoding)) throw Error("encoding must be text or base64");
  if (p.overwrite !== undefined && typeof p.overwrite !== "boolean") throw Error("overwrite must be boolean");
  if (p.encoding === "base64" && (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(p.content))) throw Error("Invalid base64");
  const bytes = Buffer.from(p.content, p.encoding === "base64" ? "base64" : "utf8");
  if (bytes.length > 512 * 1024) throw Error("Write exceeds 512 KiB");
  // Create exclusively by default. Overwrite existing regular files only; never
  // follow a symlink or truncate a device through this convenience API.
  if (p.overwrite) {
    const stat = await fsp.lstat(target).catch(error => { if (error.code !== "ENOENT") throw error; return null; });
    if (stat && (!stat.isFile() || stat.isSymbolicLink())) throw Error("Overwrite requires a regular non-symlink file");
  }
  if (p.overwrite) {
    const temporary = path.join(path.dirname(target), ".cert-x-" + require("node:crypto").randomUUID());
    try {
      await fsp.writeFile(temporary, bytes, { flag: "wx" });
      await fsp.rename(temporary, target);
    } finally { await fsp.unlink(temporary).catch(error => { if (error.code !== "ENOENT") throw error; }); }
  } else await fsp.writeFile(target, bytes, { flag: "wx" });
  return { path: target, bytesWritten: bytes.length };
}
async function listDirectory(p) {
  const target = localPath(p.path);
  const offset = integer(p.offset, 0, 0, 1000000);
  const limit = integer(p.limit, 200, 1, 1000);
  const dir = await fsp.opendir(target);
  const entries = [];
  let seen = 0, more = false;
  for await (const entry of dir) {
    if (seen++ < offset) continue;
    if (entries.length === limit) { more = true; break; }
    entries.push({ name: entry.name, type: entry.isSymbolicLink() ? "symlink" : entry.isDirectory() ? "directory" : entry.isFile() ? "file" : "other" });
  }
  return { path: target, entries, nextOffset: more ? offset + entries.length : null };
}

function serverConfig(p) {
  const command = text(p.command, "MCP executable");
  const args = p.args ?? [];
  if (!Array.isArray(args) || args.some(v => typeof v !== "string" || v.includes("\0"))) throw Error("MCP args must be an array of strings");
  const env = p.env ?? {};
  if (!env || typeof env !== "object" || Array.isArray(env) || Object.entries(env).some(([k,v]) => !k || /[=\0]/.test(k) || typeof v !== "string" || v.includes("\0"))) throw Error("MCP env must map names to strings");
  return { command, args, cwd: p.cwd ? localPath(p.cwd) : os.homedir(), env };
}
function mcpExecutable(config) {
  // npm's Windows .cmd shims require cmd.exe quoting. Invoke their JS entrypoints
  // directly instead, preserving every argument without shell interpolation.
  if (process.platform === "win32" && /^(npx|npm)(\.cmd)?$/i.test(config.command)) {
    const name = config.command.toLowerCase().startsWith("npx") ? "npx" : "npm";
    const found = spawnSync("where.exe", [name + ".cmd"], { encoding: "utf8", windowsHide: true });
    for (const shim of (found.stdout || "").trim().split(/\r?\n/)) {
      const cli = path.join(path.dirname(shim), "node_modules", "npm", "bin", name + "-cli.js");
      if (fs.existsSync(cli)) return [process.execPath, [cli, ...config.args]];
    }
    throw Error(`${name} was not found; install Node/npm or specify an executable and argument array`);
  }
  if (process.platform === "win32" && /\.(cmd|bat)$/i.test(config.command)) throw Error("Use an executable (or node plus a JS entrypoint), not a batch script");
  return [config.command, config.args];
}

class StdioServer {
  constructor(config) {
    this.safeError=value=>{let result=String(value);for(const[name,secret]of Object.entries(config.env||{}))if(/KEY|TOKEN|SECRET|PASSWORD/.test(name)&&typeof secret==='string'&&secret.length>=4)result=result.split(secret).join('[private credential]');return result;};
    const [command, args] = mcpExecutable(config);
    this.child = launch(command, args, { cwd: config.cwd, env: { ...process.env, ...config.env } });
    this.pending = new Map();
    this.sequence = 1;
    this.buffer = "";
    this.decoder = new StringDecoder("utf8");
    this.stderr = "";
    this.child.stderr.on("data", data => { this.stderr = (this.stderr + data.toString()).slice(-4000); });
    this.child.stdout.on("data", data => {
      this.buffer += this.decoder.write(data);
      if (Buffer.byteLength(this.buffer) > 4 * 1024 * 1024) return this.close(Error("MCP message exceeds 4 MiB"));
      let index;
      while ((index = this.buffer.indexOf("\n")) >= 0) {
        const line = this.buffer.slice(0, index); this.buffer = this.buffer.slice(index + 1);
        if (!line.trim()) continue;
        try {
          const message = JSON.parse(line);
          for (const item of Array.isArray(message) ? message : [message]) this.receive(item);
        } catch { this.close(Error("MCP stdout must contain newline-delimited JSON-RPC only")); return; }
      }
    });
    this.child.stdin.on("error", error => this.close(error));
    this.child.once("error", error => this.close(error));
    this.child.once("close", code => this.close(Error(this.safeError(`MCP server exited (${code})${this.stderr ? ": " + this.stderr : ""}`))));
    this.ready = this.initialize();
  }
  receive(message) {
    if (!message || message.jsonrpc !== "2.0") throw Error("Invalid JSON-RPC");
    if (message.method) {
      if (message.id !== undefined) this.write(message.method === "ping"
        ? { jsonrpc: "2.0", id: message.id, result: {} }
        : { jsonrpc: "2.0", id: message.id, error: { code: -32601, message: "Client capability unsupported" } });
      return;
    }
    const pending = this.pending.get(message.id);
    if (!pending) return;
    if (message.error) pending.finish(Error(this.safeError(message.error.message || "MCP JSON-RPC error")));
    else if (!Object.hasOwn(message, "result")) pending.finish(Error("MCP response missing result"));
    else pending.finish(null, message.result);
  }
  write(message) {
    if (this.closed) throw this.closed;
    this.child.stdin.write(JSON.stringify(message) + "\n");
  }
  rpc(method, params, signal, timeout = 30000, options = {}) {
    if (this.closed) return Promise.reject(this.closed);
    abortCheck(signal);
    return new Promise((resolve, reject) => {
      const id = this.sequence++;
      const finish = (error, result) => {
        clearTimeout(timer); signal?.removeEventListener("abort", abort); this.pending.delete(id);
        error ? reject(error) : resolve(result);
      };
      const cancel=reason=>{if(options.preserveServer){try{this.write({jsonrpc:'2.0',method:'notifications/cancelled',params:{requestId:id,reason}});}catch{}finish(Error(reason));}else this.close(Error(reason+'; server stopped'));};
      const abort = () => cancel('MCP request cancelled');
      const timer = setTimeout(() => cancel(`MCP ${method} timed out`), timeout);
      this.pending.set(id, { finish });
      signal?.addEventListener("abort", abort, { once: true });
      try { this.write({ jsonrpc: "2.0", id, method, params }); } catch (error) { finish(error); }
    });
  }
  async initialize() {
    const result = await this.rpc("initialize", { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "cert-x", version: "1.0.0" } });
    if (!["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"].includes(result?.protocolVersion)) {
      this.close(Error("Unsupported MCP protocol version")); throw this.closed;
    }
    if (!result.capabilities?.tools) { this.close(Error("MCP server does not support tools")); throw this.closed; }
    this.write({ jsonrpc: "2.0", method: "notifications/initialized" });
  }
  close(error = Error("MCP server stopped")) {
    if (this.closed) return this.killing;
    this.closed = error;
    for (const { finish } of [...this.pending.values()]) finish(error);
    this.child.stdin.end();
    this.killing = killTree(this.child);
    return this.killing;
  }
}
async function getServer(p, signal) {
  const sourceDescriptor=JSON.stringify({command:p?.command,args:p?.args||[],cwd:p?.cwd,env:p?.env||{},envFileRef:p?.envFileRef,secretRef:p?.secretRef});
  let resolved=p;
  if(p?.envFileRef){const content=await fsp.readFile(localPath(p.envFileRef),'utf8');const line=content.split(/\r?\n/).find(x=>x.startsWith('WEBHOOK_SITE_API_KEY='));if(!line)throw Error('The selected env file has no WEBHOOK_SITE_API_KEY');resolved={...p,env:{...p.env,WEBHOOK_SITE_API_KEY:line.slice(21).trim().replace(/^(['"])(.*)\1$/,'$2')}};}
  if(p?.secretRef){if(!/^[a-f0-9-]{36}$/.test(p.secretRef))throw Error('Invalid secret reference');const value=await fsp.readFile(path.join(process.env.CERT_X_SECURITY_ROOT||path.join(process.env.LOCALAPPDATA||os.homedir(),'cert-x','security-runtime'),'secrets',p.secretRef),'utf8');resolved={...resolved,env:{...resolved.env,WEBHOOK_SITE_API_KEY:value}};}
  const config = serverConfig(resolved);
  const key = JSON.stringify(config);
  for (const [oldKey, oldServer] of servers) if (oldServer.closed) servers.delete(oldKey);
  let server = servers.get(key);
  if (!server || server.closed) {
    if (server) servers.delete(key);
    if (servers.size >= 8) throw Error("Maximum of 8 local MCP servers; reconnect to reset");
    server = new StdioServer(config);server.sourceDescriptor=sourceDescriptor;servers.set(key, server);
  }
  const abort = () => server.close(Error("MCP startup cancelled"));
  signal?.addEventListener("abort", abort, { once: true });
  try { abortCheck(signal); await server.ready; abortCheck(signal); return server; }
  finally { signal?.removeEventListener("abort", abort); }
}
async function dispatch(op, p, signal) {
  abortCheck(signal);
  switch (op) {
    case "status": return { version: 1, revision: 7, features: ["command_jobs", "output_files", "security_runtime_v1", "security_runtime_restart", "security_raw_v2", "security_scope_v2", "security_candidate_replay_v2", "mcp_selective_reset"], instance: jobs.instance, platform: process.platform, node: process.version, home: os.homedir() };
    case 'security_status': return security.request('status',{},signal);
    case 'security_restart': return security.request('restart',{explicit:true},signal);
    case 'security_setup': return security.request('setup',p,signal);
    case 'security_dispatch': return security.request('dispatch',p,signal);
    case 'security_cancel': return security.request('cancel',p,signal);
    case 'security_admission_result': return security.reply(p);
    case "command": {
      if (p.background !== undefined && typeof p.background !== "boolean") throw Error("background must be boolean");
      if (p.outputs !== undefined && (!Array.isArray(p.outputs) || p.outputs.length > 16)) throw Error("outputs must be an array of up to 16 paths");
      for (const value of p.outputs || []) localPath(value);
      if (p.background === true) return jobs.start(p, signal);
      return { ...await runCommand(p, signal), ...await collectOutputs(p.outputs) };
    }
    case "job_read": return jobs.read(p);
    case "job_cancel": return jobs.cancel(p);
    case "job_list": return jobs.list(p);
    case "mcp_reset": {if(p.servers!==undefined&&!Array.isArray(p.servers))throw Error('servers must be an array');const selected=p.servers?.map(x=>JSON.stringify({command:x.command,args:x.args||[],cwd:x.cwd,env:x.env||{},envFileRef:x.envFileRef,secretRef:x.secretRef}));let closed=0;for(const[key,server]of servers)if(!selected||selected.includes(server.sourceDescriptor)){await server.close();servers.delete(key);closed++;}return {closed};}
    case "read_file": return readFile(p);
    case "write_file": return writeFile(p);
    case "list_directory": return listDirectory(p);
    case "mcp_list": {
      const server = await getServer(p.server, signal);
      const tools = []; let cursor;
      for (let page = 0; page < 16; page++) {
        const result = await server.rpc("tools/list", cursor ? { cursor } : {}, signal);
        if (!Array.isArray(result?.tools)) throw Error("Invalid MCP tools/list result");
        tools.push(...result.tools);
        if (tools.length > 256) throw Error("MCP server exceeds 256-tool limit");
        cursor = result.nextCursor;
        if (!cursor) return { tools };
      }
      throw Error("MCP tool pagination exceeds 16 pages");
    }
    case "mcp_call": {
      const server = await getServer(p.server, signal);
      return server.rpc("tools/call", { name: text(p.name, "Tool name"), arguments: p.arguments ?? {} }, signal, 120000);
    }
    default: throw Error("Unknown native operation: " + op);
  }
}
async function receive(message) {
  if (!message || typeof message.id !== "string" || message.id.length > 100) return;
  if (message.op === "cancel") {
    requests.get(message.params?.id)?.abort();
    send({ id: message.id, ok: true, result: {} }); return;
  }
  if(message.op==='security_admission_result'){try{send({id:message.id,ok:true,result:security.reply(message.params||{})});}catch(error){send({id:message.id,ok:false,error:error.message});}return;}
  if (requests.has(message.id) || requests.size >= 16) { send({ id: message.id, ok: false, error: "Duplicate ID or too many active requests" }); return; }
  const controller = new AbortController(); requests.set(message.id, controller);
  try { send({ id: message.id, ok: true, result: await dispatch(message.op, message.params || {}, controller.signal) }); }
  catch (error) { send({ id: message.id, ok: false, error: error.message || String(error) }); }
  finally { requests.delete(message.id); }
}
async function shutdown() {
  if (stopping) return; stopping = true;
  for (const controller of requests.values()) controller.abort();
  security.close();
  await Promise.all([...servers.values()].map(server => server.close()));
  await Promise.all([...processes].map(killTree));
  process.exit(0);
}
function main() {
  let buffer = Buffer.alloc(0);
  process.stdin.on("data", data => {
    buffer = Buffer.concat([buffer, data]);
    while (buffer.length >= 4) {
      const length = buffer.readUInt32LE();
      if (!length || length > MAX_FRAME) { shutdown(); return; }
      if (buffer.length < length + 4) break;
      const body = buffer.subarray(4, length + 4); buffer = buffer.subarray(length + 4);
      try { receive(JSON.parse(body.toString("utf8"))); }
      catch { shutdown(); return; }
    }
  });
  process.stdin.on("end", shutdown);
  process.stdin.on("error", shutdown);
  process.stdout.on("error", shutdown);
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}
if (require.main === module) main();
module.exports = { dispatch, serverConfig, mcpExecutable, MAX_FRAME, managedMcpCall };

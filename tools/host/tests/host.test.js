const { test, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { once } = require("node:events");
const { setTimeout: sleep } = require("node:timers/promises");
const hostPath = path.resolve(__dirname, "../ki-host.js");
const fixture = path.join(__dirname, "fixture-mcp.js");

function client(t) {
  const child = spawn(process.execPath, [hostPath], { windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
  let buffer = Buffer.alloc(0), sequence = 0, stderr = "";
  const pending = new Map(), events = [];
  child.stderr.on("data", d => { stderr += d; });
  child.stdout.on("data", d => {
    buffer = Buffer.concat([buffer, d]);
    while (buffer.length >= 4 && buffer.length >= buffer.readUInt32LE() + 4) {
      const size = buffer.readUInt32LE();
      assert.ok(size <= 900 * 1024);
      const message = JSON.parse(buffer.subarray(4, size + 4)); buffer = buffer.subarray(size + 4);
      if (message.event) { events.push(message); continue; }
      const cb = pending.get(message.id); pending.delete(message.id); cb?.(message);
    }
  });
  t.after(async () => {
    if (child.exitCode === null) { const done = once(child, "exit"); child.stdin.end(); await done; }
    assert.equal(stderr, "");
  });
  const send = (op, params = {}, fragmented = false) => {
    const id = String(++sequence);
    const body = Buffer.from(JSON.stringify({ id, op, params })), header = Buffer.alloc(4); header.writeUInt32LE(body.length);
    const frame = Buffer.concat([header, body]);
    const promise = new Promise(resolve => pending.set(id, resolve));
    if (fragmented) { child.stdin.write(frame.subarray(0, 2)); child.stdin.write(frame.subarray(2, 7)); child.stdin.write(frame.subarray(7)); }
    else child.stdin.write(frame);
    return { id, promise };
  };
  return { child, send, events, async rpc(op, params, fragmented) {
    const message = await send(op, params, fragmented).promise;
    if (!message.ok) throw Error(message.error);
    return message.result;
  } };
}
// Temp dirs go after the whole file: a test that fails mid-command leaves PowerShell
// holding its dir as cwd until the host closes, and a per-test rm that threw EPERM
// first would skip the host-closing hook and leave the run hanging. The retries cover a child a
// failing test has just killed, which releases its cwd a moment later.
const dirs = [];
after(() => { for (const dir of dirs) fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5 }); });
function temp() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cert-x-host-"));
  dirs.push(dir);
  return dir;
}
// Waits poll the condition itself and end with the test (its signal aborts on timeout), so each
// test's timeout is the one bound and a slow PowerShell or Node start is not a failure.
async function waitForFile(file, signal) {
  while (!fs.existsSync(file)) await sleep(30, undefined, { signal });
}
async function assertGone(pid, signal) {
  for (;;) {
    try { process.kill(pid, 0); } catch (error) { if (error.code === "ESRCH") return; throw error; }
    await sleep(30, undefined, { signal });
  }
}

test("native framing, concurrent correlation and unsupported operation", { timeout: 10000 }, async t => {
  const c = client(t);
  assert.equal((await c.rpc("status", {}, true)).version, 1);
  const results = await Promise.all(Array.from({ length: 8 }, () => c.rpc("status")));
  assert.equal(results.length, 8);
  await assert.rejects(c.rpc("unknown"), /Unknown native operation/);
});

test("background commands return promptly, stream bounded Unicode output and collect files", { timeout: 20000 }, async t => {
  const dir = temp(), c = client(t), file = path.join(dir, "job.txt"), win = process.platform === "win32";
  const command = win ? `Write-Output 'héllo'; Start-Sleep -Seconds 1; Set-Content -LiteralPath '${file}' -Value 'done'; Write-Output ('界' * 400000)` : `printf héllo; sleep 1; printf done > '${file}'; python3 -c "print('界'*400000)"`;
  const started = await c.rpc("command", { command, cwd: dir, background: true, owner: "task-a", outputs: [file] });
  assert.equal(started.state, "running"); assert.ok(started.jobId);
  await assert.rejects(c.rpc("job_read", { job_id: started.jobId, owner: "task-b" }), /another task/);
  let result;
  while ((result = await c.rpc("job_read", { job_id: started.jobId, owner: "task-a", cursor: 0 })).state === "running") await sleep(50, undefined, { signal: t.signal });
  assert.equal(result.state, "completed"); assert.equal(result.outputs[0].path, file); assert.equal(result.truncated, true);
  assert.equal((await c.rpc("job_read", { job_id: started.jobId, owner: "task-a" })).truncated, true);
  assert.ok(result.chunks.every(chunk => !chunk.text.includes("�")));
  assert.ok(result.chunks.reduce((n, chunk) => n + Buffer.byteLength(chunk.text), 0) <= 65536);
  assert.ok(c.events.some(event => event.event === "job_update" && event.result.state === "completed"));
  assert.equal((await c.rpc("job_list", { owner: "task-b" })).length, 0);
});
test("background jobs cancel, time out and survive MCP configuration resets", { timeout: 15000 }, async t => {
  const dir = temp(), c = client(t), command = process.platform === "win32" ? "Start-Sleep -Seconds 30" : "sleep 30";
  const started = await c.rpc("command", { command, cwd: dir, background: true, owner: "task" });
  await c.rpc("mcp_reset");
  assert.equal((await c.rpc("job_read", { job_id: started.jobId, owner: "task" })).state, "running");
  assert.equal((await c.rpc("job_cancel", { job_id: started.jobId, owner: "task" })).state, "cancelled");
  const timed = await c.rpc("command", { command, cwd: dir, background: true, owner: "task", timeout_ms: 150 });
  let status;
  while (["running", "cancelling"].includes((status = await c.rpc("job_read", { job_id: timed.jobId, owner: "task" })).state)) await sleep(30, undefined, { signal: t.signal });
  assert.equal(status.state, "timed_out");
});
test("local files: paging, binary bytes, exclusive creation, explicit overwrite, invalid inputs", { timeout: 10000 }, async t => {
  const dir = temp(), c = client(t), file = path.join(dir, "例 binary.bin");
  const bytes = Buffer.from([0, 1, 127, 128, 255]);
  assert.equal((await c.rpc("write_file", { path: file, content: bytes.toString("base64"), encoding: "base64" })).bytesWritten, 5);
  await assert.rejects(c.rpc("write_file", { path: file, content: "replace" }), /EEXIST/);
  const first = await c.rpc("read_file", { path: file, max_bytes: 2, encoding: "base64" });
  assert.deepEqual(Buffer.from(first.content, "base64"), bytes.subarray(0, 2));
  assert.equal(first.nextOffset, 2); assert.equal(first.truncated, true);
  const second = await c.rpc("read_file", { path: file, offset: 2, encoding: "base64" });
  assert.deepEqual(Buffer.from(second.content, "base64"), bytes.subarray(2));
  await c.rpc("write_file", { path: file, content: "héllo", overwrite: true });
  assert.equal((await c.rpc("read_file", { path: file })).content, "héllo");
  await c.rpc("write_file", { path: path.join(dir, "second"), content: "" });
  const listing = await c.rpc("list_directory", { path: dir, limit: 1 });
  assert.equal(listing.entries.length, 1); assert.equal(listing.nextOffset, 1);
  assert.equal((await c.rpc("list_directory", { path: dir, offset: 1 })).entries.length, 1);
  await assert.rejects(c.rpc("read_file", { path: "relative.txt" }), /absolute/i);
  await assert.rejects(c.rpc("read_file", { path: dir }), /regular file|EISDIR|EPERM/);
  await assert.rejects(c.rpc("write_file", { path: file, content: "!", encoding: "base64" }), /base64/);
  await assert.rejects(c.rpc("read_file", { path: file, max_bytes: 999999 }), /integer/);
});
test("commands: cwd, output, nonzero exit, bounds, timeout and cancellation", { timeout: 30000 }, async t => {
  const dir = temp(), c = client(t), win = process.platform === "win32";
  const result = await c.rpc("command", { cwd: dir, command: win ? "Write-Output (Get-Location).Path; [Console]::Error.Write('err'); exit 7" : "pwd; printf err >&2; exit 7" });
  assert.equal(result.exitCode, 7); assert.ok(result.stdout.includes(dir)); assert.equal(result.stderr, "err");
  const capped = await c.rpc("command", { cwd: dir, command: win ? "Write-Output ('x' * 10000)" : "printf '%10000s' x", max_output_bytes: 100 });
  assert.equal(capped.truncated, true); assert.equal(Buffer.byteLength(capped.stdout), 100);
  const sleep = win ? "Start-Sleep -Seconds 30" : "sleep 30";
  const timed = await c.rpc("command", { cwd: dir, command: sleep, timeout_ms: 150 });
  assert.equal(timed.timedOut, true);
  const running = c.send("command", { cwd: dir, command: sleep });
  await c.rpc("cancel", { id: running.id });
  const cancelled = await running.promise;
  assert.equal(cancelled.result.cancelled, true);
});
test("stdio MCP: initialization, pagination, Unicode, errors, size limits and restart", { timeout: 20000 }, async t => {
  const dir = temp(), c = client(t), server = { command: process.execPath, args: [fixture], cwd: dir };
  assert.deepEqual((await c.rpc("mcp_list", { server })).tools.map(x => x.name), ["echo", "fail"]);
  const call = name => c.rpc("mcp_call", { server, name, arguments: { text: "你好 héllo" } });
  assert.equal((await call("echo")).content[0].text, "echo:你好 héllo");
  assert.equal((await call("fail")).isError, true);
  await assert.rejects(call("rpc_error"), /Fixture RPC error/);
  await assert.rejects(call("large"), /message limit/);
  await assert.rejects(call("malformed"), /JSON-RPC/);
  assert.equal((await call("echo")).content[0].text, "echo:你好 héllo");
  await assert.rejects(call("crash"), /exited/);
  await assert.rejects(c.rpc("mcp_list", { server: { command: path.join(dir, "missing-executable") } }), /ENOENT/);
});
test("cancellation and native disconnect terminate MCP children", { timeout: 20000 }, async t => {
  const dir = temp(), c = client(t), pidFile = path.join(dir, "pid");
  const server = { command: process.execPath, args: [fixture], env: { PID_FILE: pidFile } };
  await c.rpc("mcp_list", { server });
  const pid = Number(fs.readFileSync(pidFile));
  const running = c.send("mcp_call", { server, name: "hang" });
  await new Promise(r => setTimeout(r, 80));
  await c.rpc("cancel", { id: running.id });
  assert.equal((await running.promise).ok, false);
  await assertGone(pid, t.signal);
  await c.rpc("mcp_list", { server });
  const secondPid = Number(fs.readFileSync(pidFile));
  const done = once(c.child, "exit"); c.child.stdin.end(); await done;
  await assertGone(secondPid, t.signal);
});
test("cancelling MCP initialization terminates the child", { timeout: 10000 }, async t => {
  const dir = temp(), c = client(t), pidFile = path.join(dir, "pid");
  const running = c.send("mcp_list", { server: { command: process.execPath, args: [fixture], env: { HANG_INIT: "1", PID_FILE: pidFile } } });
  await waitForFile(pidFile, t.signal);
  await c.rpc("cancel", { id: running.id });
  assert.equal((await running.promise).ok, false);
  await assertGone(Number(fs.readFileSync(pidFile)), t.signal);
});

test("command cancellation kills the shell's child process", { timeout: 15000 }, async t => {
  const dir = temp(), c = client(t), script = path.join(dir, "child.js"), pidFile = path.join(dir, "child.pid");
  fs.writeFileSync(script, "require('fs').writeFileSync(process.argv[2], String(process.pid)); setInterval(() => {}, 1000);");
  const quote = value => "'" + value.replaceAll("'", process.platform === "win32" ? "''" : "'\\''") + "'";
  const command = (process.platform === "win32" ? "& " : "") + [process.execPath, script, pidFile].map(quote).join(" ");
  const running = c.send("command", { cwd: dir, command });
  await waitForFile(pidFile, t.signal);
  await c.rpc("cancel", { id: running.id });
  assert.equal((await running.promise).result.cancelled, true);
  await assertGone(Number(fs.readFileSync(pidFile)), t.signal);
});

test("oversized native frames close the host", { timeout: 10000 }, async t => {
  const c = client(t), header = Buffer.alloc(4);
  header.writeUInt32LE(1024 * 1024);
  const done = once(c.child, "exit"); c.child.stdin.write(header); await done;
  assert.equal(c.child.exitCode, 0);
});

test("Windows npx shim resolves to Node without shell argument interpolation", { skip: process.platform !== "win32" }, () => {
  const { mcpExecutable } = require("../ki-host.js");
  const args = ["-y", "a&b", "with spaces", "\"quoted\""];
  const [command, actual] = mcpExecutable({ command: "npx", args });
  assert.equal(command, process.execPath); assert.match(actual[0], /npx-cli\.js$/);
  assert.deepEqual(actual.slice(1), args);
  const version = require("node:child_process").execFileSync(command, [actual[0], "--version"], { windowsHide: true, encoding: "utf8" });
  assert.match(version, /^\d+\./);
});

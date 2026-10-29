const { test } = require("node:test");
const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const { PassThrough } = require("node:stream");
const createJobs = require("../jobs.js");

async function started(overrides) {
  const child = Object.assign(new EventEmitter(), { pid: 1, stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough() });
  const jobs = createJobs({ launch: () => child, killTree: async () => {}, localPath: value => value, integer: (value, fallback) => value ?? fallback, text: value => value,
    commandLine: command => ["shell", [command]], collectOutputs: async () => ({ outputs: [], outputWarnings: [] }), ...overrides(child) });
  const starting = jobs.start({ command: "write out.txt", cwd: "/work", owner: "task", outputs: ["/work/out.txt"], timeout_ms: 1000 });
  await new Promise(setImmediate); child.emit("spawn");
  return { child, jobs, jobId: (await starting).jobId };
}

test("a finished job reports its terminal state only once its outputs are collected", { timeout: 5000 }, async () => {
  let collected;
  const { child, jobs, jobId } = await started(() => ({ collectOutputs: () => new Promise(resolve => { collected = resolve; }) }));
  child.emit("close", 0);
  await new Promise(setImmediate);
  assert.equal(jobs.read({ job_id: jobId, owner: "task" }).state, "running");
  collected({ outputs: [{ path: "/work/out.txt", size: 4 }], outputWarnings: [] });
  await new Promise(setImmediate);
  const done = jobs.read({ job_id: jobId, owner: "task" });
  assert.equal(done.state, "completed"); assert.equal(done.exitCode, 0); assert.deepEqual(done.outputs, [{ path: "/work/out.txt", size: 4 }]);
});

test("a job whose process tree could not be fully stopped says so", { timeout: 5000 }, async () => {
  const warning = "Child processes may still be running.";
  const { jobs, jobId } = await started(child => ({ killTree: async () => { setImmediate(() => child.emit("close", 1)); return warning; } }));
  const cancelled = await jobs.cancel({ job_id: jobId, owner: "task" });
  assert.equal(cancelled.state, "cancelled"); assert.equal(cancelled.warning, warning);
});

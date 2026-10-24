"use strict";
const { randomUUID } = require("node:crypto");
const { StringDecoder } = require("node:string_decoder");

module.exports = function createJobs({ launch, killTree, localPath, integer, text, commandLine, collectOutputs, onUpdate = () => {} }) {
  const jobs = new Map(), instance = randomUUID(), maxRetained = 1024 * 1024;
  function find(params) {
    const job = jobs.get(text(params.job_id, "job_id"));
    if (!job) throw Error("Job no longer exists. The native host may have restarted.");
    if (job.owner !== params.owner) throw Error("Job belongs to another task.");
    return job;
  }
  function summary(job) {
    return { jobId: job.id, owner: job.owner, instance, command: job.command.slice(0, 2000), commandTruncated: job.command.length > 2000, cwd: job.cwd, state: job.state, startedAt: job.startedAt, endedAt: job.endedAt,
      exitCode: job.exitCode, error: job.error, outputs: job.outputs || [], outputWarnings: job.outputWarnings || [], firstCursor: job.chunks[0]?.seq ?? job.next, nextCursor: job.next };
  }
  async function start(params, signal) {
    const command = text(params.command, "command"), cwd = localPath(params.cwd), owner = text(params.owner, "task owner");
    // Justified: 30 min default suits scans/recon scripts; the 60 min ceiling
    // bounds orphaned processes across host restarts while allowing long
    // observation runs — raise it when a real workflow demands longer, not
    // by default. The 8-concurrent and 32-retained counts match the 8-slot
    // MCP/process budget; 1 MiB output per job bounds host memory at 32 MiB
    // worst case across the retention window.
    const timeout = integer(params.timeout_ms, 30 * 60 * 1000, 100, 60 * 60 * 1000);
    if ([...jobs.values()].filter(job => ["running", "cancelling"].includes(job.state)).length >= 8) throw Error("Up to 8 background commands can run at once.");
    while (jobs.size >= 32) { const completed = [...jobs.values()].find(job => !["running", "cancelling"].includes(job.state)); if (!completed) break; jobs.delete(completed.id); }
    const job = { id: randomUUID(), owner, command, cwd, startedAt: Date.now(), state: "running", chunks: [], retained: 0, next: 0, exitCode: null };
    const [executable, args] = commandLine(command);
    const child = launch(executable, args, { cwd }); job.child = child; jobs.set(job.id, job); child.stdin.end();
    const append = (stream, value) => {
      for (let offset = 0; offset < value.length;) {
        let end = Math.min(offset + 4096, value.length);
        if (end < value.length && /[\uD800-\uDBFF]/.test(value[end - 1])) end--;
        const content = value.slice(offset, end), bytes = Buffer.byteLength(content);
        job.chunks.push({ seq: job.next++, stream, text: content, bytes }); job.retained += bytes; offset = end;
        while (job.retained > maxRetained || job.chunks.length > 4096) job.retained -= job.chunks.shift().bytes;
      }
    };
    for (const stream of ["stdout", "stderr"]) {
      const decoder = new StringDecoder("utf8");
      child[stream].on("data", bytes => append(stream, decoder.write(bytes)));
      child[stream].on("end", () => append(stream, decoder.end()));
    }
    job.stop = reason => {
      if (!job.stopping) { job.stopping = reason; job.state = "cancelling"; job.killing = killTree(child); onUpdate(summary(job)); }
      return job.killing;
    };
    job.timer = setTimeout(() => job.stop("timed_out"), timeout);
    job.done = new Promise(resolve => {
      child.once("error", error => { job.error = error.message; });
      child.once("close", async code => {
        clearTimeout(job.timer); if (job.killing) await job.killing;
        job.exitCode = code; job.state = job.stopping || (code === 0 ? "completed" : "failed"); job.endedAt = Date.now();
        try { Object.assign(job, await collectOutputs(params.outputs)); } catch (error) { job.outputWarnings = [error.message]; }
        onUpdate(summary(job));
        resolve(summary(job));
      });
    });
    // Starting means spawned successfully, not merely queued by Node.
    const abort = () => job.stop("cancelled"); signal?.addEventListener("abort", abort, { once: true });
    try {
      if (signal?.aborted) abort();
      await new Promise((resolve, reject) => { child.once("spawn", resolve); child.once("error", reject); });
      if (signal?.aborted) { await job.done; signal.throwIfAborted(); }
    } finally { signal?.removeEventListener("abort", abort); }
    return summary(job);
  }
  function read(params) {
    const job = find(params), first = job.chunks[0]?.seq ?? job.next;
    const requested = integer(params.cursor, 0, 0, Number.MAX_SAFE_INTEGER);
    if (requested > job.next) throw Error("Cursor is ahead of the job output.");
    const max = integer(params.max_bytes, 65536, 16384, 131072);
    let used = 0, cursor = Math.max(first, requested); const chunks = [];
    for (const chunk of job.chunks) if (chunk.seq >= cursor) {
      if (used + chunk.bytes > max) break;
      chunks.push({ seq: chunk.seq, stream: chunk.stream, text: chunk.text }); used += chunk.bytes; cursor = chunk.seq + 1;
    }
    return { ...summary(job), chunks, nextCursor: cursor, hasMore: cursor < job.next, truncated: requested < first };
  }
  async function cancel(params) {
    const job = find(params);
    if (["running", "cancelling"].includes(job.state)) { await job.stop("cancelled"); await job.done; }
    return summary(job);
  }
  function list(params) { return [...jobs.values()].filter(job => params.all === true || job.owner === params.owner).map(summary); }
  return { start, read, cancel, list, instance };
};

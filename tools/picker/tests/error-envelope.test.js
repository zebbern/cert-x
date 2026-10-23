// Behavior contracts for the error envelope and tool-failure telemetry.
// The bundle wiring itself (kiPolicyWrap calling these helpers) is asserted at
// build time by apply-picker.js's self-check; these tests cover the behavior.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

// ki-telemetry.js touches chrome and setTimeout only inside function bodies, so
// stubs on globals before require are enough; the flush timer never needs to run.
const stored = {};
global.chrome = {
  storage: { local: { get: async key => (stored[key] !== undefined ? { [key]: stored[key] } : {}), set: async update => Object.assign(stored, update) } },
  tabs: { query: async () => [
    { id: 101, url: "https://dvwa.local/vulnerabilities/", title: "DVWA", active: true },
    { id: 87, url: "https://example.com/", title: "Example", active: false },
  ] },
};
const realSetTimeout = global.setTimeout;
global.setTimeout = () => 0;
const telemetry = require("../src/ki-telemetry.js");
global.setTimeout = realSetTimeout;

test("a failed tab-reference error embeds the open tabs for immediate retry", async () => {
  const output = await telemetry.kiErrorEnvelope({ name: "attach_tab" }, Error("no tab matching 42 in this session — use navigate to open it"), "chat");
  const envelope = JSON.parse(output);
  assert.ok(envelope.error.includes("no tab matching"));
  assert.equal(envelope.tabs[0].tabId, 101);
  assert.equal(envelope.tabs[0].url, "https://dvwa.local/vulnerabilities/");
  assert.equal(envelope.tabs.length, 2);
  assert.ok(envelope.hint.includes("Pick a tabId"));
});

test("unrelated errors keep their plain message", async () => {
  const message = await telemetry.kiErrorEnvelope({ name: "local_run_command" }, Error("disk full"), "chat");
  assert.equal(message, "disk full");
});

test("a structured input error keeps its code and recovery text", async () => {
  const error = Error("Select a valid browser tab: tabId must be a non-negative integer.");
  error.code = "invalid_target_tab"; error.retryable = false; error.recovery = "Pick a tabId from tabs.";
  const envelope = JSON.parse(await telemetry.kiErrorEnvelope({ name: "security_start_scan" }, error, "chat"));
  assert.equal(envelope.code, "invalid_target_tab");
  assert.equal(envelope.retryable, false);
  assert.equal(envelope.recovery, "Pick a tabId from tabs.");
  assert.equal(envelope.tabs[0].tabId, 101);
});

test("telemetry counts errors and the tool the model called next", () => {
  telemetry.kiTelemetryRecord({ name: "attach_tab" }, "chat", true);
  telemetry.kiTelemetryRecord({ name: "navigate" }, "chat", false);
  const summary = telemetry.kiTelemetrySummary();
  assert.equal(summary.errors[0].tool, "attach_tab");
  assert.equal(summary.errors[0].count, 1);
  assert.equal(summary.afterError[0].failed, "attach_tab");
  assert.equal(summary.afterError[0].follower, "navigate");
  assert.equal(summary.afterError[0].count, 1);
});

test("errors in one chat do not leak transitions into another", () => {
  telemetry.kiTelemetryRecord({ name: "attach_tab" }, "chat-a", true);
  telemetry.kiTelemetryRecord({ name: "screenshot" }, "chat-b", false);
  const summary = telemetry.kiTelemetrySummary();
  // chat-b's success must not consume chat-a's pending error.
  assert.ok(summary.afterError.every(entry => entry.follower !== "screenshot"));
});

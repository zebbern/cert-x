// Contracts for the provider-refusal wrapper: an SSE refusal inside an HTTP
// 200 stream must surface as a named, actionable error; clean streams and
// unrelated endpoints must pass through byte-for-byte. On chat-completion
// streams, SSE comments (OpenRouter's keep-alive) become liveness events.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { kiRefusalFetchWrapper, kiRefusalError, kiSubagentFailure, KI_ALIVE_EVENT } = require("../src/ki-provider-compat.js");

const sse = parts => new Response(
  new ReadableStream({
    start(controller) { for (const part of parts) controller.enqueue(new TextEncoder().encode(part)); controller.close(); }
  }),
  { status: 200, headers: { "content-type": "text/event-stream" } }
);
const readAll = async body => new Response(body).text();

test("a content_filter refusal inside a 200 stream fails with a named, actionable error", async () => {
  const wrapped = kiRefusalFetchWrapper(async () => sse([
    'data: {"choices":[{"delta":{"role":"assistant","content":""}}]}\n\n',
    'data: {"choices":[{"delta":{"refusal":"This request triggered restrictions on violative cyber content"},"finish_reason":null}]}\n\n',
    'data: [DONE]\n\n'
  ]));
  const response = await wrapped("https://openrouter.ai/api/v1/chat/completions", { method: "POST" });
  await assert.rejects(() => readAll(response.body), /provider refused this request.*mimo-v2\.6/s);
});

test("a refusal marker split across network chunks is still detected", async () => {
  const wrapped = kiRefusalFetchWrapper(async () => sse([
    'data: {"choices":[{"delta":{"refu',
    'sal":"blocked"},"finish_reason":"content_filter"}]}\n\n'
  ]));
  const response = await wrapped("https://openrouter.ai/api/v1/chat/completions", { method: "POST" });
  await assert.rejects(() => readAll(response.body), /provider refused this request/);
});

test("clean streams pass through unchanged, including refusal:null fields", async () => {
  const body = 'data: {"choices":[{"delta":{"content":"ok","refusal":null}}]}\n\ndata: [DONE]\n\n';
  const wrapped = kiRefusalFetchWrapper(async () => sse([body]));
  const response = await wrapped("https://openrouter.ai/api/v1/chat/completions", { method: "POST" });
  assert.equal(await readAll(response.body), body);
});

test("an SSE comment on a chat stream becomes a liveness event; data lines pass through unchanged", async () => {
  const data = 'data: {"choices":[{"delta":{"content":"ok"}}]}\n\ndata: [DONE]\n\n';
  const wrapped = kiRefusalFetchWrapper(async () => sse([": OPENROUTER PROCESSING\n\n", data]));
  const response = await wrapped("https://openrouter.ai/api/v1/chat/completions", { method: "POST" });
  assert.equal(await readAll(response.body), KI_ALIVE_EVENT + "\n" + data);
  assert.deepEqual(JSON.parse(KI_ALIVE_EVENT.slice(6)).choices[0].delta, { ki_alive: true });
});

test("a comment split across network chunks or ending in CRLF is still seen", async () => {
  const data = 'data: {"choices":[{"delta":{"content":"é"}}]}\r\n\r\n';
  const bytes = new TextEncoder().encode(data);
  const wrapped = kiRefusalFetchWrapper(async () => new Response(new ReadableStream({
    start(controller) {
      for (const part of [": OPENROUTER PRO", "CESSING\r\n\r\n"]) controller.enqueue(new TextEncoder().encode(part));
      controller.enqueue(bytes.slice(0, 35)); controller.enqueue(bytes.slice(35)); // splits the two-byte é
      controller.close();
    }
  }), { status: 200, headers: { "content-type": "text/event-stream" } }));
  const response = await wrapped("https://openrouter.ai/api/v1/chat/completions", { method: "POST" });
  assert.equal(await readAll(response.body), KI_ALIVE_EVENT + "\r\n" + data);
});

test("Anthropic message streams keep their comments", async () => {
  const body = ": keep-alive\n\nevent: ping\ndata: {\"type\":\"ping\"}\n\n";
  const wrapped = kiRefusalFetchWrapper(async () => sse([body]));
  const response = await wrapped("https://api.anthropic.com/v1/messages", { method: "POST" });
  assert.equal(await readAll(response.body), body);
});

test("a failed subagent says whether delegating again can work", () => {
  const parse = (error, cls) => JSON.parse(kiSubagentFailure(error, cls));
  for (const cls of ["timeout", "network", "provider-error", "provider-generic", "rate-limited"]) {
    const result = parse(Error("The response stream stalled"), cls);
    assert.equal(result.retryable, true, cls);
    assert.match(result.error, /^Subagent interrupted: The response stream stalled/);
    assert.match(result.recovery, /graph_write calls persist/);
  }
  for (const cls of ["auth", "quota-exhausted", "no-api-key", "connection-gone", "model-unavailable", "client-config"]) {
    const result = parse(Error("402 Insufficient credits"), cls);
    assert.equal(result.retryable, false, cls);
    assert.equal(result.userAction, true, cls);
    assert.match(result.recovery, /fails the same way/);
  }
  // The stream wrapper's refusal reaches the runner as a generic provider error.
  const refused = parse(Error("Error: " + kiRefusalError().message), "provider-generic");
  assert.equal(refused.retryable, false);
  assert.equal(refused.userAction, true);
});

test("non-chat endpoints are not wrapped at all", async () => {
  const original = { passthrough: true };
  const wrapped = kiRefusalFetchWrapper(async () => original);
  assert.equal(await wrapped("https://openrouter.ai/api/v1/models"), original);
});

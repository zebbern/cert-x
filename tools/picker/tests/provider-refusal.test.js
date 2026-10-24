// Contracts for the provider-refusal wrapper: an SSE refusal inside an HTTP
// 200 stream must surface as a named, actionable error; clean streams and
// unrelated endpoints must pass through byte-for-byte.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { kiRefusalFetchWrapper } = require("../src/ki-provider-compat.js");

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

test("non-chat endpoints are not wrapped at all", async () => {
  const original = { passthrough: true };
  const wrapped = kiRefusalFetchWrapper(async () => original);
  assert.equal(await wrapped("https://openrouter.ai/api/v1/models"), original);
});

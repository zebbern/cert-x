const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");
const source = fs.readFileSync(path.join(__dirname, "../src/ki-browser-control.js"), "utf8");
const url = "ws://127.0.0.1:10086/ws";
const flush = () => new Promise(resolve => setImmediate(resolve));
function fixture() {
  const store = { local_url: url, ws_should_connect: false, ws_client_id: "fixture" }, sockets = [], calls = [], timers = new Map(), listeners = [];
  let sequence = 0, status = { running: true, version: "v2.0.24", name: "Fixture controller" }, failWrite = false, fetcher;
  class Socket {
    static OPEN = 1;
    constructor(endpoint) { this.url = endpoint; this.readyState = 1; this.events = {}; this.sent = []; sockets.push(this); }
    addEventListener(name, fn) { this.events[name] = fn; }
    send(data) { this.sent.push(JSON.parse(data)); }
    close() { this.closed = true; this.events.close?.({ code: 1000 }); }
    emit(name, value) { this.events[name]?.(value); }
    message(value) { this.emit("message", { data: JSON.stringify(value) }); }
  }
  const context = vm.createContext({ console, URL, Date, crypto: require("node:crypto").webcrypto, AbortSignal, AbortController,
    kiPolicyExternal: async (_name, _args, _signal, execute) => execute(), kiPolicyRecheck: async () => {},
    setTimeout(fn) { timers.set(++sequence, fn); return sequence; }, clearTimeout(id) { timers.delete(id); },
    WebSocket: Socket, fetch: (...args) => fetcher ? fetcher(...args) : Promise.resolve({ ok: true, json: async () => status }),
    chrome: { alarms: { create() {} }, runtime: { id: "test", getManifest: () => ({ version: "1.0.0" }), getURL: file => "chrome-extension://test/" + file, onMessage: { addListener: fn => listeners.push(fn) } },
      storage: { local: { get: async () => ({ ...store }), set: async data => { if (failWrite) throw Error("storage unavailable"); Object.assign(store, data); } } } },
  });
  vm.runInContext(source, context);
  const client = new context.KiBrowserControl({ onToolCall: async (name, args) => { calls.push({ name, args }); return "done"; } });
  context.XB = client;
  return { context, client, store, sockets, calls, timers, failWrite: () => failWrite = true, status: value => status = value, fetcher: value => fetcher = value,
    request: (message, sender) => new Promise(resolve => listeners[0]({ type: "KI_BROWSER_CONTROL", ...message }, sender, resolve)),
    async connect() { await client.connect(url, true); sockets.at(-1).emit("open"); },
    async hello() { sockets.at(-1).message({ type: "hello_ack", payload: { daemonVersion: "2.0.24" } }); await flush(); },
  };
}
test("Connect enables desired connection; saved old intent alone does not authorize", async () => {
  const f = fixture(); f.store.ws_should_connect = true;
  await f.client.start(); assert.equal(f.sockets.length, 0);
  await assert.rejects(f.client.connect(url), /authorize/);
  await f.connect(); assert.equal(f.sockets.length, 1); assert.equal(f.store.ws_should_connect, true);
  assert.equal(f.client.isConnected(), false);
  assert.equal(f.sockets[0].sent[0].type, "hello");
});
test("handshake and status must agree before commands are dispatched", async () => {
  const f = fixture(); await f.connect();
  f.sockets[0].message({ type: "tool_call", requestId: "early", payload: { name: "click" } }); await flush();
  assert.equal(f.calls.length, 0); assert.match(f.sockets[0].sent.at(-1).payload.error, /not authorized and verified/);
  await f.hello(); assert.equal(f.client.isConnected(), true);
  assert.equal((await f.client.snapshot()).controller.name, "Fixture controller");
  f.sockets[0].message({ type: "tool_call", requestId: "ok", payload: { name: "list_browser_tabs" } }); await flush();
  assert.equal(f.calls.length, 1);
  assert.equal(f.sockets[0].sent.at(-1).payload.data, "done");
});
test("plain WebSocket, incompatible status and mismatched version are not connected", async () => {
  const plain = fixture(); await plain.connect();
  [...plain.timers.values()][0](); assert.equal(plain.client.isConnected(), false); assert.match(plain.client.reason, /handshake/);
  for (const status of [{ running: false, version: "2.0.24" }, { running: true, version: "99.0.0" }, { running: true }]) {
    const f = fixture(); f.status(status); await f.connect(); await f.hello();
    assert.equal(f.client.isConnected(), false); assert.equal(f.sockets[0].closed, true);
  }
});
test("disconnect revokes authorization, stops retries and rejects subsequent commands", async () => {
  const f = fixture(); await f.connect(); await f.hello();
  await f.client.disconnect(); await f.client.reconcile();
  assert.equal(f.store.ws_should_connect, false); assert.equal(f.store.ki_browser_control_grant, null);
  assert.equal(f.timers.size, 0); assert.equal(f.sockets.length, 1);
  await f.client.handleToolCall({ payload: { name: "click" } }); assert.equal(f.calls.length, 0);
});
test("disconnect during handshake cannot be reversed by a late status response", async () => {
  const f = fixture(); let resolve;
  f.fetcher(() => new Promise(r => resolve = r)); await f.connect();
  f.sockets[0].message({ type: "hello_ack" }); await f.client.disconnect();
  resolve({ ok: true, json: async () => ({ running: true, version: "2.0.24" }) }); await flush();
  assert.equal(f.client.isConnected(), false); assert.equal(f.client.controller, null);
});
test("disconnect fails closed if persisted revocation fails", async () => {
  const f = fixture(); await f.connect(); await f.hello(); f.failWrite();
  await assert.rejects(f.client.disconnect(), /storage/); await f.client.reconcile();
  assert.equal(f.client.isConnected(), false); assert.equal(f.sockets.length, 1);
});
test("close code 4409 reports another browser; invalid and non-TLS remote endpoints are rejected", async () => {
  const f = fixture(); await f.connect(); f.sockets[0].emit("close", { code: 4409 });
  assert.match(f.client.reason, /another browser/);
  for (const address of ["ws://example.com", "http://localhost", "wss://user:pass@example.com", "wss://example.com/?token=x", "wss://example.com/other"]) {
    await assert.rejects(f.client.connect(address, true));
  }
  assert.equal(f.context.kiBrowserUrl("wss://example.com"), "wss://example.com/ws");
});
test("content scripts cannot authorize endpoints; settings requires explicit confirmation", async () => {
  const f = fixture();
  assert.equal((await f.request({ op: "connect", authorize: true, url }, { id: "test", url: "https://example.com" })).ok, false);
  assert.equal((await f.request({ op: "connect", url }, { id: "test", url: "chrome-extension://test/providers/providers.html" })).ok, false);
  assert.equal(f.sockets.length, 0);
});

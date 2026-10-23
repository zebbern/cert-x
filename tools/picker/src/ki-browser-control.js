// Endpoint authorization for the legacy WebBridge protocol. This is not
// cryptographic agent authentication: the companion must implement that too.
var KI_BROWSER_GRANT = "ki_browser_control_grant";
function kiBrowserUrl(value = "ws://127.0.0.1:10086/ws") {
  let text = String(value).trim();
  if (!text) text = "ws://127.0.0.1:10086/ws";
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) text = "ws://" + text;
  const url = new URL(text);
  if (!["ws:", "wss:"].includes(url.protocol)) throw Error("Use a ws:// or wss:// address.");
  if (url.username || url.password || url.search || url.hash) throw Error("Use an address without credentials, query parameters or fragments.");
  const local = ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname.toLowerCase());
  if (!local && url.protocol !== "wss:") throw Error("Connections outside this computer require wss:// (TLS).");
  if (url.pathname !== "/" && url.pathname !== "/ws") throw Error("WebBridge uses the /ws endpoint.");
  url.pathname = "/ws";
  return url.toString();
}
var KiBrowserControl = class {
  socket = null;
  state = "disconnected";
  currentUrl = "";
  controller = null;
  reason = "";
  epoch = 0;
  connectingTimer = null;
  fastRetryTimer = null;
  fastRetryAttempt = 0;
  lastActivityAt = 0;
  verifying = false;
  blocked = false;
  reconciling = null;
  revoked = false;
  permissionAbort = null;
  constructor(hooks) { Object.assign(this, hooks); }
  isConnected() { return this.state === "connected"; }
  getServerUrl() { return this.currentUrl; }
  isReconcileAlarm(alarm) { return alarm === "webbridge-reconcile"; }
  async start() {
    chrome.alarms.create("webbridge-reconcile", { periodInMinutes: .5 });
    await this.reconcile();
  }
  async getDesired() {
    const data = await chrome.storage.local.get(["ws_should_connect", "local_url", KI_BROWSER_GRANT]);
    return { shouldConnect: data.ws_should_connect === true, url: data.local_url || "ws://127.0.0.1:10086/ws", grant: data[KI_BROWSER_GRANT] };
  }
  async snapshot() {
    const desired = await this.getDesired();
    return { state: this.state, connected: this.isConnected(), url: this.currentUrl || desired.url,
      controller: this.controller, reason: this.reason, authorized: desired.grant?.url === (this.currentUrl || desired.url),
      reconnect: desired.shouldConnect, authentication: "endpoint-authorization" };
  }
  async connect(value, authorize = false) {
    const url = kiBrowserUrl(value);
    const epoch = ++this.epoch;
    this.teardown();
    const desired = await this.getDesired();
    if (epoch !== this.epoch) return;
    if (!authorize && desired.grant?.url !== url) throw Error("Open Browser control to authorize this controller.");
    await chrome.storage.local.set({ local_url: url, ws_should_connect: true,
      ...(authorize ? { [KI_BROWSER_GRANT]: { url, approvedAt: Date.now() } } : {}) });
    if (epoch !== this.epoch) return;
    this.revoked = false; this.blocked = false; this.reason = ""; this.fastRetryAttempt = 0;
    if (this.reconciling) await this.reconciling;
    if (epoch !== this.epoch) return;
    await this.reconcile();
  }
  async disconnect() {
    ++this.epoch;
    this.revoked = true;
    this.teardown(); this.reason = ""; this.blocked = false;
    await chrome.storage.local.set({ ws_should_connect: false, [KI_BROWSER_GRANT]: null });
  }
  async reconcile() {
    if (this.reconciling) return this.reconciling;
    this.reconciling = this.reconcileOnce();
    try { await this.reconciling; } finally { this.reconciling = null; }
  }
  async reconcileOnce() {
    if (this.revoked) return;
    const epoch = this.epoch, desired = await this.getDesired();
    if (epoch !== this.epoch) return;
    if (!desired.shouldConnect) { if (this.socket) this.teardown(); return; }
    let url;
    try { url = kiBrowserUrl(desired.url); } catch (error) { this.reason = error.message; return; }
    if (desired.grant?.url !== url) { this.reason = "Authorize this controller to connect."; return; }
    if (this.blocked || this.state === "connecting") return;
    if (this.isConnected() && this.isLinkAlive()) { this.send({ type: "ping" }); return; }
    this.teardown();
    const id = await this.getClientId();
    if (epoch === this.epoch) this.openSocket(url, id);
  }
  async getClientId() {
    const data = await chrome.storage.local.get("ws_client_id");
    if (typeof data.ws_client_id === "string" && data.ws_client_id) return data.ws_client_id;
    const id = crypto.randomUUID(); await chrome.storage.local.set({ ws_client_id: id }); return id;
  }
  isLinkAlive() { return Date.now() - this.lastActivityAt <= 45000; }
  markActive() { this.lastActivityAt = Date.now(); }
  async testConnection(url) {
    if (kiBrowserUrl(url) === this.currentUrl && this.isConnected() && this.isLinkAlive()) return { ok: true };
    return { ok: false, reason: "Use Browser control to authorize and verify the controller." };
  }
  openSocket(url, clientId) {
    this.clearFastRetryTimer(); this.currentUrl = url; this.controller = null; this.reason = ""; this.verifying = false;
    this.setState("connecting");
    const endpoint = new URL(url); endpoint.searchParams.set("client", clientId);
    let socket;
    try { socket = new WebSocket(endpoint.toString()); }
    catch { this.reason = "Could not open the connection."; this.setState("disconnected"); return; }
    this.socket = socket;
    this.permissionAbort = new AbortController();
    this.connectingTimer = setTimeout(() => {
      if (this.socket !== socket || this.isConnected()) return;
      this.reason = "No compatible handshake. Check that WebBridge is running.";
      this.blocked = true; this.teardown();
    }, 10000);
    socket.addEventListener("open", () => {
      if (this.socket !== socket) { socket.close(); return; }
      this.markActive();
      this.send({ type: "hello", payload: { extensionVersion: chrome.runtime.getManifest().version } });
    });
    socket.addEventListener("message", event => {
      if (this.socket !== socket) return;
      this.markActive();
      try {
        if (typeof event.data !== "string" || event.data.length > 1024 * 1024) throw Error("Invalid message size");
        this.handleMessage(JSON.parse(event.data));
      } catch { this.reason = "Controller sent an invalid protocol message."; this.blocked = true; this.teardown(); }
    });
    socket.addEventListener("close", event => {
      if (this.socket !== socket) return;
      this.socket = null; this.controller = null; this.clearConnectingTimer(); this.setState("disconnected");
      this.permissionAbort?.abort();
      if (event.code === 4409) this.reason = "This controller is already connected to another browser.";
      else { this.reason ||= "Connection lost. Retrying…"; this.scheduleFastRetry(); }
      this.onDisconnect?.();
    });
    socket.addEventListener("error", () => {
      if (this.socket === socket) this.reason = "Controller unavailable. Start WebBridge, then try again.";
    });
  }
  async verifyHello(message) {
    if (this.verifying || this.isConnected()) return;
    this.verifying = true;
    const socket = this.socket, epoch = this.epoch;
    try {
      const endpoint = new URL(this.currentUrl);
      endpoint.protocol = endpoint.protocol === "wss:" ? "https:" : "http:"; endpoint.pathname = "/status";
      const response = await fetch(endpoint.toString(), { signal: AbortSignal.timeout(3000), redirect: "error" });
      if (!response.ok) throw Error("Controller status check failed.");
      const status = await response.json();
      const version = status?.version;
      if (status?.running !== true || typeof version !== "string" || !/^v?\d+\.\d+\.\d+$/.test(version)) throw Error("The service is not a compatible WebBridge controller.");
      const ackVersion = message.payload?.daemonVersion ?? message.payload?.version;
      if (ackVersion !== undefined && String(ackVersion).replace(/^v/, "") !== version.replace(/^v/, "")) throw Error("Controller handshake and status versions do not match.");
      const desired = await this.getDesired();
      if (socket !== this.socket || epoch !== this.epoch) return;
      if (!desired.shouldConnect || desired.grant?.url !== this.currentUrl) { this.teardown(); return; }
      const name = message.payload?.name || status.name || "WebBridge";
      this.controller = { name: String(name).slice(0, 80), version, identityVerified: false };
      this.clearConnectingTimer(); this.fastRetryAttempt = 0; this.reason = ""; this.setState("connected");
    } catch (error) {
      if (socket !== this.socket || epoch !== this.epoch) return;
      this.reason = error.message; this.blocked = true; this.teardown();
    } finally { if (socket === this.socket) this.verifying = false; }
  }
  handleMessage(message) {
    switch (message?.type) {
      case "ping": this.send({ type: "pong" }); break;
      case "pong": break;
      case "hello_ack": void this.verifyHello(message); break;
      case "tool_call": void this.handleToolCall(message); break;
      default: if (typeof message?.type !== "string") throw Error("Invalid controller message");
    }
  }
  async handleToolCall(message) {
    const socket = this.socket, epoch = this.epoch;
    const reply = payload => { if (socket === this.socket && epoch === this.epoch) this.send({ type: "tool_result", responseToRequestId: message.requestId, payload }); };
    try {
      const desired = await this.getDesired();
      if (!this.isConnected() || socket !== this.socket || epoch !== this.epoch || !desired.shouldConnect || desired.grant?.url !== this.currentUrl) throw Error("Browser control is not authorized and verified.");
      if (typeof message.payload?.name !== "string" || !message.payload.name) throw Error("Missing tool name");
      const data = await kiPolicyExternal(message.payload.name, message.payload.args || {}, this.permissionAbort?.signal, async lease => {
        const latest = await this.getDesired();
        if (socket !== this.socket || epoch !== this.epoch || !this.isConnected() || !latest.shouldConnect || latest.grant?.url !== this.currentUrl) throw Error("Browser control was revoked.");
        await kiPolicyRecheck(lease);
        return this.onToolCall(message.payload.name, message.payload.args || {});
      });
      reply({ data });
    } catch (error) { reply({ error: error.message }); }
  }
  send(message) { if (this.socket?.readyState === WebSocket.OPEN) this.socket.send(JSON.stringify(message)); }
  teardown() {
    this.permissionAbort?.abort(); this.permissionAbort = null;
    this.clearConnectingTimer(); this.clearFastRetryTimer();
    const socket = this.socket; this.socket = null; this.controller = null; this.verifying = false;
    try { socket?.close(); } catch {}
    this.setState("disconnected"); this.lastActivityAt = 0;
    if (socket) this.onDisconnect?.();
  }
  setState(state) { if (this.state !== state) { this.state = state; this.onStateChange?.(state, this.currentUrl); } }
  scheduleFastRetry() {
    const delay = [1000, 3000][this.fastRetryAttempt++];
    if (delay === undefined || this.blocked) return;
    this.clearFastRetryTimer(); this.fastRetryTimer = setTimeout(() => { this.fastRetryTimer = null; void this.reconcile(); }, delay);
  }
  clearFastRetryTimer() { clearTimeout(this.fastRetryTimer); this.fastRetryTimer = null; }
  clearConnectingTimer() { clearTimeout(this.connectingTimer); this.connectingTimer = null; }
};

chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (message?.type !== "KI_BROWSER_CONTROL") return;
  if (sender.id !== chrome.runtime.id || sender.url?.split("?")[0] !== chrome.runtime.getURL("providers/providers.html")) {
    reply({ ok: false, error: "Browser control requires its settings page." }); return;
  }
  (async () => {
    try {
      if (message.op === "connect") {
        await XB.connect(message.url, message.authorize === true);
      } else if (message.op === "disconnect") await XB.disconnect();
      else if (message.op !== "status") throw Error("Unknown browser-control operation");
      reply({ ok: true, result: await XB.snapshot() });
    } catch (error) { reply({ ok: false, error: error.message }); }
  })();
  return true;
});

const $ = id => document.getElementById(id);
let busy = false, initialized = false, pendingUrl = "", actionError = "", currentState = null, editingEndpoint = false;
async function request(op, extra = {}) {
  const response = await chrome.runtime.sendMessage({ type: "KI_BROWSER_CONTROL", op, ...extra });
  if (!response?.ok) throw Error(response?.error || "Browser control did not respond.");
  return response.result;
}
function render(state) {
  currentState = state;
  if (!initialized) { $("browser-url").value = state.url; initialized = true; }
  $("browser-status").textContent = state.connected ? "Connected" : state.state === "connecting" ? "Connecting…" : "Not connected";
  $("browser-status").className = state.connected ? "connection-ok" : "";
  $("browser-controller").textContent = state.controller ? `${state.controller.name} ${state.controller.version} · ${state.url}` : "";
  $("browser-error").textContent = actionError || state.reason || "";
  $("browser-connect").disabled = busy || state.state === "connecting";
  $("browser-connect").textContent = state.connected && !editingEndpoint ? "Change controller" : "Connect";
  $("browser-disconnect").hidden = !state.authorized && !state.reconnect && !state.connected;
  $("browser-disconnect").disabled = busy;
}
async function refresh() {
  if (busy || document.hidden) return;
  try { render(await request("status")); } catch (error) { $("browser-error").textContent = error.message; }
}
$("browser-connect").onclick = async () => {
  if (currentState?.connected && !editingEndpoint) {
    editingEndpoint = true; $("browser-advanced").open = true;
    $("browser-url").focus(); $("browser-url").select(); render(currentState); return;
  }
  pendingUrl = $("browser-url").value.trim();
  if (currentState?.authorized && pendingUrl === currentState.url) { await connect(false); return; }
  $("browser-authorize-url").textContent = pendingUrl || "ws://127.0.0.1:10086/ws";
  $("browser-authorize").showModal();
};
$("browser-cancel").onclick = () => $("browser-authorize").close();
async function connect(authorize) {
  if (busy) return;
  $("browser-authorize").close(); busy = true; actionError = "";
  $("browser-connect").disabled = true;
  try { await request("connect", { url: pendingUrl, authorize }); editingEndpoint = false; }
  catch (error) { actionError = error.message; $("browser-error").textContent = actionError; busy = false; $("browser-connect").disabled = false; return; }
  busy = false; await refresh();
}
$("browser-allow").onclick = () => connect(true);
$("browser-disconnect").onclick = async () => {
  if (busy) return;
  busy = true; actionError = ""; $("browser-disconnect").disabled = true;
  try { render(await request("disconnect")); }
  catch (error) { actionError = error.message; $("browser-error").textContent = actionError; }
  finally { busy = false; await refresh(); }
};
$("browser-url").oninput = () => { editingEndpoint = true; if (currentState) render(currentState); };
$("browser-default").onclick = () => { $("browser-url").value = "ws://127.0.0.1:10086/ws"; editingEndpoint = true; if (currentState) render(currentState); };
await refresh();
await import("./permission-requests.js");
const timer = setInterval(refresh, 1000);
window.addEventListener("pagehide", () => clearInterval(timer), { once: true });
document.addEventListener("visibilitychange", refresh);

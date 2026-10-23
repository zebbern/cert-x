const $ = id => document.getElementById(id);
let busy = false;
function row(label, state, detail, section, good = false) {
  const item = document.createElement("div"); item.className = "row";
  const text = document.createElement("div"); text.className = "row-main";
  const content = document.createElement("div"), heading = document.createElement("h3"), description = document.createElement("p");
  heading.textContent = label; description.className = "meta"; description.textContent = detail; content.append(heading, description); text.append(content);
  const link = document.createElement("a"); link.href = "?section=" + section; link.className = "section-link" + (good ? " connection-ok" : ""); link.textContent = state + " ›";
  link.onclick = event => {
    if (new URLSearchParams(location.search).get("embed") === "1") { event.preventDefault(); parent.postMessage({ type: "settings-section", section }, location.origin); }
  };
  item.append(text, link); return item;
}
async function refresh() {
  if (busy) return; busy = true; $("health-refresh").disabled = true; $("health-status").textContent = "Checking…";
  try {
    const response = await chrome.runtime.sendMessage({ type: "KI_WORKSPACE", op: "health" });
    if (!response?.ok) throw Error(response?.error || "Could not check capabilities.");
    const health = response.result, list = $("health-list"), host = health.local.host;
    list.replaceChildren(
      row("Custom models", health.modelProviders.configured + " configured", "Provider configuration; credentials are not tested here.", "models"),
      row("Local computer", host.state !== "connected" ? "Not connected" : host.updateNeeded ? "Update host" : health.local.enabled ? "Ready" : "Access off", host.error || (host.updateNeeded ? "Re-run the host installer for jobs and task outputs." : "Native host " + host.revision + " · " + host.platform), "local", health.local.enabled && host.state === "connected" && !host.updateNeeded),
      row("MCP servers", health.mcp.discoveredTools + " tools discovered", health.mcp.remoteConfigured + " remote · " + health.mcp.localConfigured + " local configured", "mcp"),
      ...(health.ptk ? [row("PTK analysis", "Check page", "PTK v10 readiness is checked on the selected browser tab.", "ptk")] : []),
      row("Browser control", health.browserControl.connected ? "Connected" : "Not connected", health.browserControl.controller?.name || health.browserControl.reason || "External agent connection", "browser", health.browserControl.connected),
      row("Tool permissions", health.permissions.overrides + " overrides", health.permissions.mode === "full_access" ? "Full access" : "Requires approval", "tools"),
    );
    $("health-details").textContent = ["Extension " + health.extensionVersion, health.mcp.note, ...health.mcp.discoveryErrors.map(item => item.label + ": " + item.error)].join("\n");
    $("health-status").textContent = "Checked " + new Date(health.checkedAt).toLocaleTimeString();
  } catch (error) { $("health-status").textContent = error.message; }
  finally { busy = false; $("health-refresh").disabled = false; }
}
$("health-refresh").onclick = refresh;
await refresh();

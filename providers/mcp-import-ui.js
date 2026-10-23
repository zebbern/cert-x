import { parseMcpImport, mergeMcpImport } from "./mcp-import.js";
const $ = id => document.getElementById(id);
let preview = [];
$("mcp-import-preview").onclick = () => {
  try {
    preview = parseMcpImport($("mcp-import-json").value);
    $("mcp-import-list").replaceChildren();
    preview.forEach((entry, index) => {
      const label = document.createElement("label"); label.className = "import-row";
      const checkbox = document.createElement("input"); checkbox.type = "checkbox"; checkbox.checked = !entry.error; checkbox.disabled = !!entry.error; checkbox.dataset.index = index;
      const text = document.createElement("span"); text.textContent = entry.label + " · " + (entry.error || (entry.kind === "local" ? "Local command" : "Remote server"));
      label.append(checkbox, text); $("mcp-import-list").append(label);
    });
    $("mcp-import-save").hidden = !preview.some(entry => !entry.error);
    $("mcp-import-status").textContent = "Choose the servers to add. Existing entries are kept.";
  } catch (error) { $("mcp-import-status").textContent = error.message; $("mcp-import-save").hidden = true; }
};
$("mcp-import-json").oninput = () => { preview = []; $("mcp-import-list").replaceChildren(); $("mcp-import-save").hidden = true; };
$("mcp-import-save").onclick = async () => {
  $("mcp-import-save").disabled = true;
  try {
    const selected = [...$("mcp-import-list").querySelectorAll("input:checked")].map(node => preview[Number(node.dataset.index)]);
    if (!selected.length) throw Error("Select at least one server.");
    const data = await chrome.storage.local.get(["ki_mcp_servers", "ki_native_settings"]);
    const merged = mergeMcpImport(selected, data.ki_mcp_servers || [], data.ki_native_settings?.servers || []);
    const update = {};
    if (JSON.stringify(merged.remote) !== JSON.stringify(data.ki_mcp_servers || [])) update.ki_mcp_servers = merged.remote;
    if (JSON.stringify(merged.local) !== JSON.stringify(data.ki_native_settings?.servers || [])) update.ki_native_settings = { ...data.ki_native_settings, servers: merged.local };
    if (Object.keys(update).length) await chrome.storage.local.set(update);
    $("mcp-import-status").textContent = `Added ${merged.added} · skipped ${merged.skipped} existing`;
    $("mcp-import-save").hidden = true; $("mcp-import-json").value = ""; $("mcp-import-list").replaceChildren(); preview = [];
  } catch (error) { $("mcp-import-status").textContent = error.message; }
  finally { $("mcp-import-save").disabled = false; }
};

import { serverFromForm } from "./local-mcp-config.js";
const KEY = "ki_native_settings";
const $ = id => document.getElementById(id);
let servers = [], editing = null, original = null, busy = false;
const envFileLabel = document.createElement('label'), envFileInput = document.createElement('input'), secretNotice = document.createElement('p');
envFileInput.id = 'local-env-file'; envFileInput.placeholder = 'Absolute path to .env'; envFileLabel.textContent = 'Environment file (optional)'; envFileLabel.append(envFileInput);
secretNotice.className = 'meta'; secretNotice.hidden = true; secretNotice.textContent = 'Managed credentials are stored in the local runtime.';
$("local-options").append(envFileLabel, secretNotice);

function message(value, error = false) {
  $("local-status").textContent = value;
  $("local-status").classList.toggle("error", error);
}
async function load() {
  const stored = (await chrome.storage.local.get(KEY))[KEY] || {};
  servers = Array.isArray(stored.servers) ? stored.servers : [];
  $("local-requirement").hidden = stored.enabled === true;
  render();
}
function render() {
  const list = $("local-list"); list.replaceChildren();
  if (!servers.length) {
    const empty = document.createElement("p"); empty.className = "empty-list";
    empty.textContent = "No local servers yet."; list.append(empty);
  }
  servers.forEach((server, index) => {
    const row = document.createElement("div"); row.className = "row";
    const main = document.createElement("div"); main.className = "row-main";
    const info = document.createElement("div");
    const title = document.createElement("h3"); title.textContent = server.label || server.command;
    const subtitle = document.createElement("p"); subtitle.className = "meta"; subtitle.textContent = server.command;
    info.append(title, subtitle); main.append(info);
    const actions = document.createElement("div"); actions.className = "actions";
    const edit = document.createElement("button"); edit.type = "button"; edit.textContent = "Edit"; edit.onclick = () => open(index);
    const remove = document.createElement("button"); remove.type = "button"; remove.textContent = "Remove";
    remove.onclick = () => {
      remove.textContent = "Confirm removal";
      remove.onclick = async () => {
        remove.disabled = true;
        try {
          const saved = (await chrome.storage.local.get(KEY))[KEY] || {};
          if (JSON.stringify(saved.servers?.[index]) !== JSON.stringify(server)) throw Error("Server list changed. Reopen it and try again.");
          await chrome.storage.local.set({ [KEY]: { ...saved, servers: saved.servers.filter((_, i) => i !== index) } });
          await load();
        } catch (error) { remove.disabled = false; message(error.message, true); $("local-form").hidden = false; }
      };
    };
    actions.append(edit, remove); row.append(main, actions); list.append(row);
  });
}
function open(index = null) {
  editing = index; original = index === null ? null : servers[index];
  $("local-form").hidden = false;
  $("local-title").textContent = original ? "Edit local server" : "Add local server";
  $("local-command").value = original?.command || "";
  $("local-args").value = (original?.args || []).join("\n");
  $("local-name").value = original?.label || "";
  $("local-cwd").value = original?.cwd || "";
  $("local-env").value = Object.entries(original?.env || {}).map(([key, value]) => key + "=" + value).join("\n");
  envFileInput.value = original?.envFileRef || ''; secretNotice.hidden = !original?.secretRef;
  $("local-options").open = !!(original?.cwd || original?.envFileRef || original?.secretRef || Object.keys(original?.env || {}).length);
  message(""); $("local-command").focus();
  $("local-form").scrollIntoView({ block: "nearest" });
}
function draft() {
  return serverFromForm({ command: $("local-command").value, args: $("local-args").value,
    label: $("local-name").value, cwd: $("local-cwd").value, env: $("local-env").value, envFileRef: envFileInput.value }, original);
}
$("local-add").onclick = () => open();
$("local-cancel").onclick = () => { $("local-form").hidden = true; editing = null; original = null; };
$("local-test").onclick = async () => {
  if (busy) return;
  busy = true; $("local-test").disabled = true;
  try {
    const server = draft(); message("Connecting…");
    const result = await chrome.runtime.sendMessage({ type: "KI_NATIVE", op: "test", server });
    if (!result?.ok) throw Error(result?.error || "Connection failed.");
    message("Connected · " + result.result.tools.length + " tools");
  } catch (error) { message(error.message, true); }
  finally { busy = false; $("local-test").disabled = false; }
};
$("local-form").onsubmit = async event => {
  event.preventDefault(); if (busy) return;
  busy = true;
  try {
    const server = draft(), saved = (await chrome.storage.local.get(KEY))[KEY] || {}, next = [...(saved.servers || [])];
    if (editing === null) { if (next.length >= 8) throw Error("Up to 8 local servers are supported."); next.push(server); }
    else { if (JSON.stringify(next[editing]) !== JSON.stringify(original)) throw Error("Server changed. Reopen it before saving."); next[editing] = server; }
    await chrome.storage.local.set({ [KEY]: { ...saved, servers: next } });
    $("local-form").hidden = true; editing = null; original = null; await load();
  } catch (error) { message(error.message, true); }
  finally { busy = false; }
};
chrome.storage.onChanged.addListener((changes, area) => { if (area === "local" && changes[KEY]) load().catch(error => message(error.message, true)); });
await load();

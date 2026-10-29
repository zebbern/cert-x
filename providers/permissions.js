import { initCsp } from "./csp.js";
const $ = id => document.getElementById(id);
let inventory, saving = false;
const modes = [["inherit", "Use current mode"], ["ask", "Always ask"], ["allow", "Allow"], ["disabled", "Disabled"]];
const opened = new Set();
async function request(op, extra = {}) {
  const response = await chrome.runtime.sendMessage({ type: "KI_PERMISSIONS", op, ...extra });
  if (!response?.ok) throw Error(response?.error || "Could not update permissions.");
  return response.result;
}
function selectRule(bucket, id, label, inheritedLabel) {
  const select = document.createElement("select");
  select.setAttribute("aria-label", label + " permission"); select.dataset.ruleId = id;
  for (const [value, text] of modes) { const option = document.createElement("option"); option.value = value; option.textContent = value === "inherit" ? inheritedLabel : text; select.append(option); }
  select.value = inventory.policy[bucket][id] || "inherit";
  select.onchange = async () => {
    if (saving) { select.value = inventory.policy[bucket][id] || "inherit"; return; }
    saving = true; select.disabled = true;
    $("permissions-status").textContent = "Saving…";
    try { await request("set", { bucket, id, value: select.value }); await load(); $("permissions-status").textContent = "Saved · applies to the next tool call"; document.querySelector('[data-rule-id="' + CSS.escape(id) + '"]')?.focus(); }
    catch (error) { $("permissions-status").textContent = error.message; select.value = inventory.policy[bucket][id] || "inherit"; }
    finally { saving = false; select.disabled = false; }
  };
  return select;
}
function render() {
  if (!inventory) return;
  const query = $("permissions-search").value.trim().toLowerCase(), list = $("permissions-groups"); list.replaceChildren();
  for (const group of inventory.groups) {
    const tools = inventory.tools.filter(tool => tool.group === group.id && (!query || [tool.label, tool.name, group.label, tool.description].join(" ").toLowerCase().includes(query)));
    if (query && !tools.length && !group.label.toLowerCase().includes(query)) continue;
    const card = document.createElement("section"); card.className = "card permission-group";
    const head = document.createElement("div"); head.className = "toolbar";
    const title = document.createElement("h2"); title.textContent = group.label;
    head.append(title, selectRule("groups", group.id, group.label, group.parent ? "Use MCP default" : "Use current mode")); card.append(head);
    if (tools.length) {
      const details = document.createElement("details"), summary = document.createElement("summary");
      const overrides = tools.filter(tool => inventory.policy.tools[tool.id]).length;
      summary.textContent = tools.length + (tools.length === 1 ? " tool" : " tools") + (overrides ? " · " + overrides + (overrides === 1 ? " override" : " overrides") : ""); details.open = !!query || opened.has(group.id);
      details.ontoggle = () => { if (details.open) opened.add(group.id); else opened.delete(group.id); };
      details.append(summary);
      for (const tool of tools) {
        const row = document.createElement("div"); row.className = "permission-row";
        const text = document.createElement("div"), name = document.createElement("span"), identifier = document.createElement("small");
        name.textContent = tool.label; identifier.textContent = tool.name; identifier.title = tool.description || "";
        text.append(name, identifier); row.append(text, selectRule("tools", tool.id, tool.label, "Use group default")); details.append(row);
      }
      card.append(details);
    } else if (group.parent) {
      const hint = document.createElement("p"); hint.className = "hint"; hint.textContent = "Tools appear here after this server is used. Its default already applies."; card.append(hint);
    }
    list.append(card);
    if (group.id === "browser") {
      const controls = document.createElement("details"), summary = document.createElement("summary"), container = document.createElement("div");
      summary.textContent = "Page controls"; container.id = "csp-controls";
      controls.append(summary, container); card.append(controls); initCsp(container);
    }
  }
  if (!list.children.length) { const text = document.createElement("p"); text.className = "hint"; text.textContent = "No matching tools."; list.append(text); }
}
async function load() { inventory = await request("inventory"); render(); }
$("permissions-search").oninput = render;
$("permissions-refresh").onclick = () => load().catch(error => $("permissions-status").textContent = error.message);
$("permissions-reset").onclick = () => $("permissions-reset-confirm").showModal();
$("permissions-reset-cancel").onclick = () => $("permissions-reset-confirm").close();
$("permissions-reset-yes").onclick = async () => {
  try { await request("reset"); $("permissions-reset-confirm").close(); await load(); $("permissions-status").textContent = "Defaults restored"; }
  catch (error) { $("permissions-status").textContent = error.message; }
};
try { await load(); } catch (error) { $("permissions-status").textContent = error.message; }
await import("./permission-requests.js");

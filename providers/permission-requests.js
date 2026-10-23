const root = document.querySelector("#permissions-section:not([hidden]) .tool-approval-requests, #browser-section:not([hidden]) .tool-approval-requests");
let signature = "";
async function refresh() {
  if (!root || document.hidden) return;
  try {
    const response = await chrome.runtime.sendMessage({ type: "KI_PERMISSIONS", op: "pending" });
    if (!response?.ok) throw Error(response?.error || "Could not read approvals");
    const items = response.result, next = JSON.stringify(items);
    if (next === signature) return; signature = next;
    root.replaceChildren(); root.hidden = items.length === 0;
    for (const item of items) {
      const card = document.createElement("section"); card.className = "card permission-group";
      card.dataset.approvalId = item.id;
      const heading = document.createElement("h2"); heading.textContent = "Browser control · " + item.label;
      const preview = document.createElement("pre"); preview.className = "permission-preview"; preview.textContent = item.preview;
      const actions = document.createElement("div"); actions.className = "form-actions";
      for (const [label, allow] of [["Deny", false], ["Allow once", true]]) {
        const button = document.createElement("button"); button.type = "button"; button.textContent = label;
        button.onclick = async () => {
          button.disabled = true;
          try { const result = await chrome.runtime.sendMessage({ type: "KI_PERMISSIONS", op: "decide", id: item.id, allow }); if (!result?.ok) throw Error(result?.error || "Decision failed"); signature = ""; await refresh(); }
          catch (error) { heading.textContent = error.message; button.disabled = false; signature = ""; await refresh(); }
        };
        actions.append(button);
      }
      card.append(heading, preview, actions); root.append(card);
    }
  } catch (error) { root.hidden = false; root.textContent = error.message; }
}
await refresh();
const timer = setInterval(refresh, 1000);
window.addEventListener("pagehide", () => clearInterval(timer), { once: true });
document.addEventListener("visibilitychange", refresh);

// Fast browse settings: the decision backend browse(goal) uses. Stored in
// chrome.storage.local like provider keys; the service worker re-reads it before
// each turn's tool list, and runs the Test call (TypeSafe rejects this page's origin).
const KEY = "ki_fast_browse";
const $ = id => document.getElementById(id);

async function ask(op) {
  const response = await chrome.runtime.sendMessage({ type: "KI_BROWSE", op });
  if (response?.ok !== true) throw Error(response?.error || "The extension did not respond.");
  return response.result;
}
async function showStatus() {
  try {
    const state = await ask("status");
    $("fast-browse-status").textContent = state.ready ? "On · " + (state.backend === "typesafe" ? "TypeSafe" : "OpenRouter") + " · " + state.model : "Off · " + state.reason;
  } catch (error) { $("fast-browse-status").textContent = error.message; }
}
async function save() {
  const stored = (await chrome.storage.local.get(KEY))[KEY] || {};
  await chrome.storage.local.set({ [KEY]: { ...stored, typesafeKey: $("fast-browse-key").value.trim(), backend: $("fast-browse-backend").value, typesafeModel: $("fast-browse-typesafe-model").value.trim(), openrouterModel: $("fast-browse-openrouter-model").value.trim() } });
}

$("fast-browse-toggle").addEventListener("click", () => {
  const shown = $("fast-browse-key").type === "text";
  $("fast-browse-key").type = shown ? "password" : "text";
  $("fast-browse-toggle").textContent = shown ? "Show" : "Hide";
});
$("fast-browse-save").addEventListener("click", async () => {
  $("fast-browse-save").disabled = true;
  try { await save(); await showStatus(); } catch (error) { $("fast-browse-status").textContent = "Could not save: " + error.message; }
  finally { $("fast-browse-save").disabled = false; }
});
$("fast-browse-test").addEventListener("click", async () => {
  $("fast-browse-test").disabled = true;
  $("fast-browse-status").textContent = "Testing…";
  try {
    await save();
    const result = await ask("test");
    $("fast-browse-status").textContent = "Works · " + result.model + " answered in " + result.ms + " ms";
  } catch (error) { $("fast-browse-status").textContent = "Test failed: " + error.message; }
  finally { $("fast-browse-test").disabled = false; }
});

const stored = (await chrome.storage.local.get(KEY))[KEY] || {};
$("fast-browse-key").value = stored.typesafeKey || "";
$("fast-browse-backend").value = ["typesafe", "openrouter", "off"].includes(stored.backend) ? stored.backend : "auto";
$("fast-browse-typesafe-model").value = stored.typesafeModel || "";
$("fast-browse-openrouter-model").value = stored.openrouterModel || "";
await showStatus();

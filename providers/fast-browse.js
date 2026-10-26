// Fast browse: an on/off switch and one key box. The service worker owns the
// setting (it also checks a key against the service before saving it, which this
// page cannot: api.typesafe.ai rejects extension-origin preflights).
const KEY = "ki_fast_browse";
const $ = id => document.getElementById(id);
const toggle = $("fast-browse-switch"), input = $("fast-browse-key"), save = $("fast-browse-save"), error = $("fast-browse-error");
// note: the last key check's result, kept until the next change. savedKey: what
// the box last showed from storage, so a key being typed is never overwritten.
let status = null, note = "", busy = false, savedKey = "";

async function ask(op, extra) {
  const response = await chrome.runtime.sendMessage({ type: "KI_BROWSE", op, ...extra });
  if (response?.ok !== true) throw Error(response?.error || "The extension did not respond.");
  return response.result;
}
function showError(message) { error.textContent = message; error.hidden = !message; }
function render(next) {
  status = next;
  toggle.disabled = false;
  toggle.setAttribute("aria-checked", String(next.ready));
  toggle.classList.toggle("is-on", next.ready);
  $("fast-browse-status").textContent = next.ready ? "On · " + next.label + (next.source === "provider" ? ", using your saved provider" : "") + note
    : next.available ? "Off" : "Off · paste a key below to turn it on";
}
async function refresh() {
  try { render(await ask("status")); } catch (e) { showError(e.message); }
}
// Busy controls ignore clicks instead of going disabled, which would drop
// keyboard focus to the page.
async function change(update) {
  if (busy) return;
  busy = true; showError(""); note = "";
  toggle.setAttribute("aria-busy", "true");
  if (update.key) save.textContent = "Checking…";
  try {
    const next = await ask("save", update);
    if (next.ms !== undefined) note = " · key works (" + next.ms + " ms)";
    render(next);
  } catch (e) { showError(e.message); if (status) render(status); }
  finally { busy = false; save.textContent = "Save"; toggle.removeAttribute("aria-busy"); }
}

toggle.addEventListener("click", () => {
  if (!status) return;
  // Turning it on with a key pasted but not saved yet means "use that key".
  const typed = input.value.trim();
  if (!status.ready && typed && typed !== savedKey) return change({ key: typed });
  if (status.ready || status.available) return change({ on: !status.ready });
  showError("Paste a TypeSafe or OpenRouter key first.");
  input.focus();
});
$("fast-browse-show").addEventListener("click", () => {
  const shown = input.type === "text";
  input.type = shown ? "password" : "text";
  $("fast-browse-show").textContent = shown ? "Show" : "Hide";
});
$("fast-browse").addEventListener("submit", event => {
  event.preventDefault();
  change({ key: input.value.trim() });
});
// The model menu has the same switch, and a provider saved above can enable it.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local" || !(changes[KEY] || changes.sidepanel_connections)) return;
  if (changes[KEY]) {
    const next = changes[KEY].newValue?.key || "";
    if (input.value.trim() === savedKey) input.value = next;
    savedKey = next;
  }
  refresh();
});

input.value = savedKey = (await chrome.storage.local.get(KEY))[KEY]?.key || "";
await refresh();

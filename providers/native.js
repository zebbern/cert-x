const KEY = "ki_native_settings";
const $ = id => document.getElementById(id);
function setEnabled(enabled) {
  $("native-enabled").setAttribute("aria-checked", String(enabled));
  $("native-enabled").classList.toggle("is-on", enabled);
}

async function requestStatus() {
  const response = await chrome.runtime.sendMessage({ type: "KI_NATIVE", op: "status" });
  if (response?.ok !== true) throw Error(response?.error || "Host did not respond.");
  return response.result;
}
function installationCommand() {
  $("native-install").textContent = 'powershell -NoProfile -ExecutionPolicy Bypass -File .\\tools\\host\\install.ps1 -ExtensionId ' + chrome.runtime.id + ' -Browser ' + $("native-browser").value;
  $("native-copy-status").textContent = "";
}
async function checkHost() {
  $("native-check").disabled = true;
  $("native-status").textContent = "Checking…";
  try {
    const result = await requestStatus();
    const update = !result.features?.includes("command_jobs");
    $("native-status").textContent = update ? "Connected · update host for jobs" : "Connected";
    $("native-status").className = "connection-ok";
    $("native-detail").textContent = result.platform + ' · Node ' + result.node + ' · ' + result.home;
    $("native-setup").open = update;
  } catch (error) {
    $("native-status").textContent = /not found|not installed/i.test(error.message) ? "Setup needed" : "Not connected";
    $("native-status").className = "";
    $("native-detail").textContent = error.message;
    $("native-setup").open = true;
  } finally { $("native-check").disabled = false; }
}
$("native-check").addEventListener("click", checkHost);
$("native-browser").addEventListener("change", installationCommand);
$("native-copy").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText($("native-install").textContent); $("native-copy-status").textContent = "Copied"; }
  catch { $("native-copy-status").textContent = "Select and copy the command above."; }
});
$("native-enabled").addEventListener("click", async () => {
  const enabled = $("native-enabled").getAttribute("aria-checked") !== "true";
  setEnabled(enabled);
  $("native-enabled").disabled = true;
  $("native-access-status").textContent = "Saving…";
  try {
    const stored = (await chrome.storage.local.get(KEY))[KEY] || {};
    await chrome.storage.local.set({ [KEY]: { ...stored, enabled } });
    $("native-access-status").textContent = enabled ? "On · available next message" : "Off · local tools disabled";
  } catch (error) {
    setEnabled(!enabled);
    $("native-access-status").textContent = "Could not save: " + error.message;
  } finally { $("native-enabled").disabled = false; }
});
if (/Edg\//.test(navigator.userAgent)) $("native-browser").value = "Edge";
installationCommand();
try {
  const stored = (await chrome.storage.local.get(KEY))[KEY];
  setEnabled(stored?.enabled === true);
  $("native-access-status").textContent = stored?.enabled === true ? "On · available next message" : "Off · local tools disabled";
  $("native-enabled").disabled = false;
} catch (error) { $("native-access-status").textContent = "Could not read settings: " + error.message; }
void checkHost();

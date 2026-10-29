async function request(op, args = {}) {
  const response = await chrome.runtime.sendMessage({ type: "KI_CSP", op, ...args });
  if (!response?.ok) throw Error(response?.error || "Could not update CSP controls.");
  return response.result;
}
export function initCsp(container) {
  container.replaceChildren();
  const heading = document.createElement("h3"), select = document.createElement("select"), row = document.createElement("div"), label = document.createElement("span"), toggle = document.createElement("button"), knob = document.createElement("span"), status = document.createElement("p"), reload = document.createElement("button"), help = document.createElement("details"), summary = document.createElement("summary"), explanation = document.createElement("p");
  heading.textContent = "CSP Unblock"; select.setAttribute("aria-label", "CSP tab"); select.style.maxWidth = "100%";
  row.className = "toolbar"; label.textContent = "Unblock CSP";
  toggle.type = "button"; toggle.className = "wb-toggle wb-toggle--sm"; toggle.setAttribute("role", "switch"); toggle.setAttribute("aria-label", "Unblock CSP"); toggle.setAttribute("aria-checked", "false"); toggle.append(knob);
  knob.className = "wb-toggle-thumb"; knob.setAttribute("aria-hidden", "true"); row.append(label, toggle); status.className = "hint"; status.setAttribute("role", "status");
  reload.type = "button"; reload.textContent = "Reload to apply"; reload.hidden = true;
  summary.textContent = "Details"; explanation.className = "hint"; explanation.textContent = "Removes CSP response headers for this origin in this tab. Reload after changing it. Meta policies and service-worker responses may still apply. Resets when the tab leaves this origin or the browser closes."; help.append(summary, explanation);
  container.append(heading, select, row, status, reload, help);
  let tabs = [], busy = false, timer, disposed = false;
  const selected = () => tabs.find(tab => tab.tabId === Number(select.value));
  const render = () => {
    const tab = selected(); toggle.disabled = busy || !tab; select.disabled = busy || !tabs.length; reload.disabled = busy;
    toggle.setAttribute("aria-checked", String(!!tab?.enabled)); toggle.classList.toggle("is-on", !!tab?.enabled);
    reload.hidden = !tab?.needsReload;
    status.textContent = !tab ? "Open an HTTP or HTTPS page to use this control." : tab.enabled ? tab.needsReload ? "On · reload to apply" : "CSP headers unblocked · " + tab.origin : tab.needsReload ? "Off · reload to restore page policy" : "Off";
  };
  const refresh = async () => {
    if (disposed || !container.isConnected || busy) return;
    const value = select.value, result = await request("tabs"); if (disposed || !container.isConnected) return;
    tabs = result; select.replaceChildren();
    for (const tab of tabs) { const option = document.createElement("option"); option.value = tab.tabId; option.textContent = tab.title + " · " + tab.origin; select.append(option); }
    if (tabs.some(tab => String(tab.tabId) === value)) select.value = value;
    else if (tabs.some(tab => tab.active)) select.value = String(tabs.find(tab => tab.active).tabId);
    render();
  };
  const act = async op => {
    const tab = selected(); if (!tab || busy) return; busy = true; render();
    try { await request(op, { tabId: tab.tabId, ...(op === "set" ? { enabled: !tab.enabled } : {}) }); busy = false; await refresh(); }
    catch (error) { busy = false; render(); status.textContent = error.message; }
  };
  select.onchange = render; toggle.onclick = () => act("set"); reload.onclick = () => act("reload");
  const refreshQuiet = () => refresh().catch(error => { if (!disposed) status.textContent = error.message; });
  const changed = (changes, area) => { if (area === "session" && changes.ki_csp_tabs) refreshQuiet(); };
  chrome.storage.onChanged.addListener(changed);
  const dispose = () => { disposed = true; clearInterval(timer); chrome.storage.onChanged.removeListener(changed); observer.disconnect(); };
  const observer = new MutationObserver(() => { if (!container.isConnected) dispose(); }); observer.observe(document.body, { childList: true, subtree: true });
  timer = setInterval(refreshQuiet, 3000); refreshQuiet(); return dispose;
}

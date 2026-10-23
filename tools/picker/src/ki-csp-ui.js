function KiCspIndicator({ session }) {
  const [tabs, setTabs] = (0, _.useState)([]), [error, setError] = (0, _.useState)(""), [busy, setBusy] = (0, _.useState)(false);
  (0, _.useEffect)(() => {
    let live = true;
    const refresh = () => chrome.runtime.sendMessage({ type: "KI_CSP", op: "status" }).then(response => { if (live && response?.ok) setTabs(response.result.tabs); }).catch(() => {});
    const changed = (changes, area) => { if (area === "session" && changes.ki_csp_tabs) refresh(); };
    refresh(); chrome.storage.onChanged.addListener(changed);
    return () => { live = false; chrome.storage.onChanged.removeListener(changed); };
  }, [session]);
  const act = async (tab, op) => {
    if (busy) return; setBusy(true); setError("");
    try {
      const response = await chrome.runtime.sendMessage({ type: "KI_CSP", op, tabId: tab.tabId, ...(op === "set" ? { enabled: false } : {}) });
      if (!response?.ok) throw Error(response?.error || "Could not update CSP controls.");
      const state = await chrome.runtime.sendMessage({ type: "KI_CSP", op: "status" }); if (state?.ok) setTabs(state.result.tabs);
    } catch (failure) { setError(failure.message); } finally { setBusy(false); }
  };
  if (!tabs.length && !error) return null;
  return (0, A.jsxs)("div", { className: "ki-output-tray ki-csp-indicator", children: [
    ...tabs.map(tab => (0, A.jsxs)("div", { className: "ki-output-row", children: [
      (0, A.jsx)("span", { title: tab.title + " · " + tab.origin, children: (tab.enabled ? "CSP Unblock on" : "CSP Unblock off") + " · " + tab.origin + (tab.needsReload ? " · reload to apply" : "") }),
      tab.enabled && (0, A.jsx)("button", { type: "button", disabled: busy, onClick: () => act(tab, "set"), children: "Turn off" }),
      tab.needsReload && (0, A.jsx)("button", { type: "button", disabled: busy, onClick: () => act(tab, "reload"), children: "Reload" }),
    ] }, tab.tabId)), error && (0, A.jsx)("p", { role: "status", children: error }),
  ] });
}

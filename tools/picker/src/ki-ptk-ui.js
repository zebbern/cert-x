async function KiSecurityRequest(op, fields = {}) {
  const response = await chrome.runtime.sendMessage({ type: "KI_SECURITY", op, ...fields });
  if (!response?.ok || response.result?.ok === false || response.result?.success === false) throw Error(response?.error || response.result?.error || response.result?.message || "Security operation failed.");
  return response.result;
}
function KiPtkPanel({ session, state, onOpen }) {
  const [runs, setRuns] = (0, _.useState)([]), [tabs, setTabs] = (0, _.useState)([]), [tabId, setTabId] = (0, _.useState)(""), [preset, setPreset] = (0, _.useState)("thorough");
  const [open, setOpen] = (0, _.useState)(false), [busy, setBusy] = (0, _.useState)(false), [error, setError] = (0, _.useState)("");
  const current = (0, _.useRef)(session); current.current = session;
  const chat = state?.chats?.[session] || {}, workspace = state?.workspaces?.find(item => item.id === chat.workspaceId);
  const profile = state?.effective?.profile?.id || chat.profileId || workspace?.profileId || "default";
  const group = state?.effective?.tools?.groups?.ptk;
  const enabled = group === true || (group !== false && profile === "bugbounty");
  const active = runs.filter(run => ["queued", "starting", "running", "stopping", "unknown"].includes(run.state));
  (0, _.useEffect)(() => {
    if (!document.querySelector("link[data-security-style]")) { const link = document.createElement("link"); link.rel = "stylesheet"; link.href = chrome.runtime.getURL("providers/security.css"); link.dataset.securityStyle = ""; document.head.append(link); }
    let live = true, initialized = false; setRuns([]); setTabs([]); setTabId(""); setError(""); setOpen(false); setBusy(false);
    const load = async () => { if (!session) return; const value = await KiSecurityRequest("state", { session }); if (live && current.current === session) { setRuns(value.runs || []); if (!initialized) { setPreset(value.config?.preset || "thorough"); initialized = true; } } };
    void load().catch(error => { if (live) setError(error.message); });
    const changed = (changes, area) => { if (area === "local" && Object.keys(changes).some(key => /security|ptk_scans|dast_batches|authz_batches/.test(key))) void load().catch(error => { if (live) setError(error.message); }); };
    chrome.storage.onChanged.addListener(changed); return () => { live = false; chrome.storage.onChanged.removeListener(changed); };
  }, [session]);
  (0, _.useEffect)(() => {
    if (!open || !session || !enabled) return;
    let live = true;
    KiSecurityRequest("tabs", { session }).then(value => { if (!live) return; setTabs(value); setTabId(old => value.some(tab => String(tab.tabId) === old) ? old : value.length ? String((value.find(tab => tab.working) || value.find(tab => tab.active) || value[0]).tabId) : ""); }).catch(error => { if (live) setError(error.message); });
    return () => { live = false; };
  }, [open, session, enabled]);
  const activeIds = active.map(run => run.runId).join("|");
  (0, _.useEffect)(() => {
    if (!session || !activeIds) return;
    let live = true, timer;
    const poll = async () => {
      try { if (!document.hidden && !busy) { for (const runId of activeIds.split("|")) await KiSecurityRequest("status", { session, runId }); const value = await KiSecurityRequest("state", { session }); if (live && current.current === session) setRuns(value.runs || []); } }
      catch (failure) { if (live) setError(failure.message); }
      finally { if (live) timer = setTimeout(poll, 3000); }
    };
    timer = setTimeout(poll, 3000); return () => { live = false; clearTimeout(timer); };
  }, [session, activeIds, busy]);
  const manage = () => typeof onOpen === "function" ? onOpen("security") : chrome.tabs.create({ url: chrome.runtime.getURL("providers/providers.html?section=security&session=" + encodeURIComponent(session)) });
  const act = async (op, fields = {}) => {
    if (busy || !session) return; const owner = session; setBusy(true); setError("");
    try { const result = await KiSecurityRequest(op, { session: owner, ...fields }); if (op === "start" && (!result?.runId || !result.state)) throw Error("Scan start was not confirmed. Open Security testing to check its state."); const value = await KiSecurityRequest("state", { session: owner }); if (current.current === owner) setRuns(value.runs || []); }
    catch (failure) { if (current.current === owner) setError(failure.message); } finally { if (current.current === owner) setBusy(false); }
  };
  if (!session || (!enabled && !runs.length)) return null;
  const latest = (active.length ? active : runs.slice(-1));
  return (0, A.jsxs)("details", { className: "ki-security-panel", open, onToggle: event => setOpen(event.currentTarget.open), children: [
    (0, A.jsx)("summary", { children: "Security testing" + (active.length ? " · " + active.length + " active" : "") }),
    enabled && (0, A.jsxs)(A.Fragment, { children: [
      (0, A.jsxs)("label", { className: "security-field", children: [(0, A.jsx)("span", { children: "Target" }), (0, A.jsx)("select", { "aria-label": "Security target page", value: tabId, disabled: busy, onChange: event => setTabId(event.target.value), children: tabs.length ? tabs.map(tab => (0, A.jsx)("option", { value: String(tab.tabId), children: tab.title || tab.origin || tab.url }, tab.tabId)) : (0, A.jsx)("option", { value: "", children: "Open a page" }) })] }),
      (0, A.jsxs)("label", { className: "security-field", children: [(0, A.jsx)("span", { children: "Preset" }), (0, A.jsxs)("select", { "aria-label": "Security testing preset", value: preset, disabled: busy, onChange: event => setPreset(event.target.value), children: [(0, A.jsx)("option", { value: "thorough", children: "Thorough" }), (0, A.jsx)("option", { value: "ptk-defaults", children: "PTK defaults" })] })] }),
    ] }),
    (0, A.jsxs)("div", { className: "security-actions", children: [
      enabled && (0, A.jsx)("button", { type: "button", disabled: busy || !tabId, onClick: () => act("start", { tabId: Number(tabId), engines: ["DAST", "IAST", "SAST", "SCA"], options: { preset } }), children: "Start scan" }),
      (0, A.jsx)("button", { type: "button", onClick: manage, children: "Scans and settings" }),
    ] }),
    ...latest.map(run => (0, A.jsxs)("div", { className: "security-run", children: [
      (0, A.jsx)("p", { className: "security-meta", children: [run.title || run.origin, run.state, (run.engines || []).join(" + ")].filter(Boolean).join(" · ") }),
      run.error && (0, A.jsx)("p", { className: "security-error", children: typeof run.error === "string" ? run.error : JSON.stringify(run.error) }),
      active.includes(run) && (0, A.jsx)("button", { type: "button", disabled: busy || run.state === "stopping", onClick: () => act("stop", { runId: run.runId }), children: run.state === "stopping" ? "Stopping…" : "Stop" }),
    ] }, run.runId)),
    error && (0, A.jsx)("p", { className: "security-error", role: "alert", children: error }),
  ] });
}

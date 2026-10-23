async function KiContextRequest(op, fields = {}) {
  const response = await chrome.runtime.sendMessage({ type: "KI_CONTEXT", op, ...fields });
  if (!response?.ok) throw Error(response?.error || "Could not load task settings.");
  return response.result;
}
function KiUseContextState(session) {
  const [state, setState] = (0, _.useState)({ profiles: [], workspaces: [], chats: {}, revision: 0, error: "" });
  (0, _.useEffect)(() => {
    let live = true, sequence = 0;
    const update = async () => {
      const token = ++sequence;
      try { const value = await KiContextRequest("state"), effective = session && session !== "history" ? await KiContextRequest("effective", { session }) : null; if (live && token === sequence) setState(old => ({ ...value, effective, revision: old.revision + 1, error: "" })); }
      catch (error) { if (live && token === sequence) setState(old => ({ ...old, error: error.message })); }
    };
    const changed = (changes, area) => { if (area === "local" && changes.ki_contexts) void update(); };
    void update(); chrome.storage.onChanged.addListener(changed);
    return () => { live = false; chrome.storage.onChanged.removeListener(changed); };
  }, [session]);
  return state;
}
async function KiInitializeChat(session, previous) {
  await KiContextRequest("initialize_chat", { session, previousSession: previous || null });
}
async function KiRememberModel(session, model) {
  return KiContextRequest("assign_chat", { session, modelExplicit: { connectionId: model.connectionId, modelId: model.modelId } });
}
async function KiResolveChatModel(session, models) {
  const context = await KiContextRequest("effective", { session });
  const preference = context.model || await AA();
  const model = models.find(item => item.connectionId === preference?.connectionId && item.modelId === preference?.modelId) || (!context.model ? models[0] : null);
  if (!model) return null;
  return Mj(model, Aj(model, await VA()));
}
function KiContextManage(section) {
  chrome.tabs.create({ url: chrome.runtime.getURL("providers/providers.html?section=" + section) });
}
function KiProfileSelector({ session, state, busy }) {
  const [error, setError] = (0, _.useState)(""), [saving, setSaving] = (0, _.useState)(false);
  const chat = state.chats[session] || {}, workspace = state.workspaces.find(item => item.id === chat.workspaceId);
  const base = state.profiles.find(item => item.id === (workspace?.profileId || "default"));
  const change = async value => {
    if (value === "manage") { KiContextManage("profiles"); return; }
    setSaving(true); setError("");
    try { await KiContextRequest("assign_chat", { session, profileId: value || null }); }
    catch (failure) { setError(failure.message); }
    finally { setSaving(false); }
  };
  return (0, A.jsxs)("span", { className: "ki-profile-control", children: [
    (0, A.jsx)("select", { "aria-label": "Profile", title: error || (chat.profileId ? "Profile: " + state.profiles.find(profile => profile.id === chat.profileId)?.name : (workspace ? "Workspace default: " : "Profile: ") + (base?.name || "Default")), value: chat.profileId || "", disabled: !session || busy || saving || !state.profiles.length,
      onChange: event => void change(event.target.value), children: [
        (0, A.jsx)("option", { value: "", children: base?.name || "Default" }, "inherit"),
        ...state.profiles.filter(profile => profile.id !== (base?.id || "default") || profile.id === chat.profileId).map(profile => (0, A.jsx)("option", { value: profile.id, children: profile.name }, profile.id)),
        (0, A.jsx)("option", { value: "manage", children: "Manage profiles…" }, "manage"),
      ] }),
    error && (0, A.jsx)("span", { role: "alert", className: "ki-context-error", children: error }),
  ] });
}
function KiWorkspaceSelector({ session, state, busy, models, modelsReady }) {
  const [error, setError] = (0, _.useState)(""), [saving, setSaving] = (0, _.useState)(false);
  const chat = state.chats[session] || {}, workspace = state.workspaces.find(item => item.id === chat.workspaceId);
  const profile = state.profiles.find(item => item.id === (chat.profileId || workspace?.profileId || "default"));
  const preferred = state.effective?.model || chat.modelExplicit || workspace?.model || profile?.model;
  const missing = modelsReady && preferred && !models.some(item => item.connectionId === preferred.connectionId && item.modelId === preferred.modelId);
  const change = async value => {
    if (value === "manage") { KiContextManage("workspaces"); return; }
    setSaving(true); setError("");
    try { await KiContextRequest("assign_chat", { session, workspaceId: value || null, profileId: null }); }
    catch (failure) { setError(failure.message); }
    finally { setSaving(false); }
  };
  return (0, A.jsxs)("div", { className: "ki-workspace-control", children: [
    (0, A.jsxs)("div", { className: "ki-workspace-line", children: [
      (0, A.jsx)("select", { "aria-label": "Workspace", title: workspace?.name || "No workspace", value: chat.workspaceId || "", disabled: !session || busy || saving, onChange: event => void change(event.target.value), children: [
        (0, A.jsx)("option", { value: "", children: "No workspace" }, "none"),
        ...state.workspaces.map(item => (0, A.jsx)("option", { value: item.id, children: item.name }, item.id)),
        (0, A.jsx)("option", { value: "manage", children: "Manage workspaces…" }, "manage"),
      ] }),
      workspace?.folder && (0, A.jsx)("span", { className: "ki-workspace-folder", title: workspace.folder, children: workspace.folder.split(/[\\/]/).filter(Boolean).pop() }),
      chat.modelExplicit && (0, A.jsx)("button", { type: "button", className: "ki-context-default", disabled: busy || saving, title: "Use the workspace or profile model preference", onClick: async () => {
        setSaving(true); try { await KiContextRequest("assign_chat", { session, modelExplicit: null }); } catch (failure) { setError(failure.message); } finally { setSaving(false); }
      }, children: "Use default model" }),
    ] }),
    (error || state.error || missing) && (0, A.jsx)("p", { role: "alert", className: "ki-context-error", children: error || state.error || "Preferred model unavailable. Choose an available model to continue." }),
  ] });
}
function KiUseHistoryFilter(entries) {
  const state = KiUseContextState("history"), [filter, setFilter] = (0, _.useState)("all");
  const selected = filter !== "all" && filter !== "none" && !state.workspaces.some(item => item.id === filter) ? "all" : filter;
  return { state, filter: selected, setFilter, entries: entries?.filter(entry => selected === "all" || (selected === "none" ? !state.chats[entry.chatId]?.workspaceId : state.chats[entry.chatId]?.workspaceId === selected)) ?? null };
}
function KiHistoryFilter({ value }) {
  return (0, A.jsx)("select", { className: "ki-history-filter", "aria-label": "Filter chats by workspace", value: value.filter, onChange: event => value.setFilter(event.target.value), children: [
    (0, A.jsx)("option", { value: "all", children: "All chats" }, "all"), (0, A.jsx)("option", { value: "none", children: "No workspace" }, "none"),
    ...value.state.workspaces.map(item => (0, A.jsx)("option", { value: item.id, children: item.name }, item.id)),
  ] });
}

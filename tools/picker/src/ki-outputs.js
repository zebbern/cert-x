function KiOutputBytes(value) {
  if (value.encoding === "base64") { const binary = atob(value.content); return Uint8Array.from(binary, character => character.charCodeAt(0)); }
  return new TextEncoder().encode(value.content);
}
function KiTaskOutputs({ session, onAttach, workspaceId }) {
  const [items, setItems] = (0, _.useState)([]), [preview, setPreview] = (0, _.useState)(null), [error, setError] = (0, _.useState)(""), [busy, setBusy] = (0, _.useState)(false);
  const [workspaceScope, setWorkspaceScope] = (0, _.useState)(false);
  const [hasWorkspaceOutputs, setHasWorkspaceOutputs] = (0, _.useState)(false);
  const [expanded, setExpanded] = (0, _.useState)(false);
  const scope = workspaceScope && !!workspaceId;
  const current = (0, _.useRef)(session); current.current = session;
  (0, _.useEffect)(() => {
    let live = true; setPreview(null); setError(""); setItems([]); setHasWorkspaceOutputs(false);
    const refresh = async () => {
      if (!session) return;
      const response = await chrome.runtime.sendMessage({ type: "KI_WORKSPACE", op: "outputs", ...(workspaceId ? { workspaceId } : { session }) });
      if (live && response?.ok) { setHasWorkspaceOutputs(!!workspaceId && response.result.length > 0); setItems(workspaceId && !scope ? response.result.filter(item => item.owner === session) : response.result); }
    };
    const changed = (changes, area) => { if (area === "local" && (changes.ki_task_outputs || changes.ki_contexts)) refresh().catch(() => {}); };
    refresh().catch(() => {}); chrome.storage.onChanged.addListener(changed);
    return () => { live = false; chrome.storage.onChanged.removeListener(changed); };
  }, [session, workspaceId, scope]);
  const act = async (item, action) => {
    if (busy) return; setBusy(true); setError("");
    try {
      if (action === "open" && item.downloadId) { await chrome.downloads.show(item.downloadId); return; }
      if (action === "open" && item.path) {
        const url = new URL("file:///"); url.pathname = item.path.replace(/\\/g, "/");
        await chrome.tabs.create({ url: url.toString(), active: false }); setError("Opened in a new tab."); return;
      }
      const response = await chrome.runtime.sendMessage({ type: "KI_WORKSPACE", op: "output_read", id: item.id });
      if (!response?.ok) throw Error(response?.error || "Could not read output.");
      if (current.current !== session) throw Error("Task changed. Try again from its output tray.");
      const value = response.result, bytes = KiOutputBytes(value);
      if (action === "attach") await onAttach([new File([bytes], value.name, { type: value.mime })]);
      else if (action === "open") {
        let binary = ""; for (let offset = 0; offset < bytes.length; offset += 32768) binary += String.fromCharCode(...bytes.subarray(offset, offset + 32768));
        await chrome.downloads.download({ url: "data:" + value.mime + ";base64," + btoa(binary), filename: value.name.replace(/[\\/<>:"|?*]/g, "_"), saveAs: true });
      } else if (/^image\/(png|jpeg|webp|gif)$/.test(value.mime)) {
        setPreview({ image: "data:" + value.mime + ";base64," + value.content, name: value.name });
      } else if (/text|json|xml|javascript/.test(value.mime)) {
        const text = new TextDecoder().decode(bytes); setPreview({ text: text.slice(0, 65536) + (text.length > 65536 ? "\n[Preview shortened]" : ""), name: value.name });
      } else setPreview({ text: "Open this file or use it in chat to view its contents.", name: value.name });
    } catch (failure) { setError(failure.message); }
    finally { setBusy(false); }
  };
  if (!items.length && !hasWorkspaceOutputs && !expanded) return null;
  return (0, A.jsxs)("details", { className: "ki-output-tray", open: expanded, onToggle: event => setExpanded(event.currentTarget.open), children: [
    (0, A.jsx)("summary", { children: "Outputs · " + items.length }),
    workspaceId && (0, A.jsxs)("div", { className: "ki-output-scope", children: [
      (0, A.jsx)("button", { type: "button", "aria-pressed": !scope, onClick: () => setWorkspaceScope(false), children: "This chat" }),
      (0, A.jsx)("button", { type: "button", "aria-pressed": scope, onClick: () => setWorkspaceScope(true), children: "Workspace" }),
    ] }),
    !items.length && (0, A.jsx)("p", { children: "No outputs yet." }),
    (0, A.jsx)("div", { className: "ki-output-list", children: items.slice().reverse().map(item => (0, A.jsxs)("div", { className: "ki-output-row", children: [
      (0, A.jsxs)("span", { title: item.path || item.name, children: [item.name, scope && (0, A.jsx)("small", { className: "ki-output-source", children: "Chat · " + (item.chatTitle || item.sourceChatTitle || item.sourceChat || item.owner) })] }),
      ...[["preview", "Preview"], ["open", item.downloadId ? "Show" : item.path ? "Open" : "Download"], ["attach", "Use in chat"]].map(([action, label]) => (0, A.jsx)("button", { type: "button", disabled: busy, onClick: () => act(item, action), children: label }, action)),
    ] }, item.id)) }),
    error && (0, A.jsx)("p", { role: "status", children: error }),
    preview && (0, A.jsxs)("div", { className: "ki-output-preview", children: [(0, A.jsx)("button", { type: "button", onClick: () => setPreview(null), children: "Close preview" }), preview.image ? (0, A.jsx)("img", { src: preview.image, alt: preview.name }) : (0, A.jsx)("pre", { children: preview.text })] }),
  ] });
}

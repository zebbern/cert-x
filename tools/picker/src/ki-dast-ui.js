async function KiDastRequest(op, fields = {}, kind = "dast") {
  const response = await chrome.runtime.sendMessage({ type: kind === "authz" ? "KI_AUTHZ" : "KI_DAST", op, ...fields });
  if (!response?.ok) throw Error(response?.error || "DAST request failed."); return response.result;
}
function KiDastPanel({ session, kind = "dast" }) {
  const [batches, setBatches] = (0, _.useState)([]), [error, setError] = (0, _.useState)(""), [busy, setBusy] = (0, _.useState)(false);
  const current = (0, _.useRef)(session); current.current = session;
  (0, _.useEffect)(() => {
    if (!document.querySelector("link[data-security-style]")) { const link = document.createElement("link"); link.rel = "stylesheet"; link.href = chrome.runtime.getURL("providers/security.css"); link.dataset.securityStyle = ""; document.head.append(link); }
    let live = true; setBatches([]); setError("");
    const update = async () => { if (!session) return; const result = await KiDastRequest("state", { session }, kind); if (live) setBatches(result.batches || []); };
    const changed = (changes, area) => { if (area === "local" && changes[kind === "authz" ? "ki_authz_batches" : "ki_dast_batches"]) void update().catch(failure => { if (live) setError(failure.message); }); };
    void update().catch(failure => { if (live) setError(failure.message); });
    chrome.storage.onChanged.addListener(changed); return () => { live = false; chrome.storage.onChanged.removeListener(changed); };
  }, [session, kind]);
  const activeIds = batches.filter(batch => ["starting", "running", "stopping", "unknown"].includes(batch.state)).map(batch => batch.batchId).join("|");
  (0, _.useEffect)(() => {
    if (!session || !activeIds) return;
    let live = true, timer;
    const poll = async () => {
      if (!live) return;
      try {
        if (!document.hidden) {
          for (const batchId of activeIds.split("|")) await KiDastRequest("status", { session, batchId }, kind);
          const result = await KiDastRequest("state", { session }, kind); if (live) setBatches(result.batches || []);
        }
      } catch (failure) { if (live) setError(failure.message); }
      if (live) timer = setTimeout(poll, 5000);
    };
    timer = setTimeout(poll, 3000); return () => { live = false; clearTimeout(timer); };
  }, [session, activeIds, kind]);
  if (!session || !batches.length) return null;
  const active = batches.filter(batch => ["starting", "running", "stopping", "unknown"].includes(batch.state)), latest = active;
  if (!active.length) return null;
  const manage = () => chrome.tabs.create({ url: chrome.runtime.getURL("providers/providers.html?section=security" + (kind === "authz" ? "&view=accounts" : "") + "&session=" + encodeURIComponent(session)) });
  const stop = async batch => {
    if (busy) return; setBusy(true); setError(""); const owner = session;
    try { await KiDastRequest("stop", { session: owner, batchId: batch.batchId }, kind); const result = await KiDastRequest("state", { session: owner }, kind); if (current.current === owner) setBatches(result.batches || []); }
    catch (failure) { if (current.current === owner) setError(failure.message); } finally { setBusy(false); }
  };
  return (0, A.jsxs)("details", { className: "ki-security-panel", children: [
    (0, A.jsx)("summary", { children: "Security testing · " + (kind === "authz" ? "account comparison · " : "selected requests · ") + (({ starting: "starting", running: "testing", stopping: "stopping", unknown: "state unknown" })[active[0].state] || "state unknown") }),
    ...latest.map(batch => (0, A.jsxs)("div", { children: [
      (0, A.jsx)("p", { className: "security-meta", children: [String(batch.state).replaceAll("_", " "), Number.isFinite(batch.requestsSent) ? batch.requestsSent + " requests" : null, batch.inFlight > 0 ? batch.inFlight + " in flight" : null, Number.isFinite(batch.findingsCount) ? batch.findingsCount + (kind === "authz" ? " unexpected access results" : " candidates") : null].filter(Boolean).join(" · ") }),
      batch.error && (0, A.jsx)("p", { className: "security-error", children: String(batch.error).slice(0, 1000) }),
      ...(batch.errors || []).slice(0, 3).map((error, index) => (0, A.jsx)("p", { className: "security-error", children: String(error).slice(0, 1000) }, index)),
      (0, A.jsxs)("div", { className: "security-actions", children: [
        ["starting", "running", "stopping", "unknown"].includes(batch.state) && (0, A.jsx)("button", { type: "button", disabled: busy || batch.state === "stopping", onClick: () => stop(batch), children: batch.state === "stopping" ? "Stopping…" : "Stop" }),
        (0, A.jsx)("button", { type: "button", onClick: manage, children: "Findings and report" }),
      ] }),
    ] }, batch.batchId)),
    error && (0, A.jsx)("p", { role: "status", className: "security-error", children: error }),
  ] });
}

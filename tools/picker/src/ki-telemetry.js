// Tool-failure telemetry and error enrichment, shared by every tool family
// through kiPolicyWrap. Telemetry counts per-tool errors plus which tool the
// model called next after each error, so recovery-loop cost is measurable
// through get_capabilities. Best-effort only; it never blocks a tool call.
// next is nested { failedTool: { followingTool: count } } so no dynamic key
// is ever built by concatenation.
var KI_TELEMETRY_KEY = "ki_tool_telemetry", kiTelemetry = { counts: {}, next: {} }, kiTelemetryLast = new Map(), kiTelemetryFlush = null, kiTelemetryStarted = false;
function kiTelemetryInit() {
  if (kiTelemetryStarted) return; kiTelemetryStarted = true;
  try { chrome.storage.local.get(KI_TELEMETRY_KEY).then(stored => { const saved = stored?.[KI_TELEMETRY_KEY]; if (saved) kiTelemetry = { counts: { ...saved.counts }, next: { ...saved.next } }; }).catch(() => {}); } catch {}
}
function kiTelemetrySchedule() {
  if (kiTelemetryFlush !== null) return;
  kiTelemetryFlush = setTimeout(() => { kiTelemetryFlush = null; try { chrome.storage.local.set({ [KI_TELEMETRY_KEY]: kiTelemetry }).catch(() => {}); } catch {} }, 10000);
}
function kiTelemetryRecord(meta, session, failed) {
  try {
    kiTelemetryInit();
    const name = meta?.name || "unknown", owner = typeof kiWorkspaceOwner === "function" ? kiWorkspaceOwner(session) : session;
    if (failed) {
      kiTelemetry.counts[name] = (kiTelemetry.counts[name] || 0) + 1;
      kiTelemetryLast.set(owner, name);
    } else {
      const previous = kiTelemetryLast.get(owner);
      if (previous !== undefined) {
        const bucket = kiTelemetry.next[previous] || (kiTelemetry.next[previous] = {});
        bucket[name] = (bucket[name] || 0) + 1;
        kiTelemetryLast.delete(owner);
      }
    }
    kiTelemetrySchedule();
  } catch {}
}
function kiTelemetrySummary() {
  const top = Object.entries(kiTelemetry.counts).sort((a, b) => b[1] - a[1]).slice(0, 20).map(([tool, count]) => ({ tool, count }));
  const afterError = Object.entries(kiTelemetry.next).flatMap(([failed, followers]) =>
    Object.entries(followers).map(([follower, count]) => ({ failed, follower, count }))).sort((a, b) => b.count - a.count).slice(0, 20);
  return { errors: top, afterError };
}
// Errors are the curriculum: when recovery needs data the harness already has
// (which tabs exist right now), embed it in the error so the model spends no
// extra turn on a discovery call. Plain message text when there is nothing
// useful to add — matches the original bundle's tab error wording.
async function kiErrorEnvelope(meta, error, session) {
  const message = error instanceof Error ? error.message : String(error);
  let tabs;
  if (/no tab|tab matching|tab-group|invalid tab|tab.*unavailable|tabId must/i.test(message)) {
    try {
      const open = (await kiOpenTabs()).slice(0, 10);
      tabs = open.length ? open : "No HTTP(S) tabs are open.";
    } catch {}
  }
  if (tabs === undefined) return message;
  return JSON.stringify({ error: message, ...(error?.code ? { code: error.code } : {}), ...(error?.retryable === false ? { retryable: false, ...(error?.recovery ? { recovery: error.recovery } : {}) } : {}), tabs, hint: "Pick a tabId from tabs and retry; no extra tab listing is needed." });
}
async function kiOpenTabs() {
  const all = await chrome.tabs.query({});
  return all.filter(tab => /^https?:/i.test(tab.url || "")).map(tab => ({ tabId: tab.id, url: tab.url, title: String(tab.title || "").slice(0, 80), active: !!tab.active }));
}
// Under node --test this file is required directly; inside the bundle the
// guard is false and the functions stay in the IIFE scope.
if (typeof module === "object" && module.exports) module.exports = { kiTelemetryRecord, kiTelemetrySummary, kiErrorEnvelope, kiOpenTabs };


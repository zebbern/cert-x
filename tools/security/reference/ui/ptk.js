const ACTIVE = new Set(["starting", "running", "stopping"]);
const node = (tag, text, className) => { const element = document.createElement(tag); if (text != null) element.textContent = text; if (className) element.className = className; return element; };
function button(text, action, className = "") { const element = node("button", text, className); element.type = "button"; element.onclick = action; return element; }
async function request(op, args = {}) {
  const response = await chrome.runtime.sendMessage({ type: "KI_PTK", op, ...args });
  if (!response?.ok) throw Error(response?.error || "PTK request failed.");
  return response.result;
}
function text(value, limit = 12000) { const output = typeof value === "string" ? value : JSON.stringify(value, null, 2); return String(output || "").slice(0, limit); }
function summaryText(value) {
  const count = value?.findingsCount ?? value?.vulnsCount ?? value?.totalFindings;
  return Number.isFinite(count) ? count + (count === 1 ? " finding" : " findings") : "Analysis summary available in Findings.";
}
function isObservation(record) { return record.mode === "observe" || record.engines?.includes("IAST"); }
function scanLabel(record) {
  if (!isObservation(record)) return record.state;
  if (record.state === "running") return { observing: "Observing", degraded: "Degraded coverage", starting: "Starting instrumentation" }[record.observationState] || "Starting instrumentation";
  return { starting: "Starting instrumentation", stopping: "Stopping", completed: "Completed", interrupted: "Interrupted", unknown: "State unknown", error: "Failed" }[record.state] || record.state;
}
function observationSummary(record) {
  const count = record.summary?.findingsCount ?? record.summary?.vulnsCount ?? record.summary?.totalFindings;
  return ["IAST", scanLabel(record), Number.isFinite(count) ? count + (count === 1 ? " candidate" : " candidates") : null].filter(Boolean).join(" · ");
}
function canExtend(record) { return isObservation(record) && ["starting", "running"].includes(record.state) && Number.isFinite(record.startedAt) && record.deadline < record.startedAt + 1800000; }
function activity(container, values) {
  if (!Array.isArray(values) || !values.length) return;
  const details = node("details"), list = node("ul"); details.append(node("summary", "Nearby activity · timing only"));
  for (const action of values.slice(-10)) list.append(node("li", [action.startedAt || action.at || action.timestamp ? new Date(action.startedAt || action.at || action.timestamp).toLocaleTimeString() : null, action.label || action.summary || action.tool || action.toolName, action.route || action.url, action.outcome].filter(Boolean).map(value => text(value, 500)).join(" · ")));
  details.append(node("p", "Nearby actions provide context; timing does not establish the cause of a finding.", "ptk-meta"), list); container.append(details);
}
function warnings(container, values) { for (const value of (Array.isArray(values) ? values : []).slice(0, 12)) container.append(node("p", text(value, 1200), "ptk-meta")); }
function renderFindings(container, value) {
  container.replaceChildren();
  container.append(node("p", "Scanner candidates · verify impact before reporting", "ptk-meta"));
  warnings(container, value.scan?.warnings); warnings(container, value.analysis?.warnings); warnings(container, value.warnings);
  activity(container, value.nearbyActions);
  if (value.analysis?.summary) { const details = node("details"); details.append(node("summary", "Analysis and coverage"), node("pre", text(value.analysis.summary))); container.append(details); }
  const findings = Array.isArray(value.findings) ? value.findings : [];
  if (!findings.length) container.append(node("p", "No findings returned. Check coverage and warnings before drawing conclusions.", "ptk-meta"));
  for (const finding of findings.slice(0, 100)) {
    const card = node("article", null, "ptk-finding");
    card.append(node("h4", text(finding.title || finding.name || finding.ruleName || finding.id || "Finding", 250)));
    card.append(node("small", [finding.engine, finding.severity, finding.confidence && "Confidence: " + text(finding.confidence, 150)].filter(Boolean).join(" · ")));
    if (finding.url || finding.resource || finding.location) card.append(node("p", text(finding.url || finding.resource || finding.location, 1800), "ptk-meta"));
    const detail = node("details"); detail.append(node("summary", "Evidence and details"), node("pre", text(finding))); card.append(detail); container.append(card);
    activity(card, finding.nearbyActions);
  }
  if (value.truncated || findings.length > 100) container.append(node("p", "Preview shortened. Export the report for the retained findings.", "ptk-meta"));
}
function readyText(result) {
  if (!result) return "Check the selected page.";
  if (result.ready) return "Ready · PTK " + result.version;
  const blockers = (result.blockers || []).map(value => text(value, 500));
  return blockers.length ? blockers.map(value => value === "automation_disabled" ? "PTK is available · activation needed" : value === "automation_bridge_unavailable" ? "Load PTK v10 and reload this page." : value.replaceAll("_", " ")).join(" · ") : "PTK is not ready on this page.";
}
function canStart(result) { return !!result && (result.ready || (result.automationEnabled === false && (result.blockers || []).length > 0 && result.blockers.every(value => value === "automation_disabled"))); }
export async function initPtk() {
  const root = document.getElementById("ptk-section"); if (!root) throw Error("PTK settings panel is missing."); root.classList.add("ptk-root");
  if (!document.querySelector("link[data-ptk-style]")) { const link = node("link"); link.rel = "stylesheet"; link.href = new URL("./ptk.css", import.meta.url).href; link.dataset.ptkStyle = ""; document.head.append(link); }
  const session = new URLSearchParams(location.search).get("session") || null;
  const header = node("header"); header.append(node("h1", "OWASP PTK"), node("p", "Analyze the current application with PTK v10."));
  const card = node("section", null, "card ptk-card"), tabs = node("select", null, "ptk-tab"), status = node("p", "Choose a page.", "ptk-status"), actions = node("div", null, "ptk-actions"), notice = node("p", "", "ptk-meta");
  tabs.setAttribute("aria-label", "PTK tab"); status.setAttribute("role", "status"); notice.setAttribute("role", "status");
  const check = button("Check connection", () => run(checkPage)), analyze = button("Analyze app", () => run(() => start(false)), "primary"), observe = button("Observe while browsing", () => run(() => start(true)));
  const targeted = button("Test selected requests", () => {
    const params = new URLSearchParams(location.search); params.set("section", "dast");
    if (params.get("embed") === "1") parent.postMessage({ type: "settings-section", section: "dast" }, location.origin);
    else location.search = params.toString();
  });
  const accounts = button("Compare accounts", () => {
    const params = new URLSearchParams(location.search); params.set("section", "authz");
    if (params.get("embed") === "1") parent.postMessage({ type: "settings-section", section: "authz" }, location.origin);
    else location.search = params.toString();
  }); actions.append(analyze, observe, targeted, accounts, check);
  const options = node("details", null, "ptk-options"); options.append(node("summary", "Analysis options"));
  const engines = new Set(["SAST", "SCA"]), controls = [];
  for (const [engine, label] of [["SAST", "Client-side code (SAST)"], ["SCA", "Dependencies (SCA)"]]) {
    const row = node("div", null, "ptk-row"), control = button("", () => { if (engines.has(engine)) engines.delete(engine); else engines.add(engine); control.setAttribute("aria-checked", String(engines.has(engine))); control.classList.toggle("is-on", engines.has(engine)); update(); }, "wb-toggle wb-toggle--sm is-on");
    control.setAttribute("role", "switch"); control.setAttribute("aria-label", label); control.setAttribute("aria-checked", "true"); control.append(node("span", null, "wb-toggle-thumb")); controls.push(control); row.append(node("span", label), control); options.append(row);
  }
  const duration = node("input"); duration.type = "number"; duration.min = "10"; duration.max = "300"; duration.value = "60"; duration.setAttribute("aria-label", "Analysis duration in seconds");
  const durationRow = node("div", null, "ptk-row"); durationRow.append(node("label", "Analysis duration (seconds)"), duration); options.append(durationRow);
  const observationDuration = node("input"); observationDuration.type = "number"; observationDuration.min = "1"; observationDuration.max = "30"; observationDuration.value = "10"; observationDuration.setAttribute("aria-label", "Observation duration in minutes");
  const observationRow = node("div", null, "ptk-row"); observationRow.append(node("label", "Observation duration (minutes)"), observationDuration); options.append(observationRow);
  options.append(node("p", "Observation uses IAST alone. Wait for Observing before exercising the workflow; only one observation can run at a time.", "ptk-meta"));
  options.append(node("p", "Browse the application while analysis collects code and dependencies. Stop is requested after the selected duration. Keep the target tab open.", "ptk-meta"));
  const scans = node("section", null, "card ptk-card"), scanList = node("div"), results = node("section", null, "ptk-result"); results.hidden = true; scans.append(node("h2", "Scans"), scanList);
  const setup = node("details", null, "ptk-setup"); setup.append(node("summary", "Set up PTK v10"), node("p", "Build the supplied PTK source, then load the generated extension alongside cert-x in the same browser.", "ptk-meta"));
  const source = node("input"); source.placeholder = "Absolute path to pentestkit-10.0.0-release"; source.setAttribute("aria-label", "PTK source folder");
  const command = node("pre"), copy = button("Copy build command", async () => { try { await navigator.clipboard.writeText(command.textContent); notice.textContent = "Build command copied."; } catch (error) { notice.textContent = "Copy failed. Select the command below."; } });
  const updateCommand = () => { const directory = source.value.trim(); command.textContent = "powershell -NoProfile -ExecutionPolicy Bypass -File .\\tools\\ptk\\build.ps1 -ExtensionId " + chrome.runtime.id + (directory ? " -Source '" + directory.replaceAll("'", "''") + "'" : ""); };
  source.oninput = updateCommand; updateCommand(); setup.append(source, command, copy, node("p", "Run from the cert-x repository. The build command prints the folder to load using chrome://extensions → Load unpacked. Reload the target page after loading PTK, then check the connection.", "ptk-meta"));
  card.append(tabs, status, actions, options); root.replaceChildren(header, card, notice, scans, results, setup);
  let busy = false, disposed = false, readiness = null, records = [], tabList = [], lastRecords = "", timer;
  function update() {
    tabs.disabled = busy || !tabList.length; check.disabled = busy || !tabList.length; analyze.disabled = busy || !session || !engines.size || !canStart(readiness);
    observe.disabled = busy || !session || !canStart(readiness) || records.some(record => isObservation(record) && ACTIVE.has(record.state));
    duration.disabled = busy; observationDuration.disabled = busy; for (const control of controls) control.disabled = busy;
    if (!session) notice.textContent = "Open a Bug bounty chat to analyze this page.";
  }
  async function run(action) { if (busy) return; busy = true; notice.classList.remove("ptk-error"); notice.textContent = ""; update(); try { await action(); } catch (error) { notice.textContent = error.message; notice.classList.add("ptk-error"); } finally { busy = false; update(); } }
  async function checkPage() { readiness = null; status.textContent = "Checking…"; try { readiness = await request("check", { session, tabId: Number(tabs.value) }); status.textContent = readyText(readiness); } catch (error) { status.textContent = error.message; throw error; } }
  async function refreshTabs() {
    const selected = tabs.value; tabList = await request("tabs", { session }); tabs.replaceChildren();
    for (const tab of tabList) { const option = node("option", tab.title + " · " + tab.origin); option.value = tab.tabId; tabs.append(option); }
    if (tabList.some(tab => String(tab.tabId) === selected)) tabs.value = selected;
    else if (tabList.length) tabs.value = String((tabList.find(tab => tab.working) || tabList.find(tab => tab.active) || tabList[0]).tabId);
    if (!tabList.length) status.textContent = "Open an HTTP or HTTPS page first.";
    readiness = null; update(); if (tabList.length) await checkPage();
  }
  async function start(observation = false) {
    const seconds = observation ? Number(observationDuration.value) * 60 : Number(duration.value);
    if (observation ? !Number.isInteger(Number(observationDuration.value)) || seconds < 60 || seconds > 1800 : !Number.isInteger(seconds) || seconds < 10 || seconds > 300) throw Error(observation ? "Choose an observation duration from 1 to 30 minutes." : "Choose a duration from 10 to 300 seconds.");
    const record = await request("start", { session, tabId: Number(tabs.value), expectedOrigin: readiness.origin, engines: observation ? ["IAST"] : [...engines], durationSeconds: seconds });
    notice.textContent = observation ? "Observation requested." : record.state === "running" ? "Analysis started." : "Analysis " + record.state + "."; await refreshRecords();
    try { await checkPage(); } catch { /* Keep the successful scan result; checkPage reports readiness separately. */ }
  }
  async function scanAction(op, record) {
    const value = await request(op, { session, scanId: record.scanId, ...(op === "findings" ? { limit: 100 } : {}) });
    if (op === "findings") { results.hidden = false; renderFindings(results, value); results.prepend(button("Close findings", () => { results.hidden = true; })); }
    if (op === "export") {
      const files = value.reports || []; notice.textContent = files.length ? "Saved " + files.length + (files.length === 1 ? " report to Outputs." : " reports to Outputs.") : "No report files were saved.";
      if (value.warnings?.length) notice.textContent += " " + value.warnings.map(value => text(value, 300)).join(" · ");
    }
    if (op === "extend") notice.textContent = "Observation deadline extended · " + new Date(value.deadline).toLocaleTimeString();
    await refreshRecords();
    if (op === "stop") try { await checkPage(); } catch { /* Readiness status must not turn a successful Stop request into a failed operation. */ }
  }
  async function refreshRecords() {
    if (!session) { scanList.replaceChildren(node("p", "Open a chat to view its scans.", "ptk-meta")); return; }
    const value = await request("state", { session }); if (disposed) return; records = value.scans || [];
    const key = JSON.stringify(records.map(({ updatedAt, readiness, ...record }) => ({ ...record, ...(readiness ? { readiness: Object.fromEntries(Object.entries(readiness).filter(([key]) => key !== "checkedAt")) } : {}) })));
    if (key === lastRecords) return; lastRecords = key;
    const focused = document.activeElement?.closest("[data-ptk-scan]")?.dataset.ptkScan, focusedLabel = focused ? document.activeElement.textContent : null;
    const expanded = new Set([...scanList.querySelectorAll("[data-ptk-scan] details[open]")].map(detail => detail.closest("[data-ptk-scan]").dataset.ptkScan + ":" + detail.querySelector("summary")?.textContent));
    scanList.replaceChildren();
    for (const record of records.slice().reverse()) {
      const row = node("article", null, "ptk-scan"), controls = node("div", null, "ptk-actions");
      row.dataset.ptkScan = record.scanId;
      row.append(node("h3", record.title || record.origin, "ptk-scan-title"), node("p", isObservation(record) ? observationSummary(record) : [record.state, record.engines?.join(" + "), record.origin].filter(Boolean).join(" · "), "ptk-meta"));
      if (record.summary && !isObservation(record)) row.append(node("p", summaryText(record.summary), "ptk-meta"));
      if (isObservation(record) && ACTIVE.has(record.state)) row.append(node("p", "Stop requested by " + new Date(record.deadline).toLocaleTimeString() + " · 30-minute maximum", "ptk-meta"));
      if (record.readiness || record.coverage) { const coverage = node("details"); coverage.append(node("summary", "Instrumentation and coverage"), node("pre", text({ readiness: record.readiness, coverage: record.coverage }, 10000))); row.append(coverage); }
      if (record.error) row.append(node("p", record.error, "ptk-error")); warnings(row, [...new Set([...(record.warnings || []), ...(record.coverage?.warnings || [])])]);
      if (record.cleanup?.reloadRecommended) {
        row.append(node("p", record.cleanup.message || "Reload the observed page when ready to reset instrumentation.", "ptk-meta"));
        controls.append(button("Reload page", () => run(async () => {
          const tab = await chrome.tabs.get(record.tabId);
          if (new URL(tab.pendingUrl || tab.url).origin !== record.origin) throw Error("The tab changed origin. Reload the intended page directly.");
          await chrome.tabs.reload(record.tabId); notice.textContent = "Page reload requested.";
        })));
      }
      if (ACTIVE.has(record.state)) { const stop = button(record.state === "stopping" ? "Stopping…" : "Stop", () => run(() => scanAction("stop", record))); stop.disabled = record.state === "stopping"; controls.append(stop); }
      if (isObservation(record) && ["starting", "running"].includes(record.state)) { const extend = button("Extend 5 minutes", () => run(() => scanAction("extend", record))); extend.disabled = !canExtend(record); controls.append(extend); }
      controls.append(button("Findings", () => run(() => scanAction("findings", record))));
      const exportReport = button("Export report", () => run(() => scanAction("export", record))); exportReport.disabled = ACTIVE.has(record.state) || ["interrupted", "error"].includes(record.state); controls.append(exportReport);
      row.append(controls); scanList.append(row);
      for (const detail of row.querySelectorAll("details")) if (expanded.has(record.scanId + ":" + detail.querySelector("summary")?.textContent)) detail.open = true;
      if (record.scanId === focused) [...controls.querySelectorAll("button")].find(button => button.textContent === focusedLabel)?.focus({ preventScroll: true });
    }
    if (!records.length) scanList.append(node("p", "No scans in this chat yet.", "ptk-meta")); update();
  }
  async function poll() {
    if (disposed) return;
    try { if (!document.hidden && !busy && records.some(record => ACTIVE.has(record.state))) { for (const record of records.filter(record => ACTIVE.has(record.state))) await request("status", { session, scanId: record.scanId }); await refreshRecords(); } }
    catch (error) { notice.textContent = error.message; }
    finally { if (!disposed) timer = setTimeout(poll, 3000); }
  }
  tabs.onchange = () => run(checkPage);
  const changed = (changes, area) => { if (area === "local" && changes.ki_ptk_scans && !busy) refreshRecords().catch(error => { notice.textContent = error.message; }); };
  const visible = () => { if (!document.hidden && !busy) void run(async () => { await refreshTabs(); await refreshRecords(); }); };
  const dispose = () => { disposed = true; clearTimeout(timer); chrome.storage.onChanged.removeListener(changed); document.removeEventListener("visibilitychange", visible); };
  chrome.storage.onChanged.addListener(changed); document.addEventListener("visibilitychange", visible); window.addEventListener("pagehide", dispose, { once: true });
  await run(async () => { await refreshTabs(); await refreshRecords(); }); timer = setTimeout(poll, 3000); return dispose;
}

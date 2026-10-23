const $ = id => document.getElementById(id);
let busy = false, selected = null, cursor = 0, output = "", lastList = "";
async function request(op, extra = {}) {
  const response = await chrome.runtime.sendMessage({ type: "KI_WORKSPACE", op, ...extra });
  if (!response?.ok) throw Error(response?.error || "Job request failed.");
  return response.result;
}
async function refresh() {
  if (busy || document.hidden) return; busy = true;
  try {
    const data = await request("jobs");
    $("jobs-status").textContent = data.available ? (data.jobs.length ? "" : "No background commands yet.") : /Unknown native operation/.test(data.error) ? "Update the native host to use background jobs." : data.error;
    const key = JSON.stringify(data.jobs);
    if (key !== lastList) {
      lastList = key; $("jobs-list").replaceChildren();
      for (const job of data.jobs.slice().reverse()) {
        const row = document.createElement("div"); row.className = "row";
        const main = document.createElement("div"); main.className = "row-main";
        const info = document.createElement("div"), title = document.createElement("h3"), detail = document.createElement("p");
        title.textContent = job.command || "Command"; title.title = job.command; detail.className = "meta"; detail.title = job.cwd || "";
        detail.textContent = job.state.replaceAll("_", " ") + (job.cwd ? " · " + job.cwd.split(/[\\/]/).pop() : "") + (job.startedAt ? " · " + new Date(job.startedAt).toLocaleTimeString() : "") + (job.exitCode !== null && job.exitCode !== undefined ? " · exit " + job.exitCode : "");
        info.append(title, detail); main.append(info);
        const actions = document.createElement("div"); actions.className = "actions";
        const show = document.createElement("button"); show.textContent = "Output"; show.type = "button";
        show.onclick = () => { selected = job.jobId; cursor = 0; output = ""; $("job-output-panel").hidden = false; };
        actions.append(show);
        if (["running", "cancelling"].includes(job.state)) {
          const stop = document.createElement("button"); stop.type = "button"; stop.textContent = "Stop"; stop.disabled = job.state === "cancelling";
          stop.onclick = async () => { stop.disabled = true; try { await request("job_cancel", { id: job.jobId }); lastList = ""; } catch (error) { $("jobs-status").textContent = error.message; stop.disabled = false; } };
          actions.append(stop);
        }
        row.append(main, actions); $("jobs-list").append(row);
      }
    }
    if (selected) {
      try {
        const data = await request("job_read", { id: selected, cursor });
        if (data.truncated) output += "\n[Earlier output was evicted]\n";
        output += data.chunks.map(chunk => (chunk.stream === "stderr" ? "[stderr] " : "") + chunk.text).join(""); cursor = data.nextCursor;
        if (output.length > 262144) output = "[Earlier preview omitted]\n" + output.slice(-250000);
        $("job-output").textContent = output || "No output yet.";
        $("job-output-state").textContent = data.state + (data.hasMore ? " · reading more…" : "");
      } catch (error) { $("job-output").textContent = error.message; selected = null; }
    }
  } catch (error) { $("jobs-status").textContent = error.message; }
  finally { busy = false; }
}
$("jobs-refresh").onclick = refresh;
$("job-output-close").onclick = () => { selected = null; $("job-output-panel").hidden = true; };
void refresh();
const timer = setInterval(refresh, 2000);
window.addEventListener("pagehide", () => clearInterval(timer), { once: true });
document.addEventListener("visibilitychange", refresh);

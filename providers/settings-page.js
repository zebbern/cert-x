try {
const params = new URLSearchParams(location.search);
const requested = params.get("section");
const section = ["ptk", "dast", "authz"].includes(requested) ? "security" : ["models", "mcp", "local", "browser", "tools", "health", "profiles", "workspaces", "security"].includes(requested) ? requested : "models";
const panels = { models: "models-panel", mcp: "mcp", local: "native-section", browser: "browser-section", tools: "permissions-section", health: "health-section", profiles: "profiles-section", workspaces: "workspaces-section", security: "security-section", authz: "authz-section" };
for (const [name, id] of Object.entries(panels)) document.getElementById(id).hidden = name !== section;
if (params.get("embed") === "1") document.body.classList.add("embed");
const stored = await chrome.storage.local.get(["sidepanel_theme", "sidepanel_language"]);
const theme = params.get("theme") || stored.sidepanel_theme || "system";
document.documentElement.dataset.theme = theme === "system" ? matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light" : theme;
document.title = { models: "Your models", mcp: "MCP servers", local: "Local computer", browser: "Browser control", tools: "Tools & permissions", health: "Capability health", profiles: "Profiles", workspaces: "Workspaces", security: "Security testing" }[section];
document.querySelectorAll("a[href^='?section=']").forEach(link => {
  const target = new URL(link.href);
  for (const name of ["embed", "theme", "session"]) if (params.has(name)) target.searchParams.set(name, params.get(name));
  link.href = target.href;
  if (target.searchParams.get("section") === section) link.setAttribute("aria-current", "page");
  if (params.get("embed") === "1") link.addEventListener("click", event => {
    event.preventDefault();
    parent.postMessage({ type: "settings-section", section: target.searchParams.get("section") }, location.origin);
  });
});
if (section === "models") { await import("./providers.js"); await import("./fast-browse.js"); }
if (section === "mcp") { await import("./mcp.js"); await import("./local-mcp.js"); await import("./mcp-import-ui.js"); }
if (section === "local") { await import("./native.js"); await import("./jobs.js"); }
if (section === "browser") await import("./browser-control.js");
if (section === "tools") await import("./permissions.js");
if (section === "health") await import("./health.js");
if (["profiles", "workspaces"].includes(section)) await (await import("./contexts.js")).initContexts(section);
if (section === "security") await (await import("./security.js")).initSecurity({ view: requested === "authz" ? "accounts" : params.get("view") || "scans" });
} catch (error) {
  const message = document.createElement("p"); message.setAttribute("role", "alert"); message.textContent = "Could not load settings: " + error.message;
  document.querySelector("main").prepend(message);
} finally { document.querySelector("main").inert = false; }

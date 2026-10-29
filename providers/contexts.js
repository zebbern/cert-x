const BUILTINS = new Set(["default", "research", "coding", "bugbounty"]);
const clone = value => value == null ? value : JSON.parse(JSON.stringify(value));
const modes = [["inherit", "Use global rule"], ["ask", "Always ask"], ["allow", "Allow"], ["disabled", "Disabled"]];
function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text != null) element.textContent = text;
  if (className) element.className = className;
  return element;
}
function button(text, action, className = "") {
  const element = node("button", text, className); element.type = "button"; element.onclick = action; return element;
}
function field(label, control, hint) {
  const element = node("label", null, "context-field"); element.append(node("span", label), control);
  if (hint) element.append(node("span", hint, "hint"));
  return element;
}
function input(value = "", placeholder = "") {
  const element = node("input"); element.value = value; element.placeholder = placeholder; element.spellcheck = false; return element;
}
function select(options, value, label) {
  const element = node("select"); element.setAttribute("aria-label", label);
  for (const [id, text] of options) { const option = node("option", text); option.value = id; element.append(option); }
  element.value = value; return element;
}
function disclosure(label) {
  const element = node("details", null, "context-details"); element.append(node("summary", label)); return element;
}
function toggle(label, enabled, change) {
  const element = button("", () => { enabled = !enabled; update(); change(enabled); }, "wb-toggle wb-toggle--sm");
  element.setAttribute("role", "switch"); element.setAttribute("aria-label", label);
  element.append(node("span", null, "wb-toggle-thumb"));
  function update() { element.setAttribute("aria-checked", String(enabled)); element.classList.toggle("is-on", enabled); }
  update(); return element;
}
async function api(op, extra = {}) {
  const response = await chrome.runtime.sendMessage({ type: "KI_CONTEXT", op, ...extra });
  if (!response?.ok) throw Error(response?.error || "Could not update settings.");
  return response.result;
}
function modelKey(value) { return value ? JSON.stringify([value.connectionId, value.modelId]) : ""; }

export async function initContexts(section) {
  const root = document.getElementById(section === "profiles" ? "profiles-section" : "workspaces-section");
  if (!root) throw Error("Settings panel is missing.");
  if (!document.querySelector("link[data-context-style]")) {
    const style = node("link"); style.rel = "stylesheet"; style.href = new URL("./contexts.css", import.meta.url).href;
    style.dataset.contextStyle = ""; document.head.append(style);
  }
  const workspaceMode = section === "workspaces";
  root.classList.add("context-settings");
  let state, inventory = { groups: [], tools: [] }, models = [], modelError = "", draft = null, saving = false;
  const title = workspaceMode ? "Workspaces" : "Profiles";
  const header = node("div", null, "toolbar"), list = node("div", null, "card list context-list");
  const editor = node("form", null, "card context-editor"), status = node("p", "", "hint context-status");
  editor.hidden = true; status.setAttribute("role", "status"); status.setAttribute("aria-live", "polite");
  header.append(node("h2", title), button(workspaceMode ? "New workspace" : "New profile", () => open(), "primary"));
  root.replaceChildren(header, list, editor, status);
  const message = (text, error = false) => { status.textContent = text; status.classList.toggle("error", error); };

  async function load() {
    state = await api("state");
    renderList();
  }
  function run(operation) {
    return async () => {
      if (saving) return;
      saving = true;
      try { await operation(); }
      catch (error) { message(error.message, true); }
      finally { saving = false; }
    };
  }
  function confirmAction(title, text, action) {
    const dialog = node("dialog", null, "context-confirm"), actions = node("div", null, "context-actions");
    dialog.append(node("h2", title), node("p", text));
    const cancel = button("Cancel", () => dialog.close());
    const accept = button(title, run(async () => { await action(); dialog.close(); await load(); }), "primary");
    actions.append(cancel, accept); dialog.append(actions); root.append(dialog);
    dialog.addEventListener("close", () => dialog.remove(), { once: true }); dialog.showModal(); cancel.focus();
  }
  function renderList() {
    list.replaceChildren();
    const items = workspaceMode ? state.workspaces : state.profiles;
    for (const item of items) {
      const row = node("div", null, "row context-saved-row"), main = node("div", null, "row-main"), text = node("div");
      const count = workspaceMode ? Object.values(state.chats || {}).filter(chat => chat.workspaceId === item.id).length : 0;
      const profile = workspaceMode && state.profiles.find(profile => profile.id === item.profileId);
      text.append(node("h3", item.name), node("p", workspaceMode ? [profile?.name || "Default", count + (count === 1 ? " chat" : " chats")].join(" · ") : BUILTINS.has(item.id) ? "Built-in profile" : "Custom profile", "meta"));
      main.append(text);
      const actions = node("div", null, "context-actions");
      actions.append(button("Edit", () => open(item)));
      if (!workspaceMode) actions.append(button("Duplicate", run(async () => {
        const previous = new Set(state.profiles.map(profile => profile.id));
        await api("duplicate_profile", { id: item.id }); await load();
        const created = state.profiles.find(profile => !previous.has(profile.id));
        if (created) open(created); else message("Profile duplicated. Choose it from the list.");
      })));
      row.append(main, actions); list.append(row);
    }
    if (!items.length) list.append(node("p", "No workspaces yet. Chats can stay outside a workspace.", "empty"));
  }
  function modelEditor(value, change) {
    const known = models.map(model => [modelKey(model), model.label || model.modelId]);
    const savedKey = modelKey(value), missing = !!savedKey && !known.some(([key]) => key === savedKey);
    if (missing) known.unshift([savedKey, value.modelId + " · unavailable"]);
    const picker = select([["", workspaceMode ? "Use profile preference" : "Use app default"], ...known], savedKey, "Preferred model");
    const wrapper = field("Preferred model", picker), notice = node("span", "", "hint"); wrapper.append(notice);
    const update = () => {
      notice.textContent = modelError || (picker.value === savedKey && missing ? "This model is unavailable. Choose another before sending a message." : "");
      notice.classList.toggle("error", !!notice.textContent);
    };
    picker.onchange = () => { const selected = picker.value ? JSON.parse(picker.value) : null; change(selected ? { connectionId: selected[0], modelId: selected[1] } : null); update(); };
    update(); return wrapper;
  }
  function inheritedControl(container, property, factory, fallback) {
    if (!workspaceMode) { factory(container); return; }
    const picker = select([["inherit", "Use profile settings"], ["custom", "Customize for this workspace"]], draft[property] == null ? "inherit" : "custom", property + " settings");
    const body = node("div", null, "context-custom");
    container.append(picker, body);
    const render = () => { body.replaceChildren(); body.hidden = draft[property] == null; if (!body.hidden) factory(body); };
    picker.onchange = () => { draft[property] = picker.value === "inherit" ? null : clone(fallback()); render(); };
    render();
  }
  function selectedProfile() { return state.profiles.find(profile => profile.id === draft.profileId) || state.profiles.find(profile => profile.id === "default"); }
  function toolSettings(container) {
    draft.tools ||= { groups: {}, tools: {} }; draft.tools.groups ||= {}; draft.tools.tools ||= {};
    for (const group of inventory.groups) {
      const detail = disclosure(group.label), head = node("div", null, "context-setting-row");
      const enabled = draft.tools.groups[group.id] !== false;
      head.append(node("span", "Enable " + group.label.toLowerCase()), toggle("Enable " + group.label.toLowerCase(), enabled, enabled => { draft.tools.groups[group.id] = enabled; }));
      detail.append(head);
      for (const tool of inventory.tools.filter(tool => tool.group === group.id)) {
        const key = tool.family === "mcp" || group.parent === "mcp" ? tool.id : tool.name;
        const row = node("div", null, "context-setting-row"), text = node("div");
        text.append(node("span", tool.label), node("small", tool.name));
        const picker = select([["inherit", "Use group"], ["true", "Enabled"], ["false", "Disabled"]], Object.hasOwn(draft.tools.tools, key) ? String(draft.tools.tools[key]) : "inherit", tool.label + " availability");
        picker.onchange = () => { if (picker.value === "inherit") delete draft.tools.tools[key]; else draft.tools.tools[key] = picker.value === "true"; };
        row.append(text, picker); detail.append(row);
      }
      container.append(detail);
    }
    container.append(node("p", "Availability does not change approval rules. Job status and Stop remain available.", "hint"));
  }
  function mcpSettings(container) {
    const picker = select([["all", "All configured servers"], ["selected", "Selected servers"]], draft.mcp == null ? "all" : "selected", "MCP connections");
    const body = node("div", null, "context-custom"); container.append(picker, body);
    const render = () => {
      body.replaceChildren(); body.hidden = draft.mcp == null; if (body.hidden) return;
      const groups = inventory.groups.filter(group => group.parent === "mcp");
      for (const id of draft.mcp) if (!groups.some(group => group.id === id)) groups.push({ id, label: "Unavailable server" });
      for (const group of groups) {
        const row = node("div", null, "context-setting-row");
        row.append(node("span", group.label), toggle(group.label, draft.mcp.includes(group.id), enabled => { draft.mcp = enabled ? [...new Set([...draft.mcp, group.id])] : draft.mcp.filter(id => id !== group.id); }));
        body.append(row);
      }
      if (!groups.length) body.append(node("p", "No servers configured. Add one in MCP servers.", "hint"));
    };
    picker.onchange = () => { draft.mcp = picker.value === "all" ? null : []; render(); }; render();
  }
  function permissionSettings(container) {
    draft.permissions ||= { groups: {}, tools: {} }; draft.permissions.groups ||= {}; draft.permissions.tools ||= {};
    container.append(node("p", "Global Disabled and Always ask rules still apply.", "hint"));
    const rule = (bucket, id, label) => {
      const picker = select(modes, draft.permissions[bucket][id] || "inherit", label + " permission");
      picker.onchange = () => { if (picker.value === "inherit") delete draft.permissions[bucket][id]; else draft.permissions[bucket][id] = picker.value; };
      return picker;
    };
    for (const group of inventory.groups) {
      const details = disclosure(group.label), row = node("div", null, "context-setting-row");
      row.append(node("span", "Default"), rule("groups", group.id, group.label)); details.append(row);
      for (const tool of inventory.tools.filter(tool => tool.group === group.id)) {
        const row = node("div", null, "context-setting-row"); row.append(node("span", tool.label), rule("tools", tool.id, tool.label)); details.append(row);
      }
      container.append(details);
    }
  }
  function pinSettings(container) {
    draft.pins ||= [];
    const list = node("div", null, "context-pins"), file = input("", "C:\\project\\README.md"), fileActions = node("div", null, "context-inline");
    file.setAttribute("aria-label", "Pinned file path");
    const render = () => {
      list.replaceChildren();
      draft.pins.forEach((pin, index) => {
        const row = node("div", null, "context-setting-row"), text = node("div");
        text.append(node("span", pin.kind === "file" ? pin.path : pin.title || pin.url), node("small", pin.kind === "file" ? "File reference" : pin.url));
        row.append(text, button("Remove", () => { draft.pins.splice(index, 1); render(); })); list.append(row);
      });
    };
    const addFile = () => {
      const path = file.value.trim();
      if (!/^(?:[A-Za-z]:[\\/]|\\\\|\/)/.test(path)) { message("Use an absolute file path.", true); file.focus(); return; }
      if (!draft.pins.some(pin => pin.kind === "file" && pin.path === path)) {
        if (draft.pins.length >= 50) { message("A workspace supports up to 50 pinned references.", true); return; }
        draft.pins.push({ kind: "file", path });
      }
      file.value = ""; render(); message("");
    };
    fileActions.append(file, button("Pin file", addFile));
    const tabPicker = select([["", "Choose an open page"]], "", "Page to pin"), tabActions = node("div", null, "context-inline");
    let tabs = [];
    const refreshTabs = async () => {
      try {
        tabs = (await chrome.tabs.query({})).filter(tab => /^https?:\/\//i.test(tab.url || ""));
        tabPicker.replaceChildren(node("option", "Choose an open page")); tabPicker.firstChild.value = "";
        for (const tab of tabs) { const option = node("option", tab.title || tab.url); option.value = String(tab.id); tabPicker.append(option); }
      } catch (error) { message(error.message, true); }
    };
    tabActions.append(tabPicker, button("Pin page", () => {
      const tab = tabs.find(tab => String(tab.id) === tabPicker.value); if (!tab) return;
      if (!draft.pins.some(pin => pin.kind === "page" && pin.url === tab.url)) {
        if (draft.pins.length >= 50) { message("A workspace supports up to 50 pinned references.", true); return; }
        draft.pins.push({ kind: "page", url: tab.url, title: tab.title || tab.url });
      }
      render();
    }), button("Refresh", refreshTabs));
    container.append(list, fileActions, tabActions, node("p", "References are shared. Contents are read only when needed.", "hint")); render(); void refreshTabs();
  }
  async function outputSettings(container, workspaceId) {
    const result = await chrome.runtime.sendMessage({ type: "KI_WORKSPACE", op: "outputs", workspaceId });
    if (!result?.ok) throw Error(result?.error || "Could not load outputs.");
    const items = result.result || [];
    if (!items.length) { container.append(node("p", "No outputs in this workspace yet.", "hint")); return; }
    const preview = node("div", null, "context-output-preview"); preview.hidden = true;
    for (const item of items.slice().reverse()) {
      const row = node("div", null, "context-setting-row"), text = node("div"), actions = node("div", null, "context-actions");
      text.append(node("span", item.name), node("small", item.sourceChatTitle || item.chatTitle || "Chat " + (item.sourceChat || item.owner || "").slice(0, 12)));
      actions.append(button("Preview", run(async () => {
        const response = await chrome.runtime.sendMessage({ type: "KI_WORKSPACE", op: "output_read", id: item.id });
        if (!response?.ok) throw Error(response?.error || "Could not read output.");
        const value = response.result;
        preview.replaceChildren(button("Close preview", () => { preview.hidden = true; })); preview.hidden = false;
        if (/^image\/(png|jpeg|webp|gif)$/.test(value.mime) && value.encoding === "base64") {
          const image = node("img"); image.alt = value.name; image.src = "data:" + value.mime + ";base64," + value.content; preview.append(image);
        } else if (/text|json|xml|javascript/.test(value.mime)) {
          const text = value.encoding === "base64" ? new TextDecoder().decode(Uint8Array.from(atob(value.content), character => character.charCodeAt(0))) : value.content;
          preview.append(node("pre", text.slice(0, 65536) + (text.length > 65536 ? "\n[Preview shortened]" : "")));
        } else preview.append(node("p", "Open this output from its chat to view or attach it.", "hint"));
      })));
      if (item.downloadId || item.path) actions.append(button(item.downloadId ? "Show" : "Open", run(async () => {
        if (item.downloadId) await chrome.downloads.show(item.downloadId);
        else { const url = new URL("file:///"); url.pathname = item.path.replace(/\\/g, "/"); await chrome.tabs.create({ url: url.toString(), active: false }); }
      })));
      row.append(text, actions); container.append(row);
    }
    container.append(preview);
  }
  function open(item) {
    const profile = state.profiles.find(item => item.id === "default");
    draft = clone(item || (workspaceMode ? { name: "", profileId: "default", folder: "", notes: "", pins: [], model: null, tools: null, mcp: null, permissions: null } : { ...profile, id: undefined, name: "", builtin: false }));
    editor.replaceChildren(); editor.hidden = false; list.hidden = true; header.hidden = true; message("");
    const name = input(draft.name); name.required = true; name.maxLength = 80; name.setAttribute("aria-label", "Name"); name.oninput = () => { draft.name = name.value; };
    const heading = node("div", null, "form-head"); heading.append(node("h2", (item ? "Edit " : "New ") + (workspaceMode ? "workspace" : "profile")), button("Cancel", close));
    editor.append(heading, field("Name", name));
    if (workspaceMode) {
      const profileSelect = select(state.profiles.map(profile => [profile.id, profile.name]), draft.profileId || "default", "Default profile");
      profileSelect.onchange = () => { draft.profileId = profileSelect.value; };
      const folder = input(draft.folder, "Optional absolute folder path"); folder.maxLength = 4096; folder.oninput = () => { draft.folder = folder.value; };
      const notes = node("textarea"); notes.value = draft.notes || ""; notes.rows = 5; notes.maxLength = 20000; notes.oninput = () => { draft.notes = notes.value; };
      editor.append(field("Default profile", profileSelect), field("Working folder", folder), field("Shared notes", notes, "Project context, decisions, or testing instructions. Chat transcripts stay separate."));
      const pins = disclosure("Pinned files & pages"); pinSettings(pins); editor.append(pins);
      const scope = disclosure("Testing scope");
      draft.dastScope ||= { origins: [], excludePaths: [] };
      const origins = node("textarea"); origins.rows = 3; origins.value = draft.dastScope.origins.join("\n"); origins.placeholder = "https://app.example.com";
      const exclusions = node("textarea"); exclusions.rows = 3; exclusions.value = draft.dastScope.excludePaths.join("\n"); exclusions.placeholder = "/logout\n/account/delete";
      const lines = value => value.split(/\r?\n/).map(value => value.trim()).filter(Boolean);
      origins.oninput = () => { draft.dastScope.origins = lines(origins.value); };
      exclusions.oninput = () => { draft.dastScope.excludePaths = lines(exclusions.value); };
      scope.append(field("Allowed origins", origins, "HTTP(S) target origins, one per line. No wildcards."));
      const hostRow = node("div", null, "context-setting-row"), subdomainRow = node("div", null, "context-setting-row");
      const renderSubdomains = () => {
        subdomainRow.replaceChildren(node("span", "Include subdomains"), toggle("Subdomains", draft.dastScope.includeSubdomains === true, enabled => { if (enabled) draft.dastScope.includeSubdomains = true; else delete draft.dastScope.includeSubdomains; }));
        subdomainRow.hidden = draft.dastScope.matchMode !== "host";
      };
      hostRow.append(node("span", "Include HTTP/S and ports on the same host"), toggle("Same host", draft.dastScope.matchMode === "host", enabled => {
        if (enabled) draft.dastScope.matchMode = "host";
        else { delete draft.dastScope.matchMode; delete draft.dastScope.includeSubdomains; }
        renderSubdomains();
      }));
      renderSubdomains();
      scope.append(hostRow, subdomainRow, field("Excluded paths", exclusions, "One path per line. Includes that path and its descendants.")); editor.append(scope);
    } else {
      const instructions = node("textarea"); instructions.value = draft.instructions || ""; instructions.rows = 6; instructions.maxLength = 12000; instructions.oninput = () => { draft.instructions = instructions.value; };
      editor.append(field("Instructions", instructions));
    }
    const advanced = disclosure("Model, tools & permissions");
    advanced.append(modelEditor(draft.model, value => { draft.model = value; }));
    const tools = disclosure("Tools"); inheritedControl(tools, "tools", toolSettings, () => selectedProfile()?.tools || { groups: {}, tools: {} }); advanced.append(tools);
    const mcp = disclosure("MCP connections");
    // A workspace's null means inherit; explicit 'all' keeps all servers without
    // copying credentials. The backend normalizes this selector independently.
    if (workspaceMode) {
      const picker = select([["inherit", "Use profile connections"], ["all", "All configured servers"], ["selected", "Selected servers"]], draft.mcp == null ? "inherit" : draft.mcp === "all" ? "all" : "selected", "MCP connections");
      const body = node("div"); mcp.append(picker, body);
      const render = () => {
        body.replaceChildren(); body.hidden = !Array.isArray(draft.mcp);
        if (!body.hidden) {
          const groups = inventory.groups.filter(group => group.parent === "mcp");
          for (const id of draft.mcp) if (!groups.some(group => group.id === id)) groups.push({ id, label: "Unavailable server" });
          for (const group of groups) {
            const row = node("div", null, "context-setting-row"); row.append(node("span", group.label), toggle(group.label, draft.mcp.includes(group.id), enabled => { draft.mcp = enabled ? [...new Set([...draft.mcp, group.id])] : draft.mcp.filter(id => id !== group.id); })); body.append(row);
          }
          if (!groups.length) body.append(node("p", "No servers configured. Add one in MCP servers.", "hint"));
        }
      };
      picker.onchange = () => { draft.mcp = picker.value === "inherit" ? null : picker.value === "all" ? "all" : []; render(); }; render();
    } else mcpSettings(mcp);
    advanced.append(mcp);
    const permissions = disclosure("Permission preferences"); inheritedControl(permissions, "permissions", permissionSettings, () => selectedProfile()?.permissions || { groups: {}, tools: {} }); advanced.append(permissions);
    editor.append(advanced);
    if (workspaceMode && draft.id) {
      const outputs = disclosure("Workspace outputs"); let loaded = false;
      outputs.ontoggle = () => { if (outputs.open && !loaded) { loaded = true; outputSettings(outputs, draft.id).catch(error => { loaded = false; message(error.message, true); }); } };
      editor.append(outputs);
    }
    const actions = node("div", null, "context-actions context-footer"), save = node("button", "Save", "primary"); save.type = "submit";
    if (item) {
      if (!workspaceMode && BUILTINS.has(item.id)) actions.append(button("Reset profile", () => confirmAction("Reset profile", "Restore this built-in profile's original settings?", async () => { await api("reset_profile", { id: item.id }); close(); })));
      else actions.append(button("Delete", () => confirmAction(workspaceMode ? "Delete workspace" : "Delete profile", workspaceMode ? "Chats, files, tabs and outputs will be kept." : "Workspaces using this profile switch to Default. Chats inherit their workspace profile or Default.", async () => { await api(workspaceMode ? "delete_workspace" : "delete_profile", { id: item.id }); close(); }), "danger"));
    }
    actions.append(button("Cancel", close), save); editor.append(actions);
    editor.onsubmit = event => {
      event.preventDefault();
      void run(async () => {
        save.disabled = true; editor.inert = true;
        try {
          await api(workspaceMode ? "save_workspace" : "save_profile", workspaceMode ? { workspace: draft } : { profile: draft });
          close(); await load(); message("Saved · applies to the next message");
        } finally { save.disabled = false; editor.inert = false; }
      })();
    };
    name.focus();
  }
  function close() { draft = null; editor.hidden = true; editor.replaceChildren(); list.hidden = false; header.hidden = false; }
  const loaded = await Promise.allSettled([api("state"), chrome.runtime.sendMessage({ type: "KI_PERMISSIONS", op: "inventory" }), api("models")]);
  if (loaded[0].status === "rejected") throw loaded[0].reason;
  state = loaded[0].value;
  if (loaded[1].status === "fulfilled" && loaded[1].value?.ok) inventory = loaded[1].value.result;
  else message("Tool settings could not load. Reopen settings to try again.", true);
  if (loaded[2].status === "fulfilled") models = loaded[2].value || [];
  else modelError = "Models could not load. Existing preferences are preserved.";
  renderList();
}

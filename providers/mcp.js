const KEY = "ki_mcp_servers";
const $ = (id) => document.getElementById(id);
const copy = {
  en: {
    heading: "Remote servers",
    note: "Connect remote tools over HTTP.",
    add: "Add a server",
    empty: "No remote servers yet.",
    formAdd: "Add an MCP server",
    formEdit: "Edit MCP server",
    name: "Name",
    url: "Server URL",
    token: "Token",
    tokenHint: "Paste the key only, without Bearer.",
    test: "Test connection",
    testing: "Testing…",
    known: "Quick connect",
    signIn: "Sign in",
    signingIn: "Waiting for you to approve…",
    signedIn: "Connected · available next message",
    cancelled: "Sign-in was cancelled.",
    needsAuth: "This server uses sign-in. Click Sign in.",
    signed: "Signed in",
    postmanUs: "Sign in with your Postman account. No API key.",
    postmanEu: "Paste an API key created in the EU Postman account.",
    addKey: "Add with key",
    save: "Save",
    cancel: "Cancel",
    edit: "Edit",
    remove: "Remove",
    confirm: "Remove this server?",
    yes: "Remove",
    no: "Keep",
    urlError: "Enter a URL that starts with http:// or https://.",
    saved: "Connected · available next message",
    tools: (n) => (n === 1 ? "1 tool" : `${n} tools`),
    connected: (names) => `Connected · ${names.length} ${names.length === 1 ? "tool" : "tools"}`,
    none: "Connected, but the server published no tools.",
  },
  zh: {
    heading: "远程服务器",
    note: "通过 HTTP 连接远程工具。",
    add: "添加服务器",
    empty: "还没有 MCP 服务器。",
    formAdd: "添加 MCP 服务器",
    formEdit: "编辑 MCP 服务器",
    name: "名称",
    url: "服务器地址",
    token: "令牌",
    tokenHint: "可选。只粘贴密钥本身，不要带 Bearer。欧盟地址只接受 postman.eu 的密钥；postman.com 的密钥请用 https://mcp.postman.com/minimal。",
    test: "测试连接",
    testing: "测试中…",
    known: "可用的服务器",
    signIn: "登录",
    signingIn: "等待你在网页上确认…",
    signedIn: "已登录。下一条消息会带上这些工具。",
    cancelled: "登录已取消。",
    needsAuth: "这个服务器需要登录。点击“登录”。",
    signed: "已登录",
    postmanUs: "用 Postman 账号登录，不需要 API key。",
    postmanEu: "粘贴在欧盟 Postman 账号里创建的 API key。",
    addKey: "用密钥添加",
    save: "保存",
    cancel: "取消",
    edit: "编辑",
    remove: "移除",
    confirm: "移除这个服务器？",
    yes: "移除",
    no: "保留",
    urlError: "请填写以 http:// 或 https:// 开头的地址。",
    saved: "已保存。下一条消息会带上这些工具。",
    tools: (n) => (n === 1 ? "1 个工具" : `${n} 个工具`),
    connected: (names) => `已连上。工具：${names.join("、")}`,
    none: "已连上，但服务器没有发布工具。",
  },
};

const KNOWN = [
  { label: "Postman (US)", url: "https://mcp.postman.com/minimal", auth: "oauth", blurb: "postmanUs" },
  { label: "Postman (EU)", url: "https://mcp.eu.postman.com/minimal", auth: "token", blurb: "postmanEu" },
];

let lang = "en";
let servers = [];
let editingId = null;
const t = () => copy[lang] || copy.en;

function status(text, kind) {
  const node = $("mcp-status");
  node.textContent = text || "";
  node.classList.toggle("is-error", kind === "error");
  node.classList.toggle("is-ok", kind === "ok");
}

function applyCopy() {
  const s = t();
  $("mcp-heading").textContent = s.heading;
  $("mcp-note").textContent = s.note;
  $("mcp-add").textContent = s.add;
  $("mcp-label-name").textContent = s.name;
  $("mcp-label-url").textContent = s.url;
  $("mcp-label-token").textContent = s.token;
  $("mcp-token-hint").textContent = s.tokenHint;
  $("mcp-test").textContent = s.test;
  $("mcp-known-heading").textContent = s.known;
  $("mcp-signin").textContent = s.signIn;
  $("mcp-cancel").textContent = s.cancel;
  $("mcp-save").textContent = editingId ? s.save : (lang === "zh" ? "连接" : "Connect");
  $("mcp-form-title").textContent = editingId ? s.formEdit : s.formAdd;
}

async function persist(next) {
  servers = next;
  await chrome.storage.local.set({ [KEY]: servers });
  render();
}

function renderKnown() {
  const s = t();
  const list = $("mcp-known");
  list.replaceChildren();
  for (const item of KNOWN) {
    const row = document.createElement("div");
    row.className = "row";
    const main = document.createElement("div");
    main.className = "row-main";
    const text = document.createElement("div");
    const title = document.createElement("h3");
    title.textContent = item.label;
    const meta = document.createElement("p");
    meta.className = "meta";
    meta.textContent = s[item.blurb];
    text.append(title, meta);
    main.append(text);
    const actions = document.createElement("div");
    actions.className = "actions";
    const button = document.createElement("button");
    button.type = "button";
    button.className = item.auth === "oauth" ? "primary" : "";
    button.textContent = item.auth === "oauth" ? s.signIn : s.addKey;
    button.addEventListener("click", () => {
      if (item.auth === "oauth") signIn(item.url, item.label);
      else {
        openForm(null);
        $("mcp-name").value = item.label;
        $("mcp-url").value = item.url;
        $("mcp-options").open = true;
        $("mcp-token").focus();
      }
    });
    actions.append(button);
    row.append(main, actions);
    list.append(row);
  }
}

function render() {
  const s = t();
  renderKnown();
  const list = $("mcp-list");
  list.replaceChildren();
  if (!servers.length) {
    const empty = document.createElement("p");
    empty.className = "note";
    empty.style.padding = "12px 16px";
    empty.textContent = s.empty;
    list.append(empty);
    return;
  }
  for (const server of servers) {
    const row = document.createElement("div");
    row.className = "row";
    const main = document.createElement("div");
    main.className = "row-main";
    const text = document.createElement("div");
    const title = document.createElement("h3");
    title.textContent = server.label || server.url;
    const meta = document.createElement("p");
    meta.className = "meta";
    meta.textContent = server.oauth?.accessToken ? `${s.signed} · ${server.url}` : server.url;
    text.append(title, meta);
    main.append(text);
    const actions = document.createElement("div");
    actions.className = "actions";
    const edit = document.createElement("button");
    edit.type = "button";
    edit.textContent = s.edit;
    edit.addEventListener("click", () => openForm(server.id));
    const remove = document.createElement("button");
    remove.type = "button";
    remove.textContent = s.remove;
    remove.addEventListener("click", () => {
      remove.hidden = true;
      const ask = document.createElement("span");
      ask.className = "hint";
      ask.textContent = s.confirm;
      const yes = document.createElement("button");
      yes.type = "button";
      yes.className = "danger";
      yes.textContent = s.yes;
      yes.addEventListener("click", () => persist(servers.filter((item) => item.id !== server.id)));
      const no = document.createElement("button");
      no.type = "button";
      no.textContent = s.no;
      no.addEventListener("click", () => render());
      actions.append(ask, yes, no);
    });
    actions.append(edit, remove);
    row.append(main, actions);
    list.append(row);
  }
}

function openForm(id) {
  const server = id ? servers.find((item) => item.id === id) : null;
  editingId = server ? server.id : null;
  $("mcp-form").hidden = false;
  $("mcp-name").value = server?.label || "";
  $("mcp-url").value = server?.url || "";
  $("mcp-token").value = "";
  $("mcp-options").open = false;
  status("");
  applyCopy();
  $("mcp-url").focus();
  $("mcp-form").scrollIntoView({ block: "nearest" });
}

async function testServer() {
  const s = t();
  const url = $("mcp-url").value.trim();
  if (!/^https?:\/\//i.test(url)) {
    status(s.urlError, "error");
    return;
  }
  const current = editingId ? servers.find((item) => item.id === editingId) : null;
  const token = $("mcp-token").value || (current?.url === url ? current.token : "") || "";
  $("mcp-test").disabled = true;
  $("mcp-test").textContent = s.testing;
  status("");
  try {
    const result = await chrome.runtime.sendMessage({ type: "KI_MCP", op: "test", server: { url, token } });
    if (!result?.ok) status(result?.needsAuth ? s.needsAuth : result?.error || "Failed", "error");
    else if (!result.tools?.length) status(s.none, "ok");
    else status(s.connected(result.tools), "ok");
  } catch (error) {
    status(error instanceof Error ? error.message : String(error), "error");
  } finally {
    $("mcp-test").disabled = false;
    $("mcp-test").textContent = s.test;
  }
}

async function save(event) {
  event.preventDefault();
  const s = t();
  const url = $("mcp-url").value.trim();
  if (!/^https?:\/\//i.test(url)) {
    status(s.urlError, "error");
    return;
  }
  const current = editingId ? servers.find((item) => item.id === editingId) : null;
  const token = $("mcp-token").value || (current?.url === url ? current.token : "") || "";
  const record = {
    id: editingId || crypto.randomUUID().slice(0, 8),
    label: $("mcp-name").value.trim() || new URL(url).host,
    url,
    token,
    ...(current?.oauth && current.url === url ? { oauth: current.oauth } : {}),
  };
  $("mcp-save").disabled = true;
  $("mcp-test").disabled = true;
  status(s.testing);
  try {
    const result = await chrome.runtime.sendMessage({ type: "KI_MCP", op: "test", server: { url, token } });
    if (result?.needsAuth) { await signIn(url, record.label); return; }
    if (!result?.ok) throw Error(result?.error || "Connection failed");
    const next = editingId ? servers.map((item) => (item.id === editingId ? record : item)) : [...servers, record];
    await persist(next);
    editingId = null;
    $("mcp-form").hidden = true;
    status(s.saved, "ok");
  } catch (error) { status(error.message, "error"); }
  finally { $("mcp-save").disabled = false; $("mcp-test").disabled = false; }

}

async function load() {
  const stored = await chrome.storage.local.get([KEY, "sidepanel_language"]);
  lang = stored.sidepanel_language === "zh-CN" ? "zh" : "en";
  servers = Array.isArray(stored[KEY]) ? stored[KEY] : [];
  applyCopy();
  render();
}

$("mcp-add").addEventListener("click", () => openForm(null));
$("mcp-cancel").addEventListener("click", () => {
  editingId = null;
  $("mcp-form").hidden = true;
  status("");
  applyCopy();
});
async function signIn(url, label) {
  const s = t();
  if (!/^https?:\/\//i.test(url || "")) {
    status(s.urlError, "error");
    return;
  }
  $("mcp-signin").disabled = true;
  status(s.signingIn);
  try {
    const start = await chrome.runtime.sendMessage({ type: "KI_MCP", op: "auth-start", server: { url, label } });
    if (!start?.ok) {
      status(start?.error || "Failed", "error");
      return;
    }
    const responseUrl = await chrome.identity.launchWebAuthFlow({ url: start.url, interactive: true });
    const done = await chrome.runtime.sendMessage({ type: "KI_MCP", op: "auth-finish", state: start.state, responseUrl, server: { url, label } });
    if (!done?.ok) {
      status(done?.error || "Failed", "error");
      return;
    }
    const stored = await chrome.storage.local.get(KEY);
    servers = Array.isArray(stored[KEY]) ? stored[KEY] : [];
    $("mcp-form").hidden = true;
    editingId = null;
    render();
    status(s.signedIn, "ok");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    status(/cancel|closed|did not approve/i.test(message) ? s.cancelled : message, "error");
  } finally {
    $("mcp-signin").disabled = false;
  }
}

$("mcp-test").addEventListener("click", () => testServer());
$("mcp-signin").addEventListener("click", () => signIn($("mcp-url").value.trim(), $("mcp-name").value.trim()));
$("mcp-form").addEventListener("submit", save);
await load();
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes[KEY]) { servers = changes[KEY].newValue || []; render(); }
});

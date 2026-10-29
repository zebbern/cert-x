import {
  PRESETS,
  hostForStorage,
  modelsUrl,
  normalizeDiscoveredModels,
  parseModelIds,
  presetById,
  validateDraft,
} from "./providers-catalog.js";

const STORAGE_KEY = "sidepanel_connections";
const ROW_ICON = `<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M16.5 7.5h-9v9h9v-9Z"/><path fill-rule="evenodd" d="M8.25 2.25A.75.75 0 0 1 9 3v.75h2.25V3a.75.75 0 0 1 1.5 0v.75H15V3a.75.75 0 0 1 1.5 0v.75h.75a3 3 0 0 1 3 3v.75H21A.75.75 0 0 1 21 9h-.75v2.25H21a.75.75 0 0 1 0 1.5h-.75V15H21a.75.75 0 0 1 0 1.5h-.75v.75a3 3 0 0 1-3 3h-.75V21a.75.75 0 0 1-1.5 0v-.75h-2.25V21a.75.75 0 0 1-1.5 0v-.75H9V21a.75.75 0 0 1-1.5 0v-.75h-.75a3 3 0 0 1-3-3v-.75H3A.75.75 0 0 1 3 15h.75v-2.25H3a.75.75 0 0 1 0-1.5h.75V9H3a.75.75 0 0 1 0-1.5h.75v-.75a3 3 0 0 1 3-3h.75V3a.75.75 0 0 1 .75-.75ZM6 6.75A.75.75 0 0 1 6.75 6h10.5a.75.75 0 0 1 .75.75v10.5a.75.75 0 0 1-.75.75H6.75a.75.75 0 0 1-.75-.75V6.75Z" clip-rule="evenodd"/></svg>`;

const copy = {
  en: {
    title: "Your models",
    intro: "Connect a provider, then choose its model in chat.",
    saved: "Saved providers",
    add: "Add a provider",
    edit: "Edit",
    remove: "Remove",
    confirmRemove: "Remove this provider?",
    yes: "Remove",
    no: "Keep",
    empty: "No providers yet. Add one, then pick its model from the menu in the side panel.",
    formAdd: "Add a provider",
    formEdit: "Edit provider",
    preset: "Provider",
    name: "Name",
    host: "Base URL",
    key: "API key",
    models: "Model ids",
    modelsHint: "Optional. One id per line. Leave this empty to show up to 40 models from the provider. Fill it in to show only those.",
    save: "Save",
    saving: "Save",
    test: "Test connection",
    testing: "Test connection",
    cancel: "Cancel",
    show: "Show",
    hide: "Hide",
    keySaved: "A key is already saved. Leave this blank to keep it.",
    savedOk: "Saved. Close this tab and choose the model in the side panel.",
    testOk: "Connected.",
    use: "Use",
    noModels: "Connected, but no chat models came back. Open More and type a model id.",
    more: "More",
    less: "Less",
    ready: "Ready in the model menu",
    summaries: {
      anthropic: "Anthropic messages API",
      openai: "Chat and Codex models",
      openrouter: "One key for many models",
      kimi: "Moonshot chat models",
      deepseek: "DeepSeek chat models",
      groq: "Fast hosted models",
      mistral: "Mistral chat models",
      gemini: "Google AI Studio",
      local: "Ollama or LM Studio",
      custom: "Any OpenAI-style server",
      "anthropic-custom": "Any Claude-style server",
    },
    hostOpenAI: "OpenAI-compatible URLs usually end in /v1.",
    presetError: "Choose a provider.",
    hostError: "Enter the base URL.",
    hostScheme: "The URL needs to start with http:// or https://.",
    keyError: "Enter an API key.",
    none: "No key",
    modelsCount: (n) => (n === 1 ? "1 pinned model" : `${n} pinned models`),
    auto: "Models loaded from the provider",
  },
  zh: {
    title: "你的模型",
    intro: "连接提供方，然后在聊天中选择模型。",
    saved: "已保存的提供方",
    add: "添加提供方",
    edit: "编辑",
    remove: "移除",
    confirmRemove: "移除这个提供方？",
    yes: "移除",
    no: "保留",
    empty: "还没有提供方。添加后，在侧边栏的模型菜单里选择它。",
    formAdd: "添加提供方",
    formEdit: "编辑提供方",
    preset: "提供方",
    name: "名称",
    host: "服务地址",
    key: "API key",
    models: "模型 id",
    modelsHint: "可选。每行一个 id。留空则显示提供方返回的最多 40 个模型。填写后只显示这些。",
    save: "保存",
    saving: "保存",
    test: "测试连接",
    testing: "测试连接",
    cancel: "取消",
    show: "显示",
    hide: "隐藏",
    keySaved: "已保存密钥。留空表示继续使用它。",
    savedOk: "已保存。关掉这个标签页，然后在侧边栏的模型菜单里选择。",
    testOk: "已连上。",
    use: "使用",
    noModels: "已连上，但没有返回可用的对话模型。打开“更多”后填写模型 id。",
    more: "更多",
    less: "收起",
    ready: "可在模型菜单里选用",
    summaries: {
      anthropic: "Anthropic 消息接口",
      openai: "对话和 Codex 模型",
      openrouter: "一个密钥，多个模型",
      kimi: "Moonshot 对话模型",
      deepseek: "DeepSeek 对话模型",
      groq: "高速托管模型",
      mistral: "Mistral 对话模型",
      gemini: "Google AI Studio",
      local: "本机 Ollama 或 LM Studio",
      custom: "任意 OpenAI 兼容服务",
      "anthropic-custom": "任意 Claude 兼容服务",
    },
    hostOpenAI: "兼容 OpenAI 的地址通常以 /v1 结尾。",
    presetError: "请选择提供方。",
    hostError: "请填写服务地址。",
    hostScheme: "地址需要以 http:// 或 https:// 开头。",
    keyError: "请填写 API key。",
    none: "无密钥",
    modelsCount: (n) => (n === 1 ? "已固定 1 个模型" : `已固定 ${n} 个模型`),
    auto: "从提供方读取模型",
  },
};

const $ = (id) => document.getElementById(id);

let language = "en";
let raw = [];
let editingId = null;
let justSavedId = null;
let busy = false;
const CHECK_ICON = `<svg width="12" height="12" viewBox="0 0 14 14" fill="none" aria-hidden="true"><path d="M2.5 7.5 5.5 10.5 11.5 3.5" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"></path></svg>`;

function t() {
  return copy[language] ?? copy.en;
}

function text(id, value) {
  const node = $(id);
  if (node) node.textContent = value;
}

function applyCopy() {
  const strings = t();
  document.documentElement.lang = language === "zh" ? "zh-CN" : "en";
  document.title = strings.title;
  text("title", strings.title);
  text("intro", strings.intro);
  text("saved-heading", strings.saved);
  text("add", strings.add);
  text("form-title", editingId ? strings.formEdit : strings.formAdd);
  text("label-preset", strings.preset);
  text("label-name", strings.name);
  text("label-host", strings.host);
  text("label-key", strings.key);
  text("label-models", strings.models);
  text("models-hint", strings.modelsHint);
  text("more", $("more-fields").hidden ? strings.more : strings.less);
  text("save", busy ? strings.saving : strings.save);
  text("test", busy ? strings.testing : strings.test);
  text("cancel", strings.cancel);
  text("toggle-key", $("key").type === "password" ? strings.show : strings.hide);
}

function presetOptions() {
  const select = $("preset");
  const current = select.value;
  select.replaceChildren();
  for (const preset of PRESETS) {
    const option = document.createElement("option");
    option.value = preset.id;
    option.textContent = preset.label;
    select.append(option);
  }
  if (PRESETS.some((preset) => preset.id === current)) select.value = current;
  syncPicker();
}

function syncPicker() {
  const select = $("preset");
  const menu = $("preset-menu");
  const button = $("preset-button");
  if (!select || !menu || !button) return;
  const selected = select.options[select.selectedIndex];
  $("preset-value").textContent = selected ? selected.textContent : "";
  menu.replaceChildren();
  for (const option of select.options) {
    const item = document.createElement("li");
    item.setAttribute("role", "option");
    item.id = `preset-opt-${option.value}`;
    item.dataset.value = option.value;
    const copyWrap = document.createElement("span");
    copyWrap.className = "picker-copy";
    const name = document.createElement("span");
    name.className = "picker-name";
    name.textContent = option.textContent;
    const sub = document.createElement("span");
    sub.className = "picker-sub";
    sub.textContent = t().summaries[option.value] || "";
    copyWrap.append(name, sub);
    const mark = document.createElement("span");
    mark.className = "picker-check";
    mark.innerHTML = CHECK_ICON;
    item.append(copyWrap, mark);
    const on = option.value === select.value;
    item.setAttribute("aria-selected", on ? "true" : "false");
    if (on) item.className = "is-selected";
    menu.append(item);
  }
  const currentItem = menu.querySelector(".is-selected");
  if (currentItem) button.setAttribute("aria-activedescendant", currentItem.id);
  else button.removeAttribute("aria-activedescendant");
}

function pickerOpen() {
  return !$("preset-menu").hidden;
}

function openPicker() {
  $("preset-menu").hidden = false;
  $("preset-button").setAttribute("aria-expanded", "true");
  $("preset-menu").querySelector(".is-selected")?.scrollIntoView({ block: "nearest" });
}

function closePicker() {
  $("preset-menu").hidden = true;
  $("preset-button").setAttribute("aria-expanded", "false");
}

function movePicker(delta) {
  const select = $("preset");
  const next = select.selectedIndex + delta;
  if (next < 0 || next >= select.options.length) return;
  select.selectedIndex = next;
  select.dispatchEvent(new Event("change", { bubbles: true }));
  $("preset-menu").querySelector(".is-selected")?.scrollIntoView({ block: "nearest" });
}

function selectedPreset() {
  return presetById($("preset").value);
}

function setHint(id, value) {
  const node = $(id);
  node.textContent = value || "";
  node.hidden = !value;
}

function setMore(open) {
  $("more-fields").hidden = !open;
  $("more").setAttribute("aria-expanded", open ? "true" : "false");
  $("more").textContent = open ? t().less : t().more;
}

function fillPresetHints() {
  const preset = selectedPreset();
  if (!preset) return;
  $("host").placeholder = preset.hostHint || preset.defaultHost;
  if (!$("host").value.trim() && !editingId) $("host").value = preset.defaultHost;
  const strings = t();
  setHint("host-hint", preset.route === "chat-completions" ? strings.hostOpenAI : "");
  const savedKey = editingId && raw.find((item) => item.id === editingId)?.apiKey;
  setHint("key-hint", savedKey ? strings.keySaved : preset.keyHint || (preset.keyOptional ? strings.none : ""));
}

function maskKey(key) {
  if (!key) return t().none;
  if (key.length <= 4) return "••••";
  return `••••${key.slice(-4)}`;
}

function renderList() {
  const strings = t();
  const list = $("list");
  const visible = raw.filter((item) => presetById(item.presetId));
  list.replaceChildren();
  if (visible.length === 0) {
    const empty = document.createElement("p");
    empty.className = "empty";
    empty.textContent = strings.empty;
    list.append(empty);
    return;
  }
  for (const item of visible) {
    const preset = presetById(item.presetId);
    const row = document.createElement("div");
    row.className = "row";
    const info = document.createElement("div");
    const title = document.createElement("h3");
    title.textContent = item.label || preset.label;
    const meta = document.createElement("p");
    meta.className = "meta";
    meta.textContent = item.hostOverride || preset.defaultHost || "—";
    info.append(title, meta);
    const icon = document.createElement("span");
    icon.className = "row-icon";
    icon.setAttribute("aria-hidden", "true");
    icon.innerHTML = ROW_ICON;
    const main = document.createElement("div");
    main.className = "row-main";
    main.append(icon, info);
    const actions = document.createElement("div");
    actions.className = "actions";
    const pill = document.createElement("span");
    pill.className = "key-pill";
    pill.textContent = maskKey(item.apiKey);
    actions.append(pill);
    const edit = document.createElement("button");
    edit.type = "button";
    edit.textContent = strings.edit;
    edit.addEventListener("click", () => startEdit(item.id));
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "danger";
    remove.textContent = strings.remove;
    remove.addEventListener("click", () => confirmRemove(item.id, actions, remove));
    actions.append(edit, remove);
    row.append(main, actions);
    if (item.id === justSavedId) {
      const wrap = document.createElement("div");
      wrap.className = "saved-item";
      const ready = document.createElement("p");
      ready.className = "ready";
      ready.textContent = strings.ready;
      wrap.append(row, ready);
      list.append(wrap);
    } else {
      list.append(row);
    }
  }
}

function confirmRemove(id, actions, button) {
  const strings = t();
  button.hidden = true;
  const ask = document.createElement("span");
  ask.className = "hint";
  ask.textContent = strings.confirmRemove;
  const yes = document.createElement("button");
  yes.type = "button";
  yes.className = "danger";
  yes.textContent = strings.yes;
  yes.addEventListener("click", () => removeConnection(id));
  const no = document.createElement("button");
  no.type = "button";
  no.textContent = strings.no;
  no.addEventListener("click", () => renderList());
  actions.append(ask, yes, no);
  yes.focus();
}

function applyTheme(theme) {
  const dark = theme === "dark" || (theme !== "light" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.dataset.theme = dark ? "dark" : "light";
}

const pageParams = new URLSearchParams(location.search);
if (pageParams.get("embed") === "1") document.body.classList.add("embed");
applyTheme(pageParams.get("theme") || "system");

async function load() {
  const stored = globalThis.chrome?.storage?.local
    ? await chrome.storage.local.get([STORAGE_KEY, "sidepanel_language", "sidepanel_theme"])
    : {};
  if (!pageParams.get("theme")) applyTheme(stored.sidepanel_theme);
  language = stored.sidepanel_language === "zh-CN" ? "zh" : "en";
  raw = Array.isArray(stored[STORAGE_KEY]) ? stored[STORAGE_KEY] : [];
  applyCopy();
  presetOptions();
  fillPresetHints();
  renderList();
}

function showEditor(show) {
  $("editor").hidden = !show;
  document.body.classList.toggle("editing", show);
  closePicker();
  if (window.parent !== window) {
    window.parent.postMessage({ type: "providers-editing", editing: show }, "*");
  }
  if (show) $("editor").scrollIntoView({ block: "nearest" });
}

function clearErrors() {
  for (const id of ["host-error", "key-error"]) {
    const node = $(id);
    node.hidden = true;
    node.textContent = "";
  }
  $("host").removeAttribute("aria-invalid");
  $("key").removeAttribute("aria-invalid");
  $("test-panel").hidden = true;
  $("status").hidden = true;
  $("results").hidden = true;
  $("results").replaceChildren();
}

function startAdd() {
  editingId = null;
  $("form").reset();
  $("preset").value = PRESETS[0].id;
  $("host").value = PRESETS[0].defaultHost;
  clearErrors();
  applyCopy();
  fillPresetHints();
  setMore(false);
  showEditor(true);
  syncPicker();
  $("preset-button").focus();
}

function startEdit(id) {
  const item = raw.find((entry) => entry.id === id);
  const preset = item && presetById(item.presetId);
  if (!item || !preset) return;
  editingId = id;
  clearErrors();
  $("preset").value = preset.id;
  $("name").value = item.label || "";
  $("host").value = item.hostOverride || preset.defaultHost;
  $("key").value = "";
  $("models").value = Array.isArray(item.modelIds) ? item.modelIds.join("\n") : "";
  applyCopy();
  fillPresetHints();
  syncPicker();
  setMore(Boolean($("name").value.trim() || $("models").value.trim()));
  showEditor(true);
  ($("more-fields").hidden ? $("preset-button") : $("name")).focus();
}

function draftFromForm() {
  const item = editingId ? raw.find((entry) => entry.id === editingId) : null;
  return {
    presetId: $("preset").value,
    host: $("host").value,
    apiKey: $("key").value,
    keepSavedKey: Boolean(editingId && item?.apiKey && !$("key").value.trim()),
  };
}

function showFieldErrors(errors) {
  const strings = t();
  const map = {
    presetId: ["preset", strings.presetError],
    host: ["host-error", errors.host === "Enter the base URL." ? strings.hostError : errors.host === "The URL needs to start with http:// or https://." ? strings.hostScheme : errors.host],
    apiKey: ["key-error", strings.keyError],
  };
  let first = null;
  if (errors.host) {
    $("host-error").hidden = false;
    $("host-error").textContent = map.host[1];
    $("host").setAttribute("aria-invalid", "true");
    $("host").setAttribute("aria-describedby", "host-hint host-error");
    first = $("host");
  }
  if (errors.apiKey) {
    $("key-error").hidden = false;
    $("key-error").textContent = strings.keyError;
    $("key").setAttribute("aria-invalid", "true");
    first ??= $("key");
  }
  first?.focus();
}

function setStatus(message, kind) {
  $("test-panel").hidden = false;
  const status = $("status");
  status.hidden = false;
  status.className = `status ${kind || ""}`;
  status.textContent = message;
}

function currentRecord(apiKey) {
  const preset = selectedPreset();
  const label = $("name").value.trim() || preset.storageLabel;
  const host = hostForStorage(preset, $("host").value);
  const modelIds = parseModelIds($("models").value);
  return {
    id: editingId || `byok-${crypto.randomUUID()}`,
    label,
    presetId: preset.id,
    apiKey,
    ...(host ? { hostOverride: host } : {}),
    ...(modelIds.length ? { modelIds } : {}),
  };
}

async function persist(next) {
  await chrome.storage.local.set({ [STORAGE_KEY]: next });
  raw = next;
  renderList();
}

async function removeConnection(id) {
  await persist(raw.filter((item) => item.id !== id));
  if (editingId === id) {
    editingId = null;
    showEditor(false);
  }
}

function resolvedKey() {
  const typed = $("key").value.trim();
  if (typed) return typed;
  if (!editingId) return "";
  return raw.find((item) => item.id === editingId)?.apiKey || "";
}

async function onTest() {
  clearErrors();
  const errors = validateDraft(draftFromForm());
  if (Object.keys(errors).length) {
    showFieldErrors(errors);
    return;
  }
  const preset = selectedPreset();
  const url = modelsUrl(preset, $("host").value);
  const key = resolvedKey();
  const headers = {};
  if (preset.discovery === "anthropic-models") {
    headers["anthropic-version"] = "2023-06-01";
    if (key) headers["x-api-key"] = key;
  } else if (key) {
    headers.Authorization = `Bearer ${key}`;
  }
  busy = true;
  applyCopy();
  $("save").disabled = true;
  $("test").disabled = true;
  try {
    const response = await fetch(url, { headers });
    const bodyText = await response.text();
    let payload = {};
    try { payload = JSON.parse(bodyText); } catch { payload = {}; }
    if (!response.ok) {
      const detail = String(payload?.error?.message || payload?.message || bodyText || response.status).replaceAll(key, "••••").slice(0, 240);
      setStatus(`${response.status}: ${detail}`, "bad");
      return;
    }
    const models = normalizeDiscoveredModels(payload, preset, $("name").value.trim() || preset.storageLabel, []);
    setStatus(models.length ? t().testOk : t().noModels, models.length ? "ok" : "bad");
    if (!models.length) setMore(true);
    const results = $("results");
    results.hidden = models.length === 0;
    results.replaceChildren();
    for (const model of models) {
      const item = document.createElement("li");
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = `${t().use} ${model.modelId}`;
      button.addEventListener("click", () => {
        setMore(true);
        const ids = parseModelIds(`${$("models").value}\n${model.modelId}`);
        $("models").value = ids.join("\n");
        $("models").focus();
      });
      item.append(button);
      results.append(item);
    }
  } catch (error) {
    setStatus(error instanceof Error ? error.message : String(error), "bad");
  } finally {
    busy = false;
    $("save").disabled = false;
    $("test").disabled = false;
    applyCopy();
  }
}

async function onSave(event) {
  event.preventDefault();
  clearErrors();
  const errors = validateDraft(draftFromForm());
  if (Object.keys(errors).length) {
    showFieldErrors(errors);
    return;
  }
  const key = resolvedKey();
  const record = currentRecord(key);
  justSavedId = record.id;
  await persist([...raw.filter((item) => item.id !== record.id), record]);
  editingId = null;
  showEditor(false);
  clearErrors();
  $("saved-heading").tabIndex = -1;
  $("saved-heading").focus();
}

function onCancel() {
  editingId = null;
  showEditor(false);
  clearErrors();
}

$("more").addEventListener("click", () => setMore($("more-fields").hidden));
$("add").addEventListener("click", startAdd);
$("cancel").addEventListener("click", onCancel);
$("test").addEventListener("click", () => void onTest());
$("form").addEventListener("submit", (event) => void onSave(event));
$("preset").addEventListener("change", () => {
  const preset = selectedPreset();
  if (preset && !editingId) $("host").value = preset.defaultHost;
  fillPresetHints();
  syncPicker();
});
$("preset-button").addEventListener("click", () => {
  if (pickerOpen()) closePicker();
  else openPicker();
});
$("preset-button").addEventListener("keydown", (event) => {
  if (event.key === "ArrowDown" || event.key === "ArrowUp") {
    event.preventDefault();
    if (!pickerOpen()) openPicker();
    movePicker(event.key === "ArrowDown" ? 1 : -1);
  } else if (event.key === "Escape") {
    closePicker();
  } else if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    if (pickerOpen()) closePicker();
    else openPicker();
  }
});
$("preset-menu").addEventListener("click", (event) => {
  const item = event.target.closest("[data-value]");
  if (!item) return;
  $("preset").value = item.dataset.value;
  $("preset").dispatchEvent(new Event("change", { bubbles: true }));
  closePicker();
  $("preset-button").focus();
});
document.addEventListener("click", (event) => {
  if (!pickerOpen()) return;
  if ($("preset-picker").contains(event.target)) return;
  closePicker();
});
$("toggle-key").addEventListener("click", () => {
  $("key").type = $("key").type === "password" ? "text" : "password";
  applyCopy();
  $("key").focus();
});
window.addEventListener("message", (event) => {
  if (event.source !== window.parent) return;
  if (!event.data || event.data.type !== "providers-add") return;
  startAdd();
});
$("models").addEventListener("keydown", (event) => {
  if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) {
    event.preventDefault();
    $("form").requestSubmit();
  }
});

await load();

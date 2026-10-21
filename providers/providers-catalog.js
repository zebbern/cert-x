export const PRESETS = [
  {
    id: "anthropic",
    label: "Claude",
    storageLabel: "Claude",
    defaultHost: "https://api.anthropic.com",
    discovery: "anthropic-models",
    route: "messages",
    keyOptional: false,
    hostHint: "https://api.anthropic.com",
    keyHint: "Anthropic console API key. A claude.ai login is not a key.",
  },
  {
    id: "openai",
    label: "OpenAI / Codex",
    storageLabel: "OpenAI / Codex",
    defaultHost: "https://api.openai.com/v1",
    discovery: "openai-models",
    route: "chat-completions",
    keyOptional: false,
    hostHint: "https://api.openai.com/v1",
    keyHint: "OpenAI API key. Codex models show up when this key can use them. A ChatGPT login is not a key.",
  },
  {
    id: "openrouter",
    label: "OpenRouter",
    storageLabel: "OpenRouter",
    defaultHost: "https://openrouter.ai/api/v1",
    discovery: "openai-models",
    route: "chat-completions",
    keyOptional: false,
    hostHint: "https://openrouter.ai/api/v1",
    keyHint: "One OpenRouter key can reach Claude, OpenAI, Kimi, and other models.",
  },
  {
    id: "kimi",
    label: "Kimi",
    storageLabel: "Kimi",
    defaultHost: "https://api.moonshot.ai/v1",
    discovery: "openai-models",
    route: "chat-completions",
    keyOptional: false,
    hostHint: "https://api.moonshot.cn/v1",
    keyHint: "Moonshot API key. Use api.moonshot.cn if your account is on the China endpoint.",
  },
  {
    id: "deepseek",
    label: "DeepSeek",
    storageLabel: "DeepSeek",
    defaultHost: "https://api.deepseek.com/v1",
    discovery: "openai-models",
    route: "chat-completions",
    keyOptional: false,
    hostHint: "https://api.deepseek.com/v1",
    keyHint: "DeepSeek API key.",
  },
  {
    id: "groq",
    label: "Groq",
    storageLabel: "Groq",
    defaultHost: "https://api.groq.com/openai/v1",
    discovery: "openai-models",
    route: "chat-completions",
    keyOptional: false,
    hostHint: "https://api.groq.com/openai/v1",
    keyHint: "Groq API key.",
  },
  {
    id: "mistral",
    label: "Mistral",
    storageLabel: "Mistral",
    defaultHost: "https://api.mistral.ai/v1",
    discovery: "openai-models",
    route: "chat-completions",
    keyOptional: false,
    hostHint: "https://api.mistral.ai/v1",
    keyHint: "Mistral API key.",
  },
  {
    id: "gemini",
    label: "Gemini",
    storageLabel: "Gemini",
    defaultHost: "https://generativelanguage.googleapis.com/v1beta/openai",
    discovery: "openai-models",
    route: "chat-completions",
    keyOptional: false,
    hostHint: "https://generativelanguage.googleapis.com/v1beta/openai",
    keyHint: "Google AI Studio API key.",
  },
  {
    id: "local",
    label: "Local server",
    storageLabel: "Local server",
    defaultHost: "http://127.0.0.1:11434/v1",
    discovery: "openai-models",
    route: "chat-completions",
    keyOptional: true,
    hostHint: "http://127.0.0.1:1234/v1",
    keyHint: "Leave blank for Ollama. Ollama uses port 11434. LM Studio is usually 1234.",
  },
  {
    id: "custom",
    label: "Other OpenAI-compatible",
    storageLabel: "Other OpenAI-compatible",
    defaultHost: "",
    discovery: "openai-models",
    route: "chat-completions",
    keyOptional: true,
    hostHint: "https://zebbern.com/v1",
    keyHint: "Optional. Any server that speaks the OpenAI chat API.",
  },
  {
    id: "anthropic-custom",
    label: "Other Claude-compatible",
    storageLabel: "Other Claude-compatible",
    defaultHost: "",
    discovery: "anthropic-models",
    route: "messages",
    keyOptional: true,
    hostHint: "http://127.0.0.1:4000",
    keyHint: "Optional. Host should be the server root, without /v1.",
  },
];

const NOISE = /embed|whisper|tts|dall-e|moderation|transcri|realtime|sora|babbage|davinci|image-generation/i;

export function presetById(id) {
  return PRESETS.find((preset) => preset.id === id) ?? null;
}

export function baseHost(preset, host) {
  let value = (host || preset.defaultHost || "").trim().replace(/\/+$/, "");
  if (preset.route === "messages" && value.endsWith("/v1")) value = value.slice(0, -3);
  return value;
}

export function modelsUrl(preset, host) {
  const base = baseHost(preset, host);
  if (!base) return "";
  if (preset.discovery === "anthropic-models") return `${base}/v1/models`;
  return `${base}/models`;
}

export function hostForStorage(preset, host) {
  const value = baseHost(preset, host);
  if (!value || value === preset.defaultHost.replace(/\/+$/, "")) return undefined;
  return value;
}

export function parseModelIds(text) {
  const ids = [];
  for (const part of String(text ?? "").split(/[\s,]+/)) {
    const id = part.trim();
    if (!id || ids.includes(id) || ids.length >= 40) continue;
    ids.push(id);
  }
  return ids;
}

export function isNoisyModel(id) {
  return NOISE.test(id);
}

export function normalizeDiscoveredModels(payload, preset, connectionLabel, pinnedIds) {
  const rows = Array.isArray(payload?.data) ? payload.data : Array.isArray(payload?.models) ? payload.models : [];
  const found = [];
  for (const item of rows) {
    const id = typeof item === "string" ? item : item?.id || item?.name;
    if (typeof id !== "string" || !id || isNoisyModel(id)) continue;
    const rawName = typeof item === "object" && item
      ? (typeof item.display_name === "string" && item.display_name) || (typeof item.name === "string" && item.name !== id ? item.name : "")
      : "";
    const context = typeof item === "object" && item && typeof item.context_length === "number" && item.context_length > 0
      ? Math.floor(item.context_length)
      : undefined;
    found.push({ modelId: id, name: rawName || id, maxContextTokens: context });
    if (found.length >= 40) break;
  }
  const byId = new Map(found.map((model) => [model.modelId, model]));
  const pinned = pinnedIds.filter((id) => id);
  if (pinned.length > 0) {
    return pinned.map((id) => {
      const match = byId.get(id);
      return {
        modelId: id,
        label: `${connectionLabel} · ${match?.name || id}`,
        route: preset.route,
        ...(match?.maxContextTokens ? { maxContextTokens: match.maxContextTokens } : {}),
      };
    });
  }
  return found.map((model) => ({
    modelId: model.modelId,
    label: `${connectionLabel} · ${model.name}`,
    route: preset.route,
    ...(model.maxContextTokens ? { maxContextTokens: model.maxContextTokens } : {}),
  }));
}

export function validateDraft(draft) {
  const errors = {};
  const preset = presetById(draft.presetId);
  if (!preset) errors.presetId = "Choose a provider.";
  const host = preset ? baseHost(preset, draft.host) : "";
  if (preset && !host) errors.host = "Enter the base URL.";
  else if (preset && host && !/^https?:\/\//i.test(host)) errors.host = "The URL needs to start with http:// or https://.";
  const key = (draft.apiKey ?? "").trim();
  if (preset && !preset.keyOptional && !key && !draft.keepSavedKey) errors.apiKey = "Enter an API key.";
  return errors;
}

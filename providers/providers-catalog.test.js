import assert from "node:assert/strict";
import {
  baseHost,
  hostForStorage,
  modelsUrl,
  normalizeDiscoveredModels,
  parseModelIds,
  validateDraft,
} from "./providers-catalog.js";

const claude = { id: "anthropic", route: "messages", discovery: "anthropic-models", defaultHost: "https://api.anthropic.com", keyOptional: false };
const openai = { id: "openai", route: "chat-completions", discovery: "openai-models", defaultHost: "https://api.openai.com/v1", keyOptional: false };
const local = { id: "local", route: "chat-completions", discovery: "openai-models", defaultHost: "http://127.0.0.1:11434/v1", keyOptional: true };

assert.equal(baseHost(claude, "https://api.anthropic.com/v1/"), "https://api.anthropic.com");
assert.equal(modelsUrl(claude, "https://api.anthropic.com"), "https://api.anthropic.com/v1/models");
assert.equal(modelsUrl(openai, "https://api.openai.com/v1"), "https://api.openai.com/v1/models");
assert.equal(modelsUrl(local, ""), "http://127.0.0.1:11434/v1/models");
assert.equal(hostForStorage(openai, "https://api.openai.com/v1"), undefined);
assert.equal(hostForStorage(local, "http://127.0.0.1:1234/v1"), "http://127.0.0.1:1234/v1");

assert.deepEqual(parseModelIds(" a \n a, b "), ["a", "b"]);

const noisy = normalizeDiscoveredModels({
  data: [
    { id: "whisper-1" },
    { id: "gpt-4.1", context_length: 128000 },
    { id: "text-embedding-3-small" },
  ],
}, openai, "Work", []);
assert.deepEqual(noisy.map((model) => model.modelId), ["gpt-4.1"]);
assert.equal(noisy[0].label, "Work · gpt-4.1");
assert.equal(noisy[0].route, "chat-completions");

const pinned = normalizeDiscoveredModels({
  data: [{ id: "claude-sonnet", display_name: "Sonnet" }, { id: "claude-haiku" }],
}, claude, "Claude", ["claude-haiku", "missing"]);
assert.deepEqual(pinned.map((model) => model.modelId), ["claude-haiku", "missing"]);
assert.equal(pinned[0].label, "Claude · claude-haiku");

assert.deepEqual(validateDraft({ presetId: "local", host: "http://127.0.0.1:11434/v1", apiKey: "", keepSavedKey: false }), {});
assert.ok(validateDraft({ presetId: "openai", host: "https://api.openai.com/v1", apiKey: "  ", keepSavedKey: false }).apiKey);
assert.ok(validateDraft({ presetId: "custom", host: "ftp://zebbern.com", apiKey: "", keepSavedKey: false }).host);

console.log("providers-catalog ok");

const test = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
test("model inheritance uses app default instead of stale per-chat automatic pins", async () => {
  let preference = null;
  const scope = vm.createContext({ chrome: { runtime: { sendMessage: async () => ({ ok: true, result: { model: preference } }) } },
    AA: async () => ({ connectionId: "mock", modelId: "current-default" }), VA: async () => ({}), Aj: () => undefined, Mj: async model => model,
    Hj: () => { throw Error("Must not consult stale session pins when inheriting."); } });
  vm.runInContext(fs.readFileSync(path.join(__dirname, "../src/ki-context-ui.js"), "utf8"), scope);
  const models = [{ connectionId: "mock", modelId: "old-chat-model" }, { connectionId: "mock", modelId: "current-default" }];
  assert.equal((await scope.KiResolveChatModel("chat", models)).modelId, "current-default");
  preference = { connectionId: "mock", modelId: "old-chat-model" };
  assert.equal((await scope.KiResolveChatModel("chat", models)).modelId, "old-chat-model");
  preference = { connectionId: "mock", modelId: "missing" };
  assert.equal(await scope.KiResolveChatModel("chat", models), null, "Missing explicit/preferred models must not silently fall back");
});
test("workspace chats survive history retention without evicting unrelated user history", async () => {
  const source = fs.readFileSync(path.join(__dirname, "../../../background/background.js"), "utf8");
  const start = source.indexOf("async function Vk(e,t){"), end = source.indexOf("async function Hk(e,t){", start);
  assert.ok(start > 0 && end > start);
  const records = Array.from({ length: 15 }, (_, i) => ({ chatId: "project-" + i, user: "me", lastActiveAt: i }));
  const chats = Object.fromEntries(records.map(record => [record.chatId, { workspaceId: "project" }]));
  records.push(...Array.from({ length: 12 }, (_, i) => ({ chatId: "ordinary-" + i, user: "me", lastActiveAt: i + 20 })), { chatId: "other-account", user: "other", lastActiveAt: 1 });
  const deleted = [], scope = vm.createContext({ kiContextLoad: async () => ({ chats }), Ek: async () => records, Pk: record => record.user, xk: async id => deleted.push(id) });
  vm.runInContext(source.slice(start, end), scope);
  await scope.Vk("me", new Set(["ordinary-0"]));
  assert.deepEqual(deleted, ["ordinary-1", "ordinary-2"]);
});

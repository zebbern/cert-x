import { test } from "node:test";
import assert from "node:assert/strict";
import { serverFromForm } from "./local-mcp-config.js";
const form = { command: "node", args: "C:\\folder with spaces\\server.js\n--value=a&b", cwd: "", env: "TOKEN=a=b=c\nNAME= value ", label: "" };
test("local server form preserves argument boundaries and environment values", () => {
  const server = serverFromForm(form);
  assert.deepEqual(server.args, ["C:\\folder with spaces\\server.js", "--value=a&b"]);
  assert.deepEqual(server.env, { TOKEN: "a=b=c", NAME: " value " });
  assert.equal(server.command, "node"); assert.equal(server.label, "node");
  assert.equal(Object.hasOwn(server, "cwd"), false);
});
test("editing preserves existing multiline and empty arguments, environment and extra fields", () => {
  const original = { command: "node", args: ["", "a\nb"], env: { MULTILINE: "a\nb" }, id: "keep", cwd: "C:\\old" };
  const server = serverFromForm({ ...form, args: original.args.join("\n"), env: "MULTILINE=a\nb" }, original);
  assert.deepEqual(server.args, original.args); assert.deepEqual(server.env, original.env);
  assert.equal(server.id, "keep"); assert.equal(Object.hasOwn(server, "cwd"), false);
});
test("invalid command, relative cwd and malformed environment fail before saving", () => {
  assert.throws(() => serverFromForm({ ...form, command: " " }), /command/);
  assert.throws(() => serverFromForm({ ...form, cwd: "relative" }), /absolute/);
  assert.throws(() => serverFromForm({ ...form, env: "not-a-pair" }), /NAME=value/);
});
test('managed credential references survive editing; environment file is explicit and absolute', () => {
  const original = { command: 'node', args: [], id: 'managed-one', secretRef: 'host-secret-one', envFileRef: 'C:\\config\\callbacks.env' };
  const preserved = serverFromForm(form, original); assert.equal(preserved.secretRef, original.secretRef); assert.equal(preserved.envFileRef, original.envFileRef);
  const edited = serverFromForm({ ...form, envFileRef: 'D:\\settings\\callbacks.env' }, original); assert.equal(edited.envFileRef, 'D:\\settings\\callbacks.env'); assert.equal(edited.secretRef, original.secretRef);
  assert.equal(serverFromForm({ ...form, envFileRef: '' }, original).envFileRef, undefined);
  assert.throws(() => serverFromForm({ ...form, envFileRef: 'relative.env' }), /absolute/);
});

// Workspace knowledge graph (ki-graph.js) through the three tools the model
// calls. Storage is an in-memory chrome.storage.local; time is a settable clock.
const test = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), vm = require("node:vm"), { webcrypto } = require("node:crypto");
const code = fs.readFileSync(path.join(__dirname, "../src/ki-graph.js"), "utf8"), plain = value => JSON.parse(JSON.stringify(value));

// owners maps a subagent session to its parent chat; workspaces maps a chat to its workspace id.
function fixture({ owners = {}, workspaces = {} } = {}) {
  const store = {}, f = { now: 1000, failGet: false };
  const owner = session => owners[session] || session;
  f.scope = vm.createContext({ console, crypto: webcrypto, Date: { now: () => f.now },
    chrome: { storage: { local: {
      get: async key => { if (f.failGet) throw Error("storage read failed"); return { [key]: structuredClone(store[key]) }; },
      set: async value => { Object.assign(store, structuredClone(value)); } } } },
    kiWorkspaceOwner: owner,
    kiContextResolve: async session => ({ workspace: workspaces[owner(session)] ? { id: workspaces[owner(session)] } : null }) });
  vm.runInContext(code, f.scope);
  f.call = async (session, name, args) => {
    const tool = f.scope.kiGraphToolDefs(session).find(tool => tool.name === name);
    const { output, isError } = await tool.resolveExecution(args).execute();
    return { isError: Boolean(isError), ...plain(JSON.parse(output)) };
  };
  f.write = (args, session = "chat") => f.call(session, "graph_write", args);
  f.find = (args, session = "chat") => f.call(session, "graph_find", args);
  f.digest = (session = "chat") => f.call(session, "graph_digest", {});
  f.graph = (key = "chat:chat") => plain(store.ki_task_graphs?.[key] || null);
  return f;
}
const ids = result => result.nodes.map(node => node.id).sort();
const hops = result => result.edges.map(edge => edge.from + ">" + edge.to).sort();
const shop = f => f.write({
  nodes: [{ id: "o1", kind: "origin", label: "https://shop.test" }, { id: "r1", kind: "route", label: "/api/Orders" }, { id: "r2", kind: "route", label: "/login" }, { id: "p1", kind: "param", label: "id" }],
  edges: [{ from: "o1", to: "r1", kind: "serves" }, { from: "r1", to: "p1", kind: "has_param" }, { from: "r1", to: "r2", kind: "links_to" }] });

test("nodes and the edges between them land in one call, and the result gives the counts and the ids it made", async () => {
  const f = fixture();
  const out = await f.write({ nodes: [{ id: "o1", kind: "origin", label: "https://shop.test" }, { id: "route:api.orders", kind: "route", label: "/api/orders/{id}" }, { kind: "param", label: "id" }],
    edges: [{ from: "o1", to: "route:api.orders", kind: "serves" }] });
  assert.equal(out.isError, false, out.error);
  assert.deepEqual(out.counts, { nodes: 3, edges: 1, byKind: { origin: 1, route: 1, param: 1 } });
  const { nodes } = await f.find({ kinds: ["param"] });
  assert.match(nodes[0].id, /^param-[0-9a-f]{8}$/);
  assert.deepEqual(out.written, { nodes: 3, edges: 1, generated: [nodes[0].id] }, "the model can link a node it wrote without an id");
});

test("an empty or null id, nodes or edges field means none", async () => {
  const f = fixture();
  const out = await f.write({ nodes: [{ id: "", kind: "param", label: "q" }, { id: null, kind: "param", label: "page" }], edges: null });
  assert.equal(out.isError, false, out.error);
  assert.equal(out.written.generated.length, 2);
});

test("labels are trimmed and kept to 200 characters", async () => {
  const f = fixture();
  await f.write({ nodes: [{ id: "x1", kind: "observation", label: "  " + "a".repeat(300) + "  " }] });
  assert.equal((await f.find({ id: "x1" })).nodes[0].label, "a".repeat(200));
});

test("writing an id again updates that node in place, keeps when it was first seen, and keeps its data unless new data comes", async () => {
  const f = fixture();
  await f.write({ nodes: [{ id: "f1", kind: "finding", label: "IDOR on /api/orders", data: { request: "GET /api/orders/7", victim: "user-b" } }] });
  f.now = 5000;
  assert.equal((await f.write({ nodes: [{ id: "f1", kind: "finding", label: "IDOR on /api/orders (confirmed)" }] })).counts.nodes, 1);
  await f.write({ nodes: [{ id: "f1", kind: "finding", label: "IDOR on /api/orders (confirmed)", data: null }] });
  assert.deepEqual((await f.find({ id: "f1" })).nodes.map(({ label, at, updatedAt, data }) => ({ label, at, updatedAt, data })),
    [{ label: "IDOR on /api/orders (confirmed)", at: 1000, updatedAt: 5000, data: { request: "GET /api/orders/7", victim: "user-b" } }]);
  await f.write({ nodes: [{ id: "f1", kind: "finding", label: "IDOR on /api/orders (confirmed)", data: { severity: "high" } }] });
  assert.deepEqual((await f.find({ id: "f1" })).nodes[0].data, { severity: "high" });
});

test("a subagent writes into its parent chat's graph, and chats in one workspace share theirs", async () => {
  // The failed-subagent result tells the orchestrator that its graph_write calls persist.
  const f = fixture({ owners: { "sub-1": "chat" }, workspaces: { a: "ws-shop", b: "ws-shop" } });
  await f.write({ nodes: [{ id: "r1", kind: "route", label: "/api/cart" }] }, "sub-1");
  assert.deepEqual(ids(await f.find({ kinds: ["route"] }, "chat")), ["r1"]);
  await f.write({ nodes: [{ id: "r2", kind: "route", label: "/checkout" }] }, "a");
  assert.deepEqual(ids(await f.find({ kinds: ["route"] }, "b")), ["r2"]);
  assert.deepEqual(ids(await f.find({ kinds: ["route"] }, "elsewhere")), [], "a chat outside the workspace sees neither");
});

test("graph_write calls made at the same time all persist, across chats too", async () => {
  // Chats run at the same time, and one storage key holds every workspace's graph.
  const f = fixture();
  const results = await Promise.all([["chat", "/a"], ["chat", "/b"], ["other", "/c"]].map(([session, label], i) => f.write({ nodes: [{ id: "r" + i, kind: "route", label }] }, session)));
  assert.ok(results.every(result => !result.isError));
  assert.deepEqual(ids(await f.find({ kinds: ["route"] })), ["r0", "r1"]);
  assert.deepEqual(ids(await f.find({ kinds: ["route"] }, "other")), ["r2"]);
});

test("a failed storage read fails the call as retryable and erases nothing", async () => {
  const f = fixture();
  await f.write({ nodes: [{ id: "r1", kind: "route", label: "/a" }] });
  await f.write({ nodes: [{ id: "r1", kind: "route", label: "/b" }] }, "other");
  f.failGet = true;
  for (const out of [await f.write({ nodes: [{ id: "r2", kind: "route", label: "/c" }] }), await f.find({ kinds: ["route"] }), await f.digest()]) {
    assert.deepEqual([out.isError, out.retryable], [true, true]);
    assert.match(out.recovery, /retry/);
  }
  f.failGet = false;
  assert.deepEqual(ids(await f.find({ kinds: ["route"] })), ["r1"]);
  assert.deepEqual(ids(await f.find({ kinds: ["route"] }, "other")), ["r1"]);
});

test("reset starts this workspace's graph over with whatever came with it, and leaves other graphs alone", async () => {
  const f = fixture();
  await f.write({ nodes: [{ id: "r1", kind: "route", label: "/a" }, { id: "p1", kind: "param", label: "q" }] }, "one");
  await f.write({ nodes: [{ id: "r1", kind: "route", label: "/b" }] }, "two");
  assert.deepEqual((await f.write({ reset: true }, "one")).counts, { nodes: 0, edges: 0, byKind: {} });
  assert.deepEqual((await f.write({ reset: true, nodes: [{ id: "r9", kind: "route", label: "/fresh" }] }, "one")).counts.nodes, 1);
  assert.deepEqual(ids(await f.find({ kinds: ["route"] }, "one")), ["r9"]);
  assert.deepEqual((await f.find({ kinds: ["route"] }, "two")).nodes.map(node => node.label), ["/b"]);
  // An edge to a node the reset clears: the recovery must not send the model back to graph_find.
  const stale = await f.write({ reset: true, edges: [{ from: "r9", to: "r9", kind: "links_to" }] }, "one");
  assert.match(stale.recovery, /reset:true starts from an empty graph/);
});

test("bad input fails with the fix in the error and writes nothing", async () => {
  const f = fixture();
  await f.write({ nodes: [{ id: "r1", kind: "route", label: "/a" }] });
  const before = f.graph();
  const cases = [
    [null, /needs nodes/, /nodes:\[/],
    [{}, /Nothing to write/, /reset:true/],
    [{ nodes: '[{"kind":"route","label":"/b"}]' }, /nodes must be an array/, /JSON array/],
    [{ edges: { from: "r1", to: "r1", kind: "links_to" } }, /edges must be an array/, /JSON array/],
    [{ nodes: [null] }, /must be an object/, /kind is one of/],
    [{ edges: [null] }, /must be an object/, /kind is one of/],
    [{ nodes: [{ kind: "endpoint", label: "/b" }] }, /Unknown node kind "endpoint"/, /route/],
    [{ nodes: [{ kind: "route", label: "  " }] }, /labels are required/, /short label/],
    // Edges only take ids of the kiGraphId shape, so a node must not get another.
    [{ nodes: [{ id: "route:/api/orders", kind: "route", label: "/api/orders" }] }, /id "route:\/api\/orders" is not usable/, /route:api\.orders/],
    [{ nodes: [{ id: 7, kind: "route", label: "/b" }] }, /id 7 is not usable/, /strings/],
    [{ nodes: [{ id: "x".repeat(101), kind: "route", label: "/b" }] }, /is not usable/, /1-100/],
    [{ nodes: [{ id: "__proto__", kind: "route", label: "/b" }] }, /is not usable/, /1-100/],
    [{ nodes: [{ id: "toString", kind: "route", label: "/b" }] }, /is not usable/, /1-100/],
    [{ nodes: [{ kind: "observation", label: "dump", data: { body: "x".repeat(5000) } }] }, /exceeds 4 KiB/, /Outputs/],
    [{ nodes: [{ id: "p1", kind: "param", label: "q" }, { id: "p1", kind: "param", label: "q2" }] }, /Duplicate node id p1/, /one node per id/],
    // A good node next to a bad edge: the node is not saved either.
    [{ nodes: [{ id: "p2", kind: "param", label: "id" }], edges: [{ from: "r1", to: "p2", kind: "contains" }] }, /Unknown edge kind "contains"/, /has_param/],
    [{ nodes: [{ id: "p3", kind: "param", label: "id" }], edges: [{ from: "r1", to: "r9", kind: "has_param" }] }, /"r9" does not exist/, /graph_find/],
    [{ edges: [{ from: "r9", to: "r1", kind: "links_to" }] }, /"r9" does not exist/, /graph_find/],
  ];
  for (const [args, error, recovery] of cases) {
    const out = await f.write(args);
    assert.equal(out.isError, true, JSON.stringify(args));
    assert.match(out.error, error); assert.match(out.recovery, recovery); assert.equal(out.retryable, false);
  }
  assert.deepEqual(f.graph(), before);
});

test("the 500-node bound says how much room is left, counts only new nodes, and still takes updates", async () => {
  const f = fixture();
  const routes = (from, count) => Array.from({ length: count }, (_, i) => ({ id: "r" + (from + i), kind: "route", label: "/page/" + (from + i) }));
  await f.write({ nodes: routes(0, 450) });
  const over = await f.write({ nodes: routes(450, 60) });
  assert.match(over.error, /holds 450 of 500 nodes and this call adds 60 new/);
  assert.match(over.recovery, /at most 50 new nodes.*reset:true/);
  assert.equal((await f.write({ nodes: [...routes(0, 10), ...routes(450, 50)] })).counts.nodes, 500, "updates do not count against the bound");
  const update = await f.write({ nodes: [{ id: "r7", kind: "route", label: "/page/7", data: { status: 403 } }] });
  assert.equal(update.isError, false, update.error);
  assert.deepEqual((await f.find({ id: "r7" })).nodes[0].data, { status: 403 });
  assert.match((await f.write({ nodes: [{ kind: "route", label: "/new" }] })).recovery, /at most 0 new nodes/);
});

test("an edge written again replaces its note instead of adding a copy", async () => {
  const f = fixture();
  await f.write({ nodes: [{ id: "f1", kind: "finding", label: "open redirect" }, { id: "f2", kind: "finding", label: "token leak" }], edges: [{ from: "f1", to: "f2", kind: "enables", note: "first" }] });
  const again = await f.write({ edges: [{ from: "f1", to: "f2", kind: "enables", note: "  redirect leaks the token  " }, { from: "f1", to: "f2", kind: "enables", note: "redirect leaks the token" }] });
  assert.equal(again.counts.edges, 1);
  assert.deepEqual((await f.digest()).chainableFindings, [{ from: "open redirect", to: "token leak", note: "redirect leaks the token" }]);
});

test("edges keep the newest 2000, and an edge written again counts as new", async () => {
  const f = fixture();
  const nodes = Array.from({ length: 45 }, (_, i) => ({ id: "n" + i, kind: "route", label: "/n" + i }));
  const pairs = nodes.flatMap(a => nodes.map(b => ({ from: a.id, to: b.id, kind: "links_to" })));
  assert.equal((await f.write({ nodes, edges: pairs.slice(0, 2001).map((edge, i) => ({ ...edge, note: "e" + i })) })).counts.edges, 2000);
  await f.write({ edges: [{ ...pairs[1], note: "again" }] });
  await f.write({ edges: [{ ...pairs[2001], note: "e2001" }] });
  const notes = f.graph().edges.map(edge => edge.note);
  assert.deepEqual([notes.length, notes[0], notes.at(-2), notes.at(-1)], [2000, "e3", "again", "e2001"]);
});

test("graph_find matches kind, label in any case, or id, and brings the node at the other end of each matching edge", async () => {
  const f = fixture();
  await shop(f);
  // "order" would also match two playbooks, which a find narrowed to graph kinds leaves out.
  const byLabel = await f.find({ kinds: ["route"], label_contains: "order" });
  assert.deepEqual([ids(byLabel), hops(byLabel), byLabel.playbooks], [["o1", "p1", "r1", "r2"], ["o1>r1", "r1>p1", "r1>r2"], undefined]);
  const loose = await f.find({ label_contains: "order", from: "", kinds: [] });
  assert.deepEqual([ids(loose), hops(loose)], [ids(byLabel), hops(byLabel)], "empty from and kinds count as not given");
  // Some providers wrap the arguments in q.
  assert.deepEqual(ids(await f.find({ q: { kinds: ["param"], label_contains: "ID" } })), ["p1", "r1"]);
});

test("a traversal returns the matching edges and the nodes at their ends, and nothing else", async () => {
  const f = fixture();
  await shop(f);
  const out = await f.find({ from: "r1", edge: "has_param" });
  assert.deepEqual([hops(out), ids(out), out.playbooks], [["r1>p1"], ["p1", "r1"], undefined]);
  assert.deepEqual(hops(await f.find({ from: "r1" })), ["r1>p1", "r1>r2"], "from follows outgoing edges only");
  const into = await f.find({ to: "r1" });
  assert.deepEqual([hops(into), ids(into)], [["o1>r1"], ["o1", "r1"]]);
  // kinds narrows the far end, whichever direction the traversal goes.
  assert.deepEqual(hops(await f.find({ from: "r1", kinds: ["param"] })), ["r1>p1"]);
  assert.deepEqual(hops(await f.find({ from: "r1", kinds: ["route"] })), ["r1>r2"]);
  assert.deepEqual(hops(await f.find({ to: "r1", kinds: ["origin"] })), ["o1>r1"]);
  assert.deepEqual(hops(await f.find({ edge: "has_param", kinds: ["route"] })), ["r1>p1"], "an edge kind alone matches either end");
  const serves = await f.find({ edge: "serves" });
  assert.deepEqual([hops(serves), ids(serves), serves.playbooks], [["o1>r1"], ["o1", "r1"], undefined]);
  // An id with only an edge kind is the anchor, in either direction.
  assert.deepEqual(hops(await f.find({ id: "r1", edge: "has_param", kinds: ["param"] })), ["r1>p1"]);
  assert.deepEqual(hops(await f.find({ id: "r1", edge: "serves" })), ["o1>r1"]);
  const one = await f.find({ id: "r2" });
  assert.deepEqual([hops(one), ids(one), one.playbooks], [["r1>r2"], ["r1", "r2"], undefined], "an id lookup brings its neighbours, not the playbooks");
  // The anchor comes back even when no edge matches.
  assert.deepEqual(ids(await f.find({ from: "r2" })), ["r2"]);
  assert.deepEqual(ids(await f.find({ to: "o1" })), ["o1"]);
});

test("what was asked for is never pushed past the limit by its neighbours", async () => {
  const f = fixture();
  await f.write({ nodes: Array.from({ length: 80 }, (_, i) => ({ id: "q" + i, kind: "param", label: "filler" + i })) });
  await f.write({ nodes: [{ id: "hub", kind: "route", label: "/hub" }], edges: Array.from({ length: 80 }, (_, i) => ({ from: "hub", to: "q" + i, kind: "has_param" })) });
  assert.equal((await f.find({ id: "hub" })).nodes[0].id, "hub");
  const out = await f.find({ from: "hub" });
  assert.deepEqual([out.nodes.length, out.nodes[0].id, out.edges.length], [50, "hub", 80]);
  await f.write({ nodes: [{ id: "r1", kind: "route", label: "/api/Orders" }, { id: "p1", kind: "param", label: "id" }], edges: [{ from: "r1", to: "p1", kind: "has_param" }] });
  assert.deepEqual(ids(await f.find({ from: "r1", kinds: ["param"] })), ["p1", "r1"]);
  const g = fixture();
  for (let i = 0; i < 60; i++) await g.write({ nodes: [{ id: "r" + i, kind: "route", label: "/r" + i }, { id: "a" + i, kind: "param", label: "a" + i }, { id: "b" + i, kind: "param", label: "b" + i }],
    edges: [{ from: "r" + i, to: "a" + i, kind: "has_param" }, { from: "r" + i, to: "b" + i, kind: "has_param" }] });
  assert.ok((await g.find({ kinds: ["route"] })).nodes.every(node => node.kind === "route"));
});

test("graph_find resolves a label to its one node, and refuses an unknown or ambiguous reference with the candidates", async () => {
  const f = fixture();
  assert.match((await f.find({ from: "r1" })).recovery, /empty/);
  await shop(f);
  assert.deepEqual(hops(await f.find({ from: "/api/orders" })), ["r1>p1", "r1>r2"], "a path resolves to its route");
  assert.deepEqual(ids(await f.find({ id: "/login" })), ["r1", "r2"]);
  for (const args of [{ from: "nope" }, { to: "nope" }, { id: "nope" }, { id: "toString" }, { from: "pb:file-upload" }]) {
    const out = await f.find(args);
    assert.deepEqual([out.isError, out.retryable], [true, false], JSON.stringify(args));
    assert.match(out.error, /No node/); assert.match(out.recovery, /Recently written ids: .*r1/);
  }
  assert.match((await f.find({ from: "/" })).recovery, /Several nodes match: .*r1.*r2/);
  assert.match((await f.find({ kinds: ["endpoint"] })).recovery, /route/);
  assert.match((await f.find({ edge: "contains" })).recovery, /has_param/);
});

test("playbook seeds come with a search that matches them or with their id", async () => {
  const f = fixture();
  const labels = async args => (await f.find(args)).playbooks.map(playbook => playbook.label);
  assert.deepEqual(await labels({ label_contains: "Avatar" }), ["File upload attacks"]);
  assert.deepEqual(await labels({ label_contains: "SQL" }), ["SQL injection"]);
  assert.deepEqual(await labels({ kinds: ["playbook"], label_contains: "jwt" }), ["Authentication and session"]);
  assert.deepEqual(await labels({ id: "pb:agentic-ai" }), ["Agentic AI and LLM attacks"]);
});

test("lists are bounded: graph_find gives 50 nodes by default and 100 at most, the digest 10 per list", async () => {
  const f = fixture();
  await f.write({ nodes: Array.from({ length: 120 }, (_, i) => ({ id: "p" + i, kind: "param", label: "p" + i })) });
  assert.equal((await f.find({ kinds: ["param"] })).nodes.length, 50);
  assert.equal((await f.find({ kinds: ["param"], limit: 0 })).nodes.length, 50);
  assert.equal((await f.find({ kinds: ["param"], limit: 500 })).nodes.length, 100);
  await f.write({ nodes: Array.from({ length: 12 }, (_, i) => ({ id: "r" + i, kind: "route", label: "/r" + i })) });
  const digest = await f.digest();
  assert.deepEqual([digest.unvisitedRoutes.length, digest.untestedParams.length, digest.counts.byKind], [10, 10, { param: 120, route: 12 }]);
});

test("graph_digest lists what is still untested, the chains, and playbooks for the untested surface", async () => {
  const f = fixture();
  await f.write({
    nodes: [{ id: "r1", kind: "route", label: "/Upload/Avatar" }, { id: "r2", kind: "route", label: "/health" }, { id: "r3", kind: "route", label: "/search" },
      { id: "p1", kind: "param", label: "callback" }, { id: "p2", kind: "param", label: "next" },
      { id: "f1", kind: "finding", label: "open redirect on next" }, { id: "f2", kind: "finding", label: "token in redirect URL" },
      { id: "x1", kind: "observation", label: "health returns build info" }, { id: "x2", kind: "observation", label: "search reflects q" }],
    // Either end of a tested or observed edge counts as visited.
    edges: [{ from: "x1", to: "r2", kind: "observed" }, { from: "r3", to: "x2", kind: "observed" }, { from: "f1", to: "p2", kind: "tested" },
      { from: "f1", to: "f2", kind: "enables", note: "redirect leaks the token" }] });
  const digest = await f.digest();
  assert.deepEqual(digest.unvisitedRoutes, ["/Upload/Avatar"]);
  assert.deepEqual(digest.untestedParams, ["callback"]);
  assert.deepEqual(digest.chainableFindings, [{ from: "open redirect on next", to: "token in redirect URL", note: "redirect leaks the token" }]);
  // The visited /search would match SQL injection; only the untested surface counts, routes and params alike.
  assert.deepEqual(digest.suggestedPlaybooks, [{ playbook: "File upload attacks", matches: ["/Upload/Avatar"] }, { playbook: "SSRF and out-of-band", matches: ["callback"] }]);
  assert.deepEqual(digest.counts.byKind, { route: 3, param: 2, finding: 2, observation: 2 });
  assert.match(digest.hint, /graph_write/);
});

test("past 2 MiB the observations written longest ago go first, with their edges, and only as many as needed", async () => {
  const f = fixture();
  const observation = (label, id) => ({ ...(id && { id }), kind: "observation", label, data: { text: "x".repeat(4000) } });
  const routes = Array.from({ length: 20 }, (_, i) => ({ id: "r" + i, kind: "route", label: "/r" + i }));
  f.now = 500; await f.write({ nodes: routes });
  // Observations are usually written without ids.
  f.now = 1000; await f.write({ nodes: [...Array.from({ length: 40 }, (_, i) => observation("old-" + i)), observation("old-x", "old-x")],
    edges: [{ from: "old-x", to: "r0", kind: "observed" }, { from: "r1", to: "old-x", kind: "links_to" }] });
  f.now = 2000; await f.write({ nodes: [observation("old-x", "old-x")] });
  f.now = 3000; await f.write({ nodes: Array.from({ length: 429 }, (_, i) => observation("new-" + i, "new-" + i)) });
  f.now = 3500; await f.write({ nodes: [observation("late")] });
  f.now = 3600; await f.write({ nodes: [observation("new-0", "new-0")] });
  // 1998 more edges with long notes push the graph past 2 MiB.
  const edges = ["links_to", "tested", "requires_auth", "observed", "enables", "hosts"].flatMap(kind => routes.flatMap(a => routes.filter(b => b !== a).map(b => ({ from: a.id, to: b.id, kind, note: "n".repeat(200) })))).slice(0, 1998);
  f.now = 4000; const out = await f.write({ edges });
  const graph = f.graph(), size = JSON.stringify(graph).length, labels = new Set(Object.values(graph.nodes).map(node => node.label));
  const kept = Object.values(graph.nodes).filter(node => node.kind === "observation").length;
  assert.ok(size <= 2 * 1024 * 1024 && size > 2 * 1024 * 1024 - 4200, "dropped no more than it had to: " + size);
  assert.ok([...Array.from({ length: 40 }, (_, i) => "old-" + i), "old-x"].every(label => !labels.has(label)), "old-x was written again at 2000, still before every new- observation");
  assert.ok(labels.has("late") && labels.has("new-0") && labels.has("/r0"));
  assert.equal(graph.edges.length, 1998, "both edges of old-x went with it");
  assert.deepEqual(out.evicted, { observations: 471 - kept });
});

test("a graph over 2 MiB with no observations to drop is still saved", async () => {
  const f = fixture();
  const out = await f.write({ nodes: Array.from({ length: 500 }, (_, i) => ({ id: "f" + i, kind: "finding", label: "finding " + i + " " + "y".repeat(150), data: { text: "x".repeat(4080) } })) });
  assert.equal(out.isError, false, out.error);
  assert.ok(JSON.stringify(f.graph()).length > 2 * 1024 * 1024);
  assert.equal(out.evicted, undefined);
});

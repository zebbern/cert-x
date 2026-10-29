// Workspace knowledge graph: the persistent map of the attack surface that
// recon feeds and the orchestrator reasons over. Nodes are typed (origins,
// routes, params, roles, findings...), edges are typed relationships, and the
// playbook seed layer is pulled on demand via graph_find — never prompt text.
// Storage is chrome.storage.local under unlimitedStorage; the 2 MiB cap and
// 500-node bound are hygiene, not quota.
var KI_GRAPH_KEY = "ki_task_graphs", kiGraphWrites = Promise.resolve();
var KI_GRAPH_KINDS = ["origin", "route", "param", "tech", "role", "account", "finding", "observation", "evidence"];
var KI_GRAPH_EDGE_KINDS = ["hosts", "links_to", "serves", "has_param", "requires_auth", "uses_tech", "observed", "enables", "tested"];
function kiGraphInputError(message, recovery) { return Object.assign(Error(message), { retryable: false, recovery }); }
// Names on Object.prototype (__proto__, toString...) would read as nodes that already exist.
function kiGraphId(value) { return typeof value === "string" && /^[A-Za-z0-9_.:-]{1,100}$/.test(value) && !(value in Object.prototype); }
async function kiGraphKey(session) {
  if (typeof kiContextResolve === "function") {
    try { const context = await kiContextResolve(session); if (context?.workspace?.id) return "ws:" + context.workspace.id; } catch {}
  }
  const owner = typeof kiWorkspaceOwner === "function" ? kiWorkspaceOwner(session) : session;
  return "chat:" + owner;
}
// A failed read throws: a write built on an empty stand-in would save over
// every workspace's graph.
async function kiGraphLoad() { return (await chrome.storage.local.get(KI_GRAPH_KEY))[KI_GRAPH_KEY] || {}; }
function kiGraphWritten(node) { return node.updatedAt || node.at; }
// A write reads, changes and saves the whole record, and one key holds every
// workspace's graph, so writes run one at a time; chats running at the same
// time would otherwise overwrite each other's graphs.
function kiGraphSerial(work) {
  const task = kiGraphWrites.then(work);
  kiGraphWrites = task.catch(() => {});
  return task;
}
function kiGraphPersist(record) { return chrome.storage.local.set({ [KI_GRAPH_KEY]: record }); }
function kiGraphNormalizeNode(node) {
  if (!node || typeof node !== "object") throw kiGraphInputError("Each node must be an object.", "Supply {id?, kind, label, data?}; kind is one of: " + KI_GRAPH_KINDS.join(", ") + ".");
  // Edges only accept ids of this shape, so a node must not get any other; "" and null mean no id.
  const id = node.id || undefined;
  if (id !== undefined && !kiGraphId(id)) throw kiGraphInputError("Node id " + JSON.stringify(id) + " is not usable.", "Ids are strings of 1-100 letters, digits and _ . : - (no slashes or spaces), e.g. route:api.orders; or leave id out and one is made.");
  const kind = KI_GRAPH_KINDS.includes(node.kind) ? node.kind : null;
  if (!kind) throw kiGraphInputError("Unknown node kind " + JSON.stringify(node.kind) + ".", "Use one of: " + KI_GRAPH_KINDS.join(", ") + ".");
  const label = typeof node.label === "string" ? node.label.trim().slice(0, 200) : "";
  if (!label) throw kiGraphInputError("Node labels are required.", "Give each node a short label, e.g. the route path or parameter name.");
  const data = node.data == null ? undefined : JSON.parse(JSON.stringify(node.data));
  if (data !== undefined && JSON.stringify(data).length > 4096) throw kiGraphInputError("Node data exceeds 4 KiB.", "Keep node data to identifiers and short observations; store bulk evidence in Outputs.");
  return { id, kind, label, ...(data !== undefined ? { data } : {}) };
}
function kiGraphNormalizeEdge(edge, known, reset) {
  if (!edge || typeof edge !== "object") throw kiGraphInputError("Each edge must be an object.", "Supply {from, to, kind, note?}; kind is one of: " + KI_GRAPH_EDGE_KINDS.join(", ") + ".");
  if (!KI_GRAPH_EDGE_KINDS.includes(edge.kind)) throw kiGraphInputError("Unknown edge kind " + JSON.stringify(edge.kind) + ".", "Use one of: " + KI_GRAPH_EDGE_KINDS.join(", ") + ".");
  for (const end of [edge.from, edge.to]) if (!kiGraphId(end) || !known.has(end)) throw kiGraphInputError("Edge endpoint " + JSON.stringify(end) + " does not exist.", reset ? "reset:true starts from an empty graph, so include every endpoint in this call's nodes." : "Create the node first (same graph_write call is fine), or reuse an id from graph_find.");
  return { from: edge.from, to: edge.to, kind: edge.kind, ...(typeof edge.note === "string" && edge.note.trim() ? { note: edge.note.trim().slice(0, 200) } : {}) };
}
function kiGraphApply(session, args) { return kiGraphSerial(() => kiGraphApplyNow(session, args)); }
async function kiGraphApplyNow(session, args) {
  if (!args || typeof args !== "object") throw kiGraphInputError("graph_write needs nodes and/or edges.", "Example: {nodes:[{id:'route:api.orders', kind:'route', label:'/api/orders'}], edges:[]}.");
  for (const field of ["nodes", "edges"]) if (args[field] != null && !Array.isArray(args[field])) throw kiGraphInputError(field + " must be an array.", "Pass " + field + " as a JSON array, not a string or a single object.");
  const record = await kiGraphLoad(), key = await kiGraphKey(session), reset = args.reset === true;
  // reset starts this workspace's graph over, then writes whatever came with it.
  const graph = !reset && record[key] || { version: 1, nodes: {}, edges: [], updatedAt: 0 };
  const incoming = (args.nodes || []).map(kiGraphNormalizeNode), incomingEdges = args.edges || [];
  if (!incoming.length && !incomingEdges.length && !reset) throw kiGraphInputError("Nothing to write.", "Pass nodes and/or edges, or reset:true to clear this workspace graph.");
  const count = Object.keys(graph.nodes).length, added = incoming.filter(node => !node.id || !graph.nodes[node.id]).length;
  if (count + added > 500) throw kiGraphInputError("This graph holds " + count + " of 500 nodes and this call adds " + added + " new ones.", "Write at most " + Math.max(0, 500 - count) + " new nodes, update existing ids instead, or reset:true to start over.");
  const ids = new Set(), generated = [];
  for (const node of incoming) {
    if (node.id && ids.has(node.id)) throw kiGraphInputError("Duplicate node id " + node.id + " in this batch.", "Use one node per id; upserts update in place.");
    // An update keeps when the node was first seen, and its data unless new data comes.
    if (node.id) { graph.nodes[node.id] = { at: Date.now(), ...graph.nodes[node.id], ...node, updatedAt: Date.now() }; ids.add(node.id); }
    else { let id; do { id = node.kind + "-" + crypto.randomUUID().slice(0, 8); } while (graph.nodes[id]); graph.nodes[id] = { ...node, id, at: Date.now() }; generated.push(id); }
  }
  // One edge per (from, to, kind): writing it again replaces its note and makes it the newest.
  const known = new Set(Object.keys(graph.nodes)), edgeKey = edge => edge.from + " " + edge.to + " " + edge.kind;
  const byKey = new Map(graph.edges.map(edge => [edgeKey(edge), edge]));
  for (const edge of incomingEdges.map(edge => kiGraphNormalizeEdge(edge, known, reset))) { byKey.delete(edgeKey(edge)); byKey.set(edgeKey(edge), edge); }
  graph.edges = [...byKey.values()].slice(-2000);
  graph.updatedAt = Date.now();
  // Hygiene cap: 2 MiB serialized; drop the observations written longest ago first.
  let evicted = 0;
  while (JSON.stringify(graph).length > 2 * 1024 * 1024) {
    const oldest = Object.values(graph.nodes).filter(node => node.kind === "observation").sort((a, b) => kiGraphWritten(a) - kiGraphWritten(b))[0];
    if (!oldest) break;
    delete graph.nodes[oldest.id]; graph.edges = graph.edges.filter(edge => edge.from !== oldest.id && edge.to !== oldest.id); evicted++;
  }
  await kiGraphPersist({ ...record, [key]: graph });
  return { ...(reset && { reset: true }), written: { nodes: incoming.length, edges: incomingEdges.length, ...(generated.length && { generated }) },
    ...(evicted && { evicted: { observations: evicted } }), counts: kiGraphCounts(graph) };
}
function kiGraphCounts(graph) {
  const counts = {}; for (const node of Object.values(graph.nodes)) counts[node.kind] = (counts[node.kind] || 0) + 1;
  return { nodes: Object.keys(graph.nodes).length, edges: graph.edges.length, byKind: counts };
}
function kiGraphFindRaw(session, args) {
  const q = args?.q && typeof args.q === "object" ? args.q : args || {};
  const limit = Math.min(Number.isInteger(q.limit) && q.limit > 0 ? q.limit : 50, 100);
  const given = value => typeof value === "string" && value !== "";
  for (const kind of Array.isArray(q.kinds) ? q.kinds : []) if (kind !== "playbook" && !KI_GRAPH_KINDS.includes(kind)) throw kiGraphInputError("Unknown kind " + JSON.stringify(kind) + ".", "Use any of: " + KI_GRAPH_KINDS.join(", ") + ", playbook.");
  if (given(q.edge) && !KI_GRAPH_EDGE_KINDS.includes(q.edge)) throw kiGraphInputError("Unknown edge kind " + JSON.stringify(q.edge) + ".", "Use one of: " + KI_GRAPH_EDGE_KINDS.join(", ") + ".");
  return kiGraphLoad().then(record => kiGraphKey(session).then(key => {
    const graph = record[key] || { nodes: {}, edges: [] }, all = Object.values(graph.nodes);
    // A reference that is not an id resolves to the one node whose label is (or
    // else contains) it, such as a path; otherwise the error lists the candidates.
    const resolve = ref => {
      if (!given(ref) || Object.hasOwn(graph.nodes, ref)) return given(ref) ? ref : null;
      const term = ref.toLowerCase(), exact = all.filter(node => node.label.toLowerCase() === term);
      const near = exact.length ? exact : all.filter(node => node.label.toLowerCase().includes(term));
      if (near.length === 1) return near[0].id;
      const list = (near.length ? near : [...all].sort((a, b) => kiGraphWritten(b) - kiGraphWritten(a))).slice(0, 10).map(node => node.id);
      throw kiGraphInputError("No node " + JSON.stringify(ref) + " in this graph.", !list.length ? "This graph is empty; record nodes with graph_write first." : (near.length ? "Several nodes match: " : "Recently written ids: ") + list.join(", ") + ".");
    };
    const playbookId = KI_GRAPH_PLAYBOOKS.some(pb => pb.id === q.id);
    const from = resolve(q.from), to = resolve(q.to), id = playbookId ? null : resolve(q.id), edgeKind = given(q.edge) ? q.edge : null;
    // from/to/edge make a traversal: the matching edges and the nodes at their
    // ends, with kinds and label_contains applied to the far end; an id with only
    // an edge kind is the anchor in either direction. Neither a traversal nor an
    // id lookup brings in the rest of the graph or other playbooks.
    const traversal = Boolean(from || to || edgeKind), anchor = traversal && !from && !to ? id : null;
    const nodeMatches = node => (!Array.isArray(q.kinds) || q.kinds.length === 0 || q.kinds.includes(node.kind)) &&
      (typeof q.label_contains !== "string" || !q.label_contains || node.label.toLowerCase().includes(q.label_contains.toLowerCase())) &&
      (!id || anchor || node.id === id);
    const far = edge => from ? [edge.to] : to ? [edge.from] : anchor ? [edge.from === anchor ? edge.to : edge.from] : [edge.from, edge.to];
    const matched = new Set(traversal || playbookId ? [] : all.filter(nodeMatches).slice(0, limit).map(node => node.id));
    const edges = graph.edges.filter(edge => traversal
      ? (!edgeKind || edge.kind === edgeKind) && (!from || edge.from === from) && (!to || edge.to === to) && (!anchor || edge.from === anchor || edge.to === anchor) && far(edge).some(end => graph.nodes[end] && nodeMatches(graph.nodes[end]))
      : matched.has(edge.from) || matched.has(edge.to)).slice(0, limit * 2);
    // What was asked for comes first, so neighbours never push it past the limit.
    const order = new Set([from, to, anchor, ...matched].filter(Boolean));
    for (const edge of edges) { order.add(edge.from); order.add(edge.to); }
    const playbooks = traversal ? [] : KI_GRAPH_PLAYBOOKS.filter(pb => (!Array.isArray(q.kinds) || q.kinds.length === 0 || q.kinds.includes("playbook")) && (!given(q.id) || pb.id === q.id) &&
      (typeof q.label_contains !== "string" || !q.label_contains || (pb.label + " " + pb.data.triggers.join(" ")).toLowerCase().includes(q.label_contains.toLowerCase())));
    return { nodes: [...order].slice(0, limit).map(end => graph.nodes[end]), edges, ...(playbooks.length ? { playbooks: playbooks.slice(0, 10) } : {}) };
  }));
}
function kiGraphDigest(session) {
  return kiGraphLoad().then(record => kiGraphKey(session).then(key => {
    const graph = record[key] || { nodes: {}, edges: [] };
    const nodes = Object.values(graph.nodes);
    const testedTargets = new Set(graph.edges.filter(edge => edge.kind === "tested" || edge.kind === "observed").flatMap(edge => [edge.from, edge.to]));
    const unvisitedRoutes = nodes.filter(node => node.kind === "route" && !testedTargets.has(node.id)).map(node => node.label).slice(0, 10);
    const untestedParams = nodes.filter(node => node.kind === "param" && !testedTargets.has(node.id)).map(node => node.label).slice(0, 10);
    const chainable = graph.edges.filter(edge => edge.kind === "enables").map(edge => ({ from: graph.nodes[edge.from]?.label || edge.from, to: graph.nodes[edge.to]?.label || edge.to, ...(edge.note ? { note: edge.note } : {}) })).slice(0, 10);
    const frontier = [...unvisitedRoutes.map(label => ({ kind: "route", label })), ...untestedParams.map(label => ({ kind: "param", label }))];
    const suggested = frontier.length ? KI_GRAPH_PLAYBOOKS.filter(pb => frontier.some(item => pb.data.triggers.some(trigger => item.label.toLowerCase().includes(trigger)))).slice(0, 5)
      .map(pb => ({ playbook: pb.label, matches: frontier.filter(item => pb.data.triggers.some(trigger => item.label.toLowerCase().includes(trigger))).map(item => item.label).slice(0, 5) })) : [];
    return { counts: kiGraphCounts(graph), unvisitedRoutes, untestedParams, chainableFindings: chainable, ...(suggested.length ? { suggestedPlaybooks: suggested } : {}),
      hint: "Feed recon with graph_write, then pick next moves from unvisitedRoutes/untestedParams; chain 'enables' edges into an exploit path before reporting." };
  }));
}
function kiGraphToolDefs(session) {
  const meta = name => ({ id: "graph:" + name, group: "graph", family: "graph", name, label: "Knowledge graph", defaultAsk: false });
  // Input errors carry their own recovery; anything else (storage) is worth one retry.
  const wrapError = error => ({ output: JSON.stringify({ error: error.message, retryable: error.retryable !== false, recovery: error.recovery || "Not an input problem; retry this call once." }), isError: true });
  const run = async work => { try { return { output: JSON.stringify(await work()) }; } catch (error) { return wrapError(error); } };
  return [
    { name: "graph_write", description: "Add or update nodes and edges in this workspace’s attack-surface graph (origins, routes, params, roles, tech, findings). Upsert by id; edges may use nodes from the same call; reset:true clears.", kiPolicyMeta: meta("graph_write"),
      parameters: { type: "object", properties: {
        nodes: { type: "array", description: "Nodes to upsert: {id?, kind, label, data?}. Kinds: " + KI_GRAPH_KINDS.join(", ") + "." },
        edges: { type: "array", description: "Edges to add: {from, to, kind, note?}. Kinds: " + KI_GRAPH_EDGE_KINDS.join(", ") + "." },
        reset: { type: "boolean", description: "Clear this workspace’s graph first." } }, additionalProperties: false },
      resolveExecution(args) { return { approvalRule: "allow", async execute() { return run(() => kiGraphApply(session, args)); } }; } },
    { name: "graph_find", description: "Find graph nodes by kind or label substring, or traverse an id by edge kind; matching playbook seeds are included.", kiPolicyMeta: meta("graph_find"),
      parameters: { type: "object", properties: { kinds: { type: "array", items: { type: "string" } }, label_contains: { type: "string" }, id: { type: "string" }, from: { type: "string" }, to: { type: "string" }, edge: { type: "string" }, limit: { type: "integer", minimum: 1, maximum: 100 } }, additionalProperties: false },
      resolveExecution(args) { return { approvalRule: "allow", async execute() { return run(() => kiGraphFindRaw(session, args)); } }; } },
    { name: "graph_digest", description: "The graph’s decision summary: coverage counts, unvisited routes, untested inputs, chainable findings, suggested playbooks.", kiPolicyMeta: meta("graph_digest"),
      parameters: { type: "object", properties: {}, additionalProperties: false },
      resolveExecution() { return { approvalRule: "allow", async execute() { return run(() => kiGraphDigest(session)); } }; } },
  ];
}
// Playbook seed layer, distilled from the checkbox methodology sources
// (Get Root Access, the file-upload attack map, and the Agentic AI Red Team
// Checklist). Pulled via graph_find on demand; deliberately terse — chains
// of moves, not prose.
var KI_GRAPH_PLAYBOOKS = [
  { id: "pb:recon-entry", kind: "playbook", label: "Recon and entry points", data: { triggers: [], chain: ["Map assets, subdomains and origins", "Enumerate entry points: routes, forms, API operations", "Identify roles and account tiers", "Fingerprint technologies", "Write everything to the graph before testing"] } },
  { id: "pb:file-upload", kind: "playbook", label: "File upload attacks", data: { triggers: ["upload", "avatar", "import", "attachment", "file"], chain: ["Probe default web-shell extensions per language (php/asp/jsp)", "Content-Type and magic-byte mismatches", "Filename tricks: null byte, special characters, double extensions", "Configuration files (.htaccess, web.config) as payload", "Parser CVEs (ImageMagick, image libraries)", "ZIP: ZipSlip path traversal on extraction", "SVG/XXE upload for exotic-file XXE", "Prove execution, then bound impact"] } },
  { id: "pb:sql-injection", kind: "playbook", label: "SQL injection", data: { triggers: ["search", "sort", "filter", "category", "query", "id"], chain: ["Error-based probe with quote syntax", "Column-count reconciliation for UNION", "WAF bypass: whitespace alternatives, comments, encoding", "Conditional and time-based blind extraction", "Try NoSQL syntax on document stores", "Extract one protected datum as proof"] } },
  { id: "pb:lfi-rfi", kind: "playbook", label: "File inclusion (LFI/RFI)", data: { triggers: ["path", "page", "file", "template", "lang", "include"], chain: ["Directory traversal depth probe", "Wrappers: php://filter to read source", "Log poisoning to RCE", "RFI if remote inclusion is permitted", "Controlled config-file inclusion"] } },
  { id: "pb:xxe", kind: "playbook", label: "XXE injection", data: { triggers: ["xml", "svg", "soap", "docx", "rss", "sitemap"], chain: ["Error-based external entity probe", "Blind XXE via out-of-band callback", "Exotic vectors: uploaded SVG, office documents", "File read via entity, then impact bounding"] } },
  { id: "pb:idor-access", kind: "playbook", label: "IDOR and access control", data: { triggers: ["id", "uid", "account", "order", "invoice", "download", "document"], chain: ["Object swap in path/query/JSON with a second verified account", "Negative control first: same-account request must succeed", "Role-pair comparison across privilege boundaries", "State the invariant: prerequisites, boundary, observable effect"] } },
  { id: "pb:auth-session", kind: "playbook", label: "Authentication and session", data: { triggers: ["oauth", "login", "token", "jwt", "session", "cookie", "2fa", "mfa"], chain: ["JWT structure: alg confusion, weak secret, claim trust", "OAuth: redirect_uri manipulation, state CSRF, code reuse", "2FA misconfiguration and brute-force lockout behavior", "Password reset token scope and expiry", "Session fixation and logout failures", "Chain into account takeover proof"] } },
  { id: "pb:account-takeover", kind: "playbook", label: "Account takeover chaining", data: { triggers: ["register", "email", "password", "forgot", "verify"], chain: ["Registration: email confusion, duplicate handling", "Reset flow: token predictability, host-header poisoning", "Cross-account token/session reuse", "Chain minor issues into full takeover; verify restoration after"] } },
  { id: "pb:business-logic", kind: "playbook", label: "Business logic (purchase flows)", data: { triggers: ["price", "cart", "voucher", "coupon", "gift", "checkout", "order", "quantity"], chain: ["Client-side price tampering", "Voucher reuse and race conditions", "Rounding and currency confusion", "Negative quantities and integer edges", "Order-state and workflow skips"] } },
  { id: "pb:ssrf-oob", kind: "playbook", label: "SSRF and out-of-band", data: { triggers: ["url", "fetch", "preview", "import", "webhook", "callback"], chain: ["URL parameter scheme and host probing", "Internal ranges and metadata endpoints", "Response differentials when blind", "Out-of-band callback confirmation", "Bound impact to observed internal interaction"] } },
  { id: "pb:deserialization", kind: "playbook", label: "Insecure deserialization", data: { triggers: ["cookie", "session", "serialize", "export", "base64"], chain: ["Identify framework by blob shape", "Known gadget chains for the stack", "Read-only probes before execution attempts", "RCE proof with controlled marker"] } },
  { id: "pb:agentic-ai", kind: "playbook", label: "Agentic AI and LLM attacks", data: { triggers: ["chat", "prompt", "assistant", "agent", "mcp", "llm", "gpt", "rag", "embedding", "vector", "summar", "translate", "tool_call"], chain: ["Fingerprint the AI stack from public artifacts and responses (model, framework, provider)", "Recover system prompts, AGENTS/SKILL instruction files and tool manifests", "Direct prompt injection; then indirect injection through ingested content (pages, emails, documents, RAG corpus)", "Encoding and filter-evasion variants when input filters engage", "Abuse exposed tools/MCP endpoints: unauthorized actions, cross-tool chaining", "Poison memory or vector stores for persistence", "Exfiltrate through tool calls, webhooks or CI/CD autonomy", "Bound impact: distinguish executed action from refusal or hallucination"] } },
];
if (typeof module === "object" && module.exports) module.exports = { kiGraphToolDefs, kiGraphApply, kiGraphFindRaw, kiGraphDigest, KI_GRAPH_PLAYBOOKS };

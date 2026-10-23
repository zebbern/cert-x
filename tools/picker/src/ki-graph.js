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
function kiGraphId(value) { return typeof value === "string" && /^[A-Za-z0-9_.:-]{1,100}$/.test(value); }
async function kiGraphKey(session) {
  if (typeof kiContextResolve === "function") {
    try { const context = await kiContextResolve(session); if (context?.workspace?.id) return "ws:" + context.workspace.id; } catch {}
  }
  const owner = typeof kiWorkspaceOwner === "function" ? kiWorkspaceOwner(session) : session;
  return "chat:" + owner;
}
async function kiGraphLoad() {
  try { return (await chrome.storage.local.get(KI_GRAPH_KEY))[KI_GRAPH_KEY] || {}; } catch { return {}; }
}
async function kiGraphPersist(record) {
  const task = kiGraphWrites.then(() => chrome.storage.local.set({ [KI_GRAPH_KEY]: record }));
  kiGraphWrites = task.catch(() => {});
  return task;
}
function kiGraphNormalizeNode(node) {
  if (!node || typeof node !== "object") throw kiGraphInputError("Each node must be an object.", "Supply {id?, kind, label, data?}; kind is one of: " + KI_GRAPH_KINDS.join(", ") + ".");
  const kind = KI_GRAPH_KINDS.includes(node.kind) ? node.kind : null;
  if (!kind) throw kiGraphInputError("Unknown node kind " + JSON.stringify(node.kind) + ".", "Use one of: " + KI_GRAPH_KINDS.join(", ") + ".");
  const label = typeof node.label === "string" ? node.label.trim().slice(0, 200) : "";
  if (!label) throw kiGraphInputError("Node labels are required.", "Give each node a short label, e.g. the route path or parameter name.");
  const data = node.data === undefined ? undefined : JSON.parse(JSON.stringify(node.data));
  if (data !== undefined && JSON.stringify(data).length > 4096) throw kiGraphInputError("Node data exceeds 4 KiB.", "Keep node data to identifiers and short observations; store bulk evidence in Outputs.");
  return { id: node.id, kind, label, ...(data !== undefined ? { data } : {}) };
}
function kiGraphNormalizeEdge(edge, known) {
  if (!edge || typeof edge !== "object") throw kiGraphInputError("Each edge must be an object.", "Supply {from, to, kind, note?}; kind is one of: " + KI_GRAPH_EDGE_KINDS.join(", ") + ".");
  if (!KI_GRAPH_EDGE_KINDS.includes(edge.kind)) throw kiGraphInputError("Unknown edge kind " + JSON.stringify(edge.kind) + ".", "Use one of: " + KI_GRAPH_EDGE_KINDS.join(", ") + ".");
  for (const end of [edge.from, edge.to]) if (!kiGraphId(end) || !known.has(end)) throw kiGraphInputError("Edge endpoint " + JSON.stringify(end) + " does not exist.", "Create the node first (same graph_write call is fine), or reuse an id from graph_find.");
  return { from: edge.from, to: edge.to, kind: edge.kind, ...(typeof edge.note === "string" && edge.note.trim() ? { note: edge.note.trim().slice(0, 200) } : {}) };
}
async function kiGraphApply(session, args) {
  if (!args || typeof args !== "object") throw kiGraphInputError("graph_write needs nodes and/or edges.", "Example: {nodes:[{kind:'route',label:'/api/orders'}], edges:[]}.");
  const record = await kiGraphLoad(), key = await kiGraphKey(session);
  if (args.reset === true) { const graph = { version: 1, nodes: {}, edges: [], updatedAt: Date.now() }; await kiGraphPersist({ ...record, [key]: graph }); return { reset: true, counts: kiGraphCounts(graph) }; }
  const graph = record[key] || { version: 1, nodes: {}, edges: [], updatedAt: 0 };
  const incoming = Array.isArray(args.nodes) ? args.nodes.map(kiGraphNormalizeNode) : [];
  const incomingEdges = Array.isArray(args.edges) ? args.edges : [];
  if (!incoming.length && !incomingEdges.length) throw kiGraphInputError("Nothing to write.", "Pass nodes and/or edges, or reset:true to clear this workspace graph.");
  const known = new Set([...Object.keys(graph.nodes), ...incoming.map(node => node.id).filter(Boolean)]);
  if (Object.keys(graph.nodes).length + incoming.length > 500) throw kiGraphInputError("This graph is at the 500-node bound.", "Reset it, or find and remove stale observations; keep one node per distinct surface element.");
  const ids = new Set();
  for (const node of incoming) {
    if (node.id && ids.has(node.id)) throw kiGraphInputError("Duplicate node id " + node.id + " in this batch.", "Use one node per id; upserts update in place.");
    if (node.id) { graph.nodes[node.id] = { ...node, at: graph.nodes[node.id]?.at || Date.now(), updatedAt: Date.now() }; ids.add(node.id); }
    else { let id; do { id = node.kind + "-" + crypto.randomUUID().slice(0, 8); } while (graph.nodes[id]); graph.nodes[id] = { ...node, id, at: Date.now() }; }
  }
  for (const edge of incomingEdges.map(edge => kiGraphNormalizeEdge(edge, new Set([...Object.keys(graph.nodes)])))) graph.edges.push(edge);
  graph.edges = graph.edges.slice(-2000);
  graph.updatedAt = Date.now();
  // Hygiene cap: 2 MiB serialized; drop the oldest observations first.
  while (JSON.stringify(graph).length > 2 * 1024 * 1024) {
    const oldest = Object.values(graph.nodes).filter(node => node.kind === "observation").sort((a, b) => a.updatedAt - a.at - (b.updatedAt - b.at))[0];
    if (!oldest) break;
    delete graph.nodes[oldest.id]; graph.edges = graph.edges.filter(edge => edge.from !== oldest.id && edge.to !== oldest.id);
  }
  await kiGraphPersist({ ...record, [key]: graph });
  return { written: { nodes: incoming.length, edges: incomingEdges.length }, counts: kiGraphCounts(graph) };
}
function kiGraphCounts(graph) {
  const counts = {}; for (const node of Object.values(graph.nodes)) counts[node.kind] = (counts[node.kind] || 0) + 1;
  return { nodes: Object.keys(graph.nodes).length, edges: graph.edges.length, byKind: counts };
}
function kiGraphFindRaw(session, args) {
  const q = args?.q && typeof args.q === "object" ? args.q : args || {};
  const limit = Math.min(Number.isInteger(q.limit) && q.limit > 0 ? q.limit : 50, 100);
  return kiGraphLoad().then(record => kiGraphKey(session).then(key => {
    const graph = record[key] || { nodes: {}, edges: [] };
    const nodeMatches = node => (!Array.isArray(q.kinds) || q.kinds.length === 0 || q.kinds.includes(node.kind)) &&
      (typeof q.label_contains !== "string" || !q.label_contains || node.label.toLowerCase().includes(q.label_contains.toLowerCase())) &&
      (typeof q.id !== "string" || node.id === q.id);
    const matched = Object.values(graph.nodes).filter(nodeMatches).slice(0, limit).map(node => node.id);
    const matchedSet = new Set(matched);
    const edges = graph.edges.filter(edge => (!q.edge || edge.kind === q.edge) &&
      ((typeof q.from === "string" ? edge.from === q.from : matchedSet.has(edge.from) || matchedSet.has(edge.to)) &&
      (typeof q.to !== "string" || edge.to === q.to))).slice(0, limit * 2);
    for (const edge of edges) { matchedSet.add(edge.from); matchedSet.add(edge.to); }
    const playbooks = !Array.isArray(q.kinds) || q.kinds.length === 0 || q.kinds.includes("playbook") ? KI_GRAPH_PLAYBOOKS.filter(pb => typeof q.label_contains !== "string" || !q.label_contains || (pb.label + " " + pb.data.triggers.join(" ")).toLowerCase().includes(q.label_contains.toLowerCase())) : [];
    return { nodes: Object.values(graph.nodes).filter(node => matchedSet.has(node.id)).slice(0, limit), edges, ...(playbooks.length ? { playbooks: playbooks.slice(0, 10) } : {}) };
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
  const wrapError = error => ({ output: JSON.stringify({ error: error.message, ...(error.retryable === false ? { retryable: false, recovery: error.recovery } : {}) }), isError: true });
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
// (Get Root Access + file-upload attack map). Pulled via graph_find on
// demand; deliberately terse — chains of moves, not prose.
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
];
if (typeof module === "object" && module.exports) module.exports = { kiGraphToolDefs, kiGraphApply, kiGraphFindRaw, kiGraphDigest, KI_GRAPH_PLAYBOOKS };

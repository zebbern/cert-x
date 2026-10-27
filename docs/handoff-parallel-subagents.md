# Handoff: run subagents in parallel (and a clearer 404 message)

Status: section 1 designed and measured on 2026-10-26, not started; section 2
done. Base: branch
`fast-browse` at `7ed96cc`. Read AGENTS.md first; the build rules there apply
(patch through `tools/picker/apply-picker.js`, never hand-edit
`background/background.js` or `chunks/*`).

## 1. Parallel subagents

### Why

When the model dispatches several subagents in one turn, they run one after
another. BugStore live run 2 (request bodies in `C:/tmp/m4-req-*.json`, run log
in `tools/security/evidence/m4-live-baseline/bugstore-run2-run.log`):

| Batch | Run one after another | Longest single subagent |
|---|---|---|
| 4 recon subagents | 32.5 min | about 9–10 min |
| 3 more subagents | 18.5 min | about 9 min |

Subagents took about 54 of the 60 minutes. In parallel that is roughly 20, less
now that `7ed96cc` stopped the 90 s stall cuts that padded several of them. The
orchestrator waits for the whole batch either way, so the slowest one sets the
pace.

### What is known (verified in the bundle)

- A turn's tool calls go through a scheduler (search `LM=class{activeTasks=[]`).
  It starts each call at once unless its declared `accesses` conflict with a
  running or queued call (`wM.conflict`). An access of kind `all` conflicts with
  everything; two `read` accesses never conflict with each other.
- A call's accesses come from its tool's `resolveExecution(...)` result. When the
  result has none, the step uses `wM.all()` (search `accesses??wM.all()`).
- The `agent` tool (builder: search `let r=pP.agent`) declares none, so every
  subagent call is exclusive. That is the whole cause. The browser tools (builder:
  search `let r=mP[e];if(!r)throw`) declare none either, which is right inside
  one conversation.
- A subagent shares its parent's tab-group session and starts without a primary
  tab of its own. It can still be told to act on the parent's tab.
- `graph_write` was not safe to run concurrently: two writes at once lost one,
  across workspaces too, because one key holds every workspace's graph. Fixed
  2026-10-28: the whole load-edit-save runs one at a time (`kiGraphSerial` in
  `tools/picker/src/ki-graph.js`), covered by `tools/picker/tests/graph.test.js`.

Minified names (`LM`, `wM`, `UM`, ...) change if the vendor snapshot changes;
find them by the quoted anchors.

### Plan

1. **Graph writes.** Done 2026-10-28 (see above); nothing else writes
   `KI_GRAPH_KEY`.
2. **Audit other shared state** that subagents' tools write at the same time;
   this was not done. Candidates: Outputs (`kiWorkspaceOutput`, used by
   download and save_file results), `ki-telemetry.js`, security run and capture
   state, context stores in `ki-context.js`, and the vendor's persistence of child
   conversations. Any load-edit-save on a shared key needs the same treatment as
   step 1.
3. **One subagent per tab at a time.** In the browser tool builder, after the
   target tab is resolved and before the executor runs, chain the call on a
   per-tab queue (`Map` of tab id → tail promise). Calls on different tabs, and
   calls with no tab (`download` fetches from the worker), stay parallel. Release
   on error and on abort.
4. **Let subagent calls overlap.** Give the agent tool's `resolveExecution`
   result an access that is a shared read among subagents and still conflicts
   with `all`, for example `[{kind:'subagent',operation:'read',path:'subagent'}]`.
   Only `all` is special-cased by kind; other kinds are compared by operation and
   path. Subagents in one turn then run together, and any other tool call in that
   turn still waits for them.
5. **No concurrency cap.** Nothing measured calls for one (AGENTS.md: every limit
   needs a stated reason).

### How to verify

- A new browser test modelled on `tools/picker/tests/stream-liveness.browser.cjs`
  (mock OpenRouter-style provider, real side panel, scripted `agent` calls; test
  build `KI_TEST_HOOKS=1 node tools/picker/apply-picker.js`):
  - 3 agent calls in one turn, each subagent stream about 2 s: their first
    requests start within about 0.5 s of each other, and the turn takes about
    2 s, not 6;
  - two subagents `graph_write` different nodes at the same moment: both nodes
    are in `graph_digest` afterwards;
  - two subagents click the same tab: the fixture page receives the clicks in
    sequence, never interleaved; on two different tabs they overlap;
  - an agent call plus a browser tool in the same turn do not overlap.
  Undo each fix in the built bundle and confirm its check fails, as was done for
  stream-liveness.
- The unit test for concurrent graph writes exists:
  `tools/picker/tests/graph.test.js`.
- The full suite, `node tools/run-browser-tests.cjs`. It needs the local DVWA:
  `docker start cert-x-dvwa`, and stop it afterwards. The DVWA rehearsal covers
  the subagent resume path. Run it once before your change as a baseline: its
  last run on `7ed96cc` was stopped because the machine ran low on memory.
- Rebuild production afterwards: `background/background.js` must contain no
  `globalThis.kiTest`. A live comparison of batch wall time is a session the user
  runs.

## 2. Clearer 404 message (small)

Done 2026-10-27: swaps after "Same rule when the provider answers 404" in
`apply-picker.js` plus `kiModelUnavailableText` in `ki-provider-compat.js`. A
manual `/compact` that gets a 404 no longer switches models either. Tested by
`tools/picker/tests/model-404.browser.cjs` (turn and compaction).

- In `7ed96cc` the vendor's 404 model recovery is off. In `apply-picker.js`,
  search for "Same rule when the provider answers 404". That recovery cleared
  the saved default model and re-sent the conversation to another model on any
  connection. The provider's raw 404 now reaches the user as
  `APIModelUnavailableError`. It is accurate, but it doesn't say what to do.
- Wanted: "Model X isn't available (provider said: …). Pick another model in the
  model menu." Per the AGENTS.md error contract, it is a user action.
- Where: the 404 becomes that error in the llm factory's generate wrapper
  (search `new rE(e.message,e.requestId)`); the wrapper also builds the llm with
  the model name. Check variable shadowing in the minified code before using it.
- Test: the mock provider answers 404 on chat/completions. The panel message
  names the model and the model menu, no other model is called, and
  `sidepanel_last_model_v2` is unchanged.

## Rules that bite

- `swap()` anchors must be unique, and the build refuses a bundle whose top scope
  binds a name twice (`tools/picker/scope-check.mjs`). Name new top-level
  helpers `ki*`.
- Unit tests: the command in AGENTS.md (735 passing at `7ed96cc`).
- Background on why streams and subagents failed before `7ed96cc`: its commit
  message, and `tools/picker/tests/stream-liveness.browser.cjs`.

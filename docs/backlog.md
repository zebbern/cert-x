# Backlog — honest open items

Ordered by expected value, not by age.

1. **Parallel subagents** — a batch of subagents runs one after another (about
   54 of 60 minutes in BugStore run 2). Cause, plan, the safety fixes it needs
   (graph writes done 2026-10-28), and tests: `docs/handoff-parallel-subagents.md`.
2. **Mimosa scanning**: exclude generated bundles (`background/background.js`,
   `chunks/*`) from line-level diff scans — their line numbers shift every
   rebuild and produce phantom findings. Scan `tools/picker/src/`,
   `security/`, `providers/` instead. Blocked 2026-10-27: Mimosa is no longer
   installed (no hook, plugin or binary; its last run in `.mimosa/` is from
   2026-10-25), so there is no config to change. Do this when it is
   reinstalled.
3. **Knowledge graph, smaller open items** (found by the 2026-10-28 review,
   not fixed): when observations are not what makes a graph big, the 2 MiB
   cap still drops all of them and saves above 2 MiB (the result now reports
   the count); a failed `kiContextResolve` sends a write to `chat:<owner>`
   instead of the shared `ws:<id>` graph; nodes written without ids are not
   matched by kind and label, so re-run recon duplicates them; digest
   suggestions match triggers as raw substrings ("id" matches "/guide");
   nodes saved before 2026-10-28 with slash or space ids can be read but not
   updated; there is no way to remove one node short of `reset`.
4. **omnigraph**: deferred until graph-query volume justifies a real graph
   engine; the embedded graph has not been a bottleneck in any session.

Closed 2026-10-28: `tools/picker/tests/graph.test.js` (21 tests; Mimosa,
which blocked writing it, is gone). Writing and reviewing it found graph bugs,
now fixed: concurrent writes lost each other's (across workspaces too); one
failed storage read made the next write erase every graph; node ids that
edges could never use; the 500-node bound counted updates; reset dropped the
nodes sent with it; updates without data wiped stored data; duplicate edges;
eviction dropped the wrong observations; `graph_find` traversals and id
lookups returned up to 50 unrelated nodes plus 10 playbooks, could push the
requested node past the limit, and answered unknown ids with an empty result.

Closed 2026-10-24: provider-refusal surfacing (named errors, unit-tested);
subagent auto-resume (oP retries once via durable state, proven by
stream-kill injection in the DVWA rehearsal); download failures (diagnosed
working-as-intended — clear HTTP errors on genuinely failing URLs — plus
network errors now name the URL); lifecycle flake (deterministic
condition-waits, 4/4 solo + 15/15 full battery); FIXME limits (read cap
raised 128→512 KiB against the 900 KiB frame ceiling; foreground/job/save
caps each carry their stated reason).

Reopened and closed 2026-10-26: the lifecycle flake returned (8/8 failures in
one window). Two root causes, found by reproducing under full CPU load: a live
DAST event overtaking the adoption replay failed it with
`dast_runtime_event_cursor_gap` and lost the interrupted scan's evidence (a
product bug, also seen unloaded), and the test restarted the worker before the
executor had saved a request record. 15/15 after the fixes (10 normal, 5 with
every core saturated). Same day: Page.handleJavaScriptDialog no longer queues
behind a debugger command the dialog itself blocks (it waited out the 300 s
CDP timeout after a click whose handler alerted).

# Backlog — honest open items

Ordered by expected value, not by age.

1. **Parallel subagents** — a batch of subagents runs one after another (about
   54 of 60 minutes in BugStore run 2). Cause, plan, the safety fixes it needs
   (graph writes done 2026-10-28), and tests: `docs/handoff-parallel-subagents.md`.
2. **Fast mode, steps 3-4** (plan agreed 2026-10-26; step 1, the highlight and
   ref guard, and step 2, `browse(goal)`, are done): step 3 ranks and flags
   tool results with TypeSafe (`graph_digest` frontier, batch probe triage,
   scanner candidates) and never drops them; step 4 is an optional fast model
   for subagents through the existing OpenRouter connection, shipped only
   after an A/B.
3. **browse(goal) limits**: `<select multiple>` options are offered as click
   targets, so they do not get selected; iframe and shadow-DOM content is not
   read. Adoption, measured 2026-10-26 with the [Fast browse] prompt line and
   the snapshot hint: mimo-v2.6-pro chose `browse` in 9 of 14 tasks (median
   10.1 s vs 24.9 s with it off); Sonnet 5.5 in only 2 of 14 (it batches
   fills itself; about 9 s either way).
4. **Failed subagents keep no partial work**: the failure envelope carries
   none of it; only what the subagent wrote with `graph_write` survives.
5. **Knowledge graph, smaller open items** (found by the 2026-10-28 review,
   not fixed): when observations are not what makes a graph big, the 2 MiB
   cap still drops all of them and saves above 2 MiB (the result reports the
   count); a failed `kiContextResolve` sends a write to `chat:<owner>`
   instead of the shared `ws:<id>` graph; nodes written without ids are not
   matched by kind and label, so re-run recon duplicates them; digest
   suggestions match triggers as raw substrings ("id" matches "/guide");
   nodes saved before 2026-10-28 with slash or space ids can be read but not
   updated; there is no way to remove one node short of `reset`.
6. **Mimosa scanning**: exclude generated bundles (`background/background.js`,
   `chunks/*`) from line-level diff scans — their line numbers shift every
   rebuild and produce phantom findings. Scan `tools/picker/src/`,
   `security/`, `providers/` instead. Blocked (checked 2026-10-29): Mimosa
   1.0.4 is installed only as a zcode CLI plugin, not in Claude Code, and
   `.mimosa/` has no runs since 2026-10-25. Its README documents no per-repo
   exclude (it skips only files over 2 MB or that look binary; every bundle
   is smaller), and its engine is sealed, so whether one exists is
   unconfirmed.
7. **Load-only test failures** (low value): three tests fail only under
   stalls far beyond realistic load — `tools/picker/tests/context.test.js`
   (20 s), `tools/ptk/authz-transport.test.mjs` (10 s) and the IAST taint-TTL
   test in `tools/security/tests/runtime-iast-propagation.test.mjs` (10 s).
8. **Test harnesses assume one machine**: `PLAYWRIGHT_MODULE` defaults to a
   developer-specific global npm path, so other machines must set it.
9. **BugHunterz and Shodan integrations**: follow-up work, not started
   (moved here from the README).
10. **omnigraph**: deferred until graph-query volume justifies a real graph
    engine; the embedded graph has not been a bottleneck in any session.

Closed 2026-10-29: the unit suite hung on a machine without Chromium build
1234, which 88 test files hard-coded (a Playwright update had replaced it), and
a failed launch in `providers/authz.test.js` and `providers/security.test.js`
left their fixture server holding the run open. Tests now launch the newest
installed build (`tools/chromium-path.cjs`; `CHROMIUM_PATH` still overrides)
and start fixtures after the launch: 763/763 with no `CHROMIUM_PATH`, and a
missing browser fails in about 1 s instead of hanging. The build the test
Playwright module ships with (1212, Chromium 146) is too old: on it the macro
and port-probe checks fail and the CSP check timed out; 1248 (Chromium 156)
passes them.
Same day: `local_read_file` says 512 KiB per call like the host,
`save_as_pdf` says it saves to Downloads, and the browser runner points at
this backlog instead of a deleted `HANDOFF.md`.

Closed 2026-10-28 (a311f71, 46cde53): the unit suite's rare failure (1 of
760) and its hang. `tools/host/jobs.js` reported a job completed before
collecting its declared outputs; `tools/host/tests/host.test.js` hung the
whole run when a test failed mid-command (node:test skips later `t.after`
hooks once one throws, and removing the temp dir threw EPERM because Windows
will not delete a live process's working directory); 10 more races that
failed tests only under CPU load wait on conditions or carry bounded timeouts.
Reproduced with 34 busy loops (suite about 10x slower) or an injected stall;
763/763 twice after. Same day: cancelling a command left the children it
started during taskkill's ~700 ms window running (orphans 3 of 3 times
before, 0 after; the new host test fails 3 of 3 on the old code, with 5-6 of
about 17 children surviving). The cost is a kill of about 1.5-2.5 s.

Closed 2026-10-28: `tools/picker/tests/graph.test.js` (21 tests; Mimosa,
which blocked writing it, does not run in Claude Code). Writing and reviewing
it found graph bugs, now fixed: concurrent writes lost each other's (across
workspaces too); one failed storage read made the next write erase every
graph; node ids that edges could never use; the 500-node bound counted
updates; reset dropped the nodes sent with it; updates without data wiped
stored data; duplicate edges; eviction dropped the wrong observations;
`graph_find` traversals and id lookups returned up to 50 unrelated nodes plus
10 playbooks, could push the requested node past the limit, and answered
unknown ids with an empty result.

Closed 2026-10-24: provider-refusal surfacing (named errors, unit-tested);
subagent auto-resume (oP retries once via durable state, proven by
stream-kill injection in the DVWA rehearsal); download failures (diagnosed
working-as-intended — clear HTTP errors on genuinely failing URLs — plus
network errors name the URL); lifecycle flake (deterministic
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

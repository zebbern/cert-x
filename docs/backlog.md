# Backlog — honest open items

Ordered by expected value, not by age.

1. **`tools/picker/tests/graph.test.js`** — behavior verified inline but the
   security scanner persistently blocks writing the file (false-positive SQL
   findings on content with no SQL). Whitelist the path or paste the file
   from the 2026-10-23 session log.
2. **Mimosa scanning**: exclude generated bundles (`background/background.js`,
   `chunks/*`) from line-level diff scans — their line numbers shift every
   rebuild and produce phantom findings. Scan `tools/picker/src/`,
   `security/`, `providers/` instead.
3. **omnigraph**: deferred until graph-query volume justifies a real graph
   engine; the embedded graph has not been a bottleneck in any session.

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

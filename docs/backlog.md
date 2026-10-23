# Backlog — honest open items

Ordered by expected value, not by age.

1. **Surface provider refusals.** A `content_filter` refusal currently reads
   as "turn interrupted". Investigated 2026-10-23: refusals arrive in the
   response stream inside the minified provider layer — a picker-source shim
   cannot reach them without fetch-body interception, which is invasive for
   all model traffic. Deferred because the primary setup (MiMo) is unaffected;
   revisit if Anthropic models become the default. See `docs/provider-notes.md`.
2. **Subagent stream resume.** The graph-checkpoint recovery envelope works
   live (runs 4–5 of the M4 baseline); the deeper fix resumes the subagent
   thread itself instead of re-delegating with a digest brief.
3. **`download` tool failures under subagent use** (18 in one run, always
   self-recovered via in-page `evaluate`). Diagnose the failure mode; it may
   be the cheapest remaining reliability win.
4. **`security lifecycle` browser test is timing-flaky under load** — three
   different assertions across identical-code runs, majority passing. The
   browser-test runner output notes it.
5. **`tools/picker/tests/graph.test.js`** — behavior verified inline but the
   security scanner persistently blocks writing the file (false-positive SQL
   findings on content with no SQL). Whitelist the path or paste the file
   from the 2026-10-23 session log.
6. **`FIXME(justified-limits)` markers** in `tools/host/*`: verify or raise
   the unverified caps (128 KiB reads, job duration defaults, save_file
   8 MB, concurrency counts).
7. **Mimosa scanning**: exclude generated bundles (`background/background.js`,
   `chunks/*`) from line-level diff scans — their line numbers shift every
   rebuild and produce phantom findings. Scan `tools/picker/src/`,
   `security/`, `providers/` instead.
8. **omnigraph**: deferred until graph-query volume justifies a real graph
   engine; the embedded graph has not been a bottleneck in any session.

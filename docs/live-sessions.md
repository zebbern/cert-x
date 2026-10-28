# Live autonomous sessions

How to run cert-x end-to-end against a practice target with a real model,
unattended. Session evidence stays local in
`tools/security/evidence/m4-live-baseline/` (gitignored, since transcripts of
live runs don't belong in a public repo; see `INDEX.md` there).

## Runner

```text
OPENROUTER_API_KEY=... M4_MINUTES=40 M4_MODEL=xiaomi/mimo-v2.6-pro \
  node tools/picker/tests/m4-live-session.cjs
```

- Loads the extension in an isolated Chromium profile, configures an
  OpenRouter connection pinned to `M4_MODEL`, logs into the target, selects
  the Bug bounty profile, sends one instruction, then only watches — no
  model behavior is scripted.
- `M4_MINUTES` is a **test-only** timebox. The product has no time window;
  at 60% of the box the runner steers a wrap-up through the same mid-run
  message channel any human user has. **Scale the box with scope** — a
  single target finishes naturally in ~25 min under 60% steering; a
  dual-target session exceeded 35 min and lost its final report to the
  clock (work was complete; the report was mid-generation at expiry).
- `M4_ORIGIN2` adds a second target tab in the same workspace — the
  cross-target map scenario (validated 2026-10-24: parallel recon
  subagents, one shared graph, orchestrator holds the hypothesis ledger).
- Captures per run: model request bodies (full conversation history), the
  panel transcript, and tool telemetry (`C:/tmp/m4-*`).

## Targets

- **Local DVWA**: Docker container `cert-x-dvwa` at `127.0.0.1:4280`
  (admin/password, security Low). Agent sessions can change the admin
  password while testing brute force/SQLi; the runner self-heals by resetting
  the DVWA database via `setup.php`, which restores default credentials.
- **pentest-ground.com**: free, no account, instances rebuilt every 30
  minutes, other users scan concurrently. GraphQL app `:5013` and RestFlaw
  `:9000` verified alive 2026-10-23; hosted DVWA had blank DB credentials
  that day. Re-check liveness at session time.

## Reading results

- `telemetry.calls` — tool adoption; `telemetry.errors` and `afterError` —
  recovery-loop cost (via `get_capabilities` or the captured storage dump).
- The fullest captured request body contains the whole conversation; the DOM
  transcript contains the final report.

## First real session (your browser)

Five minutes of setup, then the same shape as every evidence run:

1. Reload the extension (`chrome://extensions`).
2. **Settings → Models**: your OpenRouter connection needs the models in its
   `modelIds` list (e.g. `xiaomi/mimo-v2.6-pro`); pick it as the model.
3. **Settings → Workspaces**: create one for the program. Put the program's
   **scope and exclusions in the workspace notes** (origins in scope,
   out-of-scope paths, rate expectations) and the testing scope origins —
   scans and replays are refused outside those origins, and the agent treats
   written limits as binding.
4. Open the target logged in as the intended account, select the Bug bounty
   profile and the workspace, and give one instruction: what to test, "work
   findings to proof, report each one with the invariant."
5. Watch the transcript; steer mid-run like any chat. Afterwards,
   `get_capabilities` → `telemetry` is the session scoreboard.

Note: the runner's timebox and wrap-up steering are test-harness only — a
real session has no clock; the model works until it reports.

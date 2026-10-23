# Live autonomous sessions

How to run cert-x end-to-end against a practice target with a real model,
unattended. Session evidence lives in `tools/security/evidence/m4-live-baseline/`
(see `INDEX.md` there).

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
  at 75% of the box the runner may steer a wrap-up through the same mid-run
  message channel any human user has.
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

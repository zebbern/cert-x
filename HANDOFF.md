# Handoff: three pre-existing engine test failures

Date: 2026-10-23. Owner: engine/security-service lane.

Three real-browser security tests fail on the current tree. They fail
**identically on commit `1ed391e`** (the 05:00 backup, before the M1/M2
picker-side work), verified by worktree rebuild + rerun — they are not caused
by commits `d3f0029`/`e9eaf28`/`5384cc9`/`5f90786`.

## Failures

| Test | Assertion | Symptom |
| --- | --- | --- |
| `tools/security/tests/browser-smoke.cjs` | "Combined stop must reach a confirmed terminal state" (line 47) | SAST/SCA scan `stop` returns `state: "incomplete"`; engineStatus still `running` |
| `tools/security/tests/utilities.browser.cjs` | `capabilities.operations.includes('utility')` falsy (line 38) | `security_capabilities` operation list does not include `security_utility` |
| `tools/security/tests/lifecycle.browser.cjs` | expected `'completed'`, actual `'incomplete'` (line 30) | Same terminal-state issue via lifecycle path |

Repro (each exits non-zero):

```text
node tools/security/tests/browser-smoke.cjs
node tools/security/tests/utilities.browser.cjs
node tools/security/tests/lifecycle.browser.cjs
```

## Why these went unnoticed

These `.cjs` browser tests are not matched by the default
`node --test ... tools/security/tests/*.test.mjs` glob and have no runner, so
they silently skip in every normal validation pass. Consider adding them to a
runner script so red stays red (after fixing).

## Context for the fix

- The default unit suite is green (709/709) and the other real-browser checks
  pass (contexts-ui, csp-ui, dast-real, dast-coverage-real, iast-real,
  authz-real, ui.browser, browser-parity, runtime-browser-dast, native-test,
  browser-control-ui-test).
- Likely area: scan stop/drain logic in `security/service.mjs` and the
  capabilities operation list assembly (`kiSecurityToolDefs` gating or
  `service.describe`), not the picker patches.

Delete this file once all three pass.

# M4 runbook — the proof demo

The bar (AGENTS.md): cert-x demonstrates an exploitable path — weaknesses
chained the way an intruder would, proven with the finding invariant — that a
conventional scanner would not have found. This file is the procedure; delete
it after the demo.

## Targets

- **Primary: local DVWA** at `http://127.0.0.1:4280` (Docker `cert-x-dvwa`,
  restart policy set; admin/password; security Low). Deterministic, rehearsed
  end-to-end (`tools/picker/tests/dvwa-rehearsal.cjs`).
- **Secondary: Damn Vulnerable GraphQL** at
  `https://pentest-ground.com:5013` (verified alive 2026-10-23; free, no
  account, explicitly for scanning practice). Different attack class —
  introspection, query injection. RestFlaw REST API at `:9000` is the
  alternate. Hosted apps redeploy every 30 minutes and other users scan
  concurrently; re-check liveness at session time
  (`curl -sk https://pentest-ground.com:5013/`).
  Hosted DVWA (`:4280`) had blank database credentials at last check — skip it
  unless a redeploy fixed it.

## Setup (5 minutes)

1. `chrome://extensions` → reload cert-x (many new commits since last load).
2. Settings → Workspaces → create **M4** with testing scope origins
   `http://127.0.0.1:4280` and `https://pentest-ground.com:5013`, Bug bounty
   profile.
3. Log into DVWA in a normal tab (admin/password). Open the GraphQL app in
   another tab.

## The session

One instruction:

> Test these targets. Map the surface first, orchestrate the recon, work
> findings to proof, and report each one with the invariant.

## What to judge

1. **Orchestration (M3):** raw enumeration stays out of the orchestrator's
   turns; subagents return summaries and references.
2. **Map-driven moves (M2):** next moves justified by `graph_digest` frontier
   and playbook suggestions, including across the two origins.
3. **Proof (the invariant):** every reported finding states "given
   [prerequisites], I demonstrated [unauthorized action] across [security
   boundary], producing [observable effect]" — no bare CVSS-style listings.

Then: `get_capabilities` → `telemetry.calls` (tool adoption),
`telemetry.errors` / `afterError` (recovery-loop cost). Save those numbers —
they are the session's scoreboard and the evidence for what gets built next.

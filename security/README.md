# Security testing

The maintained security subsystem starts inside cert-x. Users install one extension; no PTK companion, pairing key, or native-host reinstall is required for browser testing. The implementation derives from the supplied PTK 10.0.0 source and retains its license and dependency notices. `provenance.json` records original file hashes; it is provenance, not a claim that maintained files remain unchanged.

The optional managed local backends require the updated native host. Open **Security testing → Local runtime & connections** to set up isolated browsing, callbacks, or ZAP after updating the host from Local computer settings. Setup uses pinned components and is explicitly user-triggered. See [advanced verification](advanced-verification.md) for implemented features and remaining gaps; the complete advanced plan is not yet fully delivered.

When upgrading from the companion setup, disable that separate PTK extension, reload cert-x, and reload pages to replace old instrumentation. The migration does not change the installed companion or its data automatically.

## Use

Choose the Bug bounty profile, open **Security testing**, select the target and engines, and start. The agent can also use the structured `security_*` tools. Capture and browse meaningful application workflows; check instrumentation readiness before relying on IAST. Stop observation when finished and inspect findings, evidence, coverage and errors. Exported reports enter the existing chat/workspace Outputs tray.

**Thorough** uses COMPREHENSIVE strategy and wide native scan controls. **PTK defaults** retains SMART/safe baseline behavior for comparisons. Both initially use 5 requests/second, concurrency 3 and planning concurrency 2. Advanced settings expose native options, optional total request/time budgets, workspace defaults and explicit user limits. Preferences can be overridden per run; explicit user limits remain binding, including across subagents. An absent total budget means no added total cap, not unlimited browser resources.

The inherited `ptk` permission-group identifier remains stable so existing profiles and overrides survive. Its UI label is **Security testing**. Full access follows the existing permission engine; Always ask and Disabled remain effective. Management runs through the trusted cert-x adapter. Imported popup/page-management message routes are disabled; content instrumentation remains a source of observations, not privileged control.

Saved account snapshots supply verified headers/cookies for DAST and replay. IAST/SAST/SCA observe an actual browser session, so choose a tab signed into the intended account. A saved header snapshot does not create an isolated browser identity for JavaScript, local storage, or service workers. Account comparisons use the existing verified-identity/evidence workflow; their wire transport remains serial because simultaneous credential overrides for the same URL would mix accounts.

The cookie/session utility supports list, set, remove, block, readonly, unset, and listpolicies. Results contain cookie metadata; retained values stay in private storage. Explicit block/readonly policies persist and are revalidated against their owner's current permissions and scope. Cookie identity includes domain, path, store and partition. Browser cookies are shared across ports and can cover subdomains; a cookie policy is not a per-tab or network sandbox. `security_clear_cookie_policy` can clear an owned policy after permissions or workspace scope change.

Reports export as JSON, Markdown, or native technical/executive PDFs through Outputs. Supporting utilities include native JWT operations, codecs, browser timing probes, technology reconnaissance, OpenAPI JSON/YAML inspection, HAR/API exploration, and workflow import/export. Imported external references remain references until an explicit scoped operation uses them.

## Ownership and recovery

Runs and retained results belong to a chat, with workspace aggregation preserving that source. Subagents inherit parent ownership, configuration and limits. Browser debugging, request rules and offscreen work have separate resource ownership. Stopping a scanner cannot detach the agent or delete manual CSP controls.

Completed and partial evidence is persisted. On worker restart, active runs are marked interrupted and are not automatically replayed. Old companion records remain historical; previously exported files stay available, but the new runtime cannot recover evidence that existed only in the old extension's memory. Installing this version does not uninstall another extension.

The engine can perform HTTP/browser testing supported by its native transports. Raw TCP/request-smuggling transports, arbitrary WebSocket frame testing and a server-side DNS/HTTP callback service are not supplied by a browser-only installation. Browser-observed callback traffic is not proof of server-side OAST. Port timing probes report timing observations, not confirmed TCP port state. Missing implementations and dependencies must remain visible in capabilities and coverage.

Ordinary replay supports scoped redirects and the browser's normal HTTP/2 negotiation. PTK's special HTTP/2 browser-helper path reports an explicit error when following a redirect would bypass per-hop admission; it does not silently follow that redirect.

## Build and verification

`node tools/picker/apply-picker.js` validates the packaged module graph and capability inventory, then rebuilds cert-x's generated bundles. Normal builds use maintained files in this checkout; they do not read inspiration folders or fetch moving upstream data. `tools/security/import.cjs` is a guarded one-time provenance import, not the normal build.

`capabilities.json` separates executable modules from metadata-only entries. Its verification fields must be updated only from recorded tests. Copying a rulepack, a matching module count, or a successful start does not establish detection parity.

Run unit/contract tests with `node --test tools/security/tests/*.test.mjs tools/ptk/*.test.cjs tools/ptk/*.test.mjs`, and real Chromium checks plus the source-only build check (`clean-build.cjs`) with:

```text
node tools/security/tests/browser-smoke.cjs
node tools/security/tests/ui.browser.cjs
node tools/security/tests/utilities.browser.cjs
node tools/security/tests/lifecycle.browser.cjs
node tools/security/tests/isolation.browser.cjs
node tools/security/tests/reporting.browser.cjs
node tools/security/tests/runtime-browser-accounts.cjs
node tools/security/tests/runtime-browser-cookies.cjs
node tools/security/tests/runtime-browser-cookie-bridge.cjs
node tools/security/tests/browser-parity.cjs
node tools/security/tests/runtime-browser-dast.cjs
node tools/security/tests/clean-build.cjs
```

Browser tests use fresh temporary profiles and local application fixtures. `PLAYWRIGHT_MODULE` and `CHROMIUM_PATH` override the installed test runtime paths (Chromium defaults to the newest build Playwright has installed); the unit run's detector tests launch Chromium too. The parity harness copies the unmodified supplied v10 extension through `prepare-reference.cjs`, or accepts `PTK_REFERENCE_ROOT` pointing to such a copy. Set `PARITY_ENGINES` to select DAST, IAST, SAST, SCA, or comma-separated combinations. Original PTK and cert-x execute in separate profiles against identical fixtures. Reports are written to the OS temporary directory; source fixtures remain in the repository. Some harnesses leave the machine and are in neither list: `dvwa-live.browser.cjs`, `live-model.browser.cjs` and `dvwa-report-complete.cjs` make paid model calls, and the `*-public*` harnesses send bounded traffic to a public training lab only when their opt-in variable is `1`.

All reference paths are checked against the recorded source-tree digest in `tools/security/reference/baseline.json`, including environment overrides. A patched companion cannot serve as the oracle. The focused DAST differential fixture selects the original three reflected-XSS checks; it is not evidence of parity for every DAST module. Per-module detector tests and imported engine regression suites supply additional evidence. Baseline defects and intentional fixes require separate expectations, rather than normalizing away meaningful differences.

Selected-request compatibility remains for existing calls and cert-x's exact-input, Boolean/SSTI, and verified-account workflows. It uses the owned native modules and isolated transport. The main scan action uses the complete native engine; these focused workflows do not define its module coverage.

See [verification.md](verification.md) for the tested environment, observed results, and the boundary between module contracts and browser parity.

### Testing scope

In **Settings → Workspaces → Testing scope**, keep exact origins or enable **Include HTTP/S and ports on the same host**. **Include subdomains** appears once that is on. Excluded paths still apply. Without configured targets, each new operation uses its explicitly selected target; discovering a link does not silently add another host. Capabilities report the effective scope, and denied-target errors identify the URL and settings location.

### Reading execution coverage

The agent should keep scanning active while it browses relevant routes and submits forms. DAST consumes that application traffic and mutates the observed inputs. A page-only/header-only run does not cover the site's other forms and APIs. Wait for the current work to finish before stopping; retain unexercised routes as gaps.

`security_list_runs` recovers this chat's public run IDs. Use those for status, findings and candidate investigation; native engine session IDs are separate. `security_capabilities` exposes the actual public argument schemas and the loaded integration fingerprint. Security utilities require an `arguments.tool` selector; ZAP uses its own tool.

Thorough can start from an already-loaded page using a safe GET seed. PTK defaults waits for its original interaction prerequisite. A baseline alone, skipped probes or zero traffic does not establish a clean DAST assessment. Status separates application observations, tasks, baselines, probes, errors and skips.

SCA separates captured HTTP bodies from already-loaded executable script text, including scoped same-process and cross-origin child documents. URI/filename matches alone do not prove content analysis. Stop establishes a browser-protocol cut and drains relevant in-flight acquisition and analysis; timeouts preserve partial evidence and report the unresolved work. Inspect `coverage.scaAcquisition` and `coverage.actionableGaps` before concluding. Script and body counts may overlap.

SAST also analyzes owned preloaded client scripts. Its coverage distinguishes missing original HTML, unavailable scripts, and actual engine failures while retaining successfully analyzed findings. Browser SAST cannot read server-side application source. Preloaded SCA sources with zero newly captured bodies are not by themselves a failure.

The agent receives recovery steps for missing inputs, expired authentication, unavailable resources and incomplete drains. These steps also appear in exported reports. Repeating an unchanged failed start is not recovery: invalid target errors include `retryable: false`; an uncertain start's returned run ID should be inspected first. `tabId` is canonical; decimal-string IDs and the existing `tab` alias are accepted for compatibility.

**Scan options → Acquisition limits** contains per-resource bytes, total acquired bytes, loaded-script count and drain time. Defaults are 8 MiB, 32 MiB, 128 scripts and five seconds. Preferences resolve through global → workspace → explicit run values. **Your limits** sets user ceilings that a run cannot raise. Memory preferences remain within the shared capture platform caps (8 MiB per resource, 32 MiB per tab); scripts can be configured up to 4,096 and drain time up to 60 seconds. Lowering an explicit acquisition ceiling stops an incompatible active SCA run and retains its evidence. No native-host reinstall is needed for these changes.

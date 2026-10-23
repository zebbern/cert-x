# Native security verification

These results apply to the local Windows checkout tested with Node 24.20.0 and Chromium 151.0.7922.34. Browser checks use isolated temporary profiles and resettable local fixtures. They do not establish CI results or universal finding parity on arbitrary applications.

Final maintained contract/regression run: **516 passed, 0 failed, 0 skipped** using the root README's `node --test` command. Separate browser suites and the combined four-engine workflow passed. The standalone source-copy build passed twice with identical output; `git diff --check` passed.

## Reference and coverage

The independent oracle is the unmodified supplied PTK 10.0.0 source: 1,465 files, SHA-256 tree digest `901619844a281628f9dc9eb17ff978cc3498cf05b9548cea15808c706c42c581`. The harness validates that digest before accepting either a copied reference or `PTK_REFERENCE_ROOT`. The original inspiration directories are not build inputs and remain unchanged.

The owned inventory contains 23 DAST modules, 11 CVE modules, 11 SAST modules, and 20 IAST modules. Every executable module has a positive/negative detector disposition. This covers detector execution, not every payload, environment, browser hook, or combination of options. `capabilities.json` records the test level and evidence files individually. Metadata-only entries remain distinct from executable code. The v9.9.9 source comparison found no additional local non-UI implementation, module, attack, or rule IDs requiring a backport.

Observed differential browser results under matched settings:

| Fixture | Original PTK | Native cert-x | Negative control |
| --- | --- | --- | --- |
| SAST taint/pattern fixture | 3 findings | 3 findings | 0 / 0 |
| SCA vulnerable dependency | 6 findings | 6 findings | 0 / 0 |
| IAST SMART fixture | 1 finding | 1 finding | 0 / 0 |
| DAST reflected XSS, original checks 1–3 | 1 finding | 1 finding | 0 / 0 |
| AngularJS browser confirmation | execution observed | execution observed | no execution |
| SPA DOM XSS browser confirmation | execution observed | execution observed | reflection candidate only; no execution |

Comparisons retain meaningful finding/evidence differences. The SPA negative case is deliberately recorded as a reflection observation because the baseline produces a candidate without execution proof. It is not relabelled as confirmed XSS.

The independent DAST contract comparison additionally covers all 34 modules and 158 prepared attack definitions, with 246 positive/negative request-mutation cases and 246 validation/evidence comparisons across the 31 HTTP-fixture modules. Request targets, payloads and metadata match with deterministic nonce/UUID generation. One expected difference remains: the maintained cache/privacy validator detects the characterized nested-constant case missed by the original. Its negative controls still match. JWT, AngularJS and SPA execution have separate specialized tests.

## Functional and regression checks

- Native installation: only cert-x installed; SAST/SCA and combined DAST/IAST/SAST/SCA starts/stops, evidence, all-engine JSON export, output ownership, cross-chat denial, and debugger coexistence. Set `SECURITY_SMOKE_ENGINES=all` for the combined check; it selects XSS to keep active probe work bounded.
- Actual agent conversation: browser attach/fill/click with Thorough IAST; instrumentation readiness, real script execution evidence, safe controls, scope exit, revocation, stop/drain, and export. The settings overlay retains the same chat and profile.
- Requests and identities: replay methods/bodies/headers, per-hop scope, budgets, error evidence, saved/anonymous account headers and cookies, unchanged ambient identity, and the existing account comparison matrix.
- Supporting tools: capture, macros, import/export, JWT operations, codecs, reconnaissance, timing probes, OpenAPI JSON/YAML parsing, and native reports. JSON/Markdown and both PDF styles were downloaded; PDF text and rendered pages were inspected.
- Cookie policies: actual privileged settings bridge, production approval grant, private persistence, browser restart, exact domain/path/store/partition identity, cross-owner denial, revocation, removal after workspace movement, and unavailable private-store refusal.
- Worker recovery: completed SAST evidence survives exactly; active SAST/DAST runs become interrupted. Surviving DAST request evidence retains its original automation-session and scan IDs. Old probes stop, a fresh scan starts, and no state-changing request is replayed automatically. Failed cleanup still reports an error.
- Existing integrations: native commands/files/jobs, local and remote MCP, Browser control, profiles/workspaces/model precedence, permission rules, manual CSP control, and legacy DAST/account extensions.
- UI: keyboard-accessible controls, persisted settings, dark 420px and light 720px layouts, no horizontal overflow, concise collapsed advanced controls, and neutral switches.
- Packaging: source-only temporary checkout without dependencies, inspiration folders, or companion configuration; two normal builds produced byte-identical bundles. The packaged static module graph is validated on every build.

## Characterized baseline defects

Focused regressions cover nested JsonLogic metadata constants in cache/privacy checks, comprehensive IAST propagation reentrancy, response-header correlation during redirects, worker resource URL rebasing, and ignoring unrelated extension ports in the imported offscreen document. These are explicit maintained changes, not differences removed by parity normalization.

## Limits of the evidence

Representative browser parity plus per-module contracts does not prove exhaustive end-to-end parity for all PTK mutation paths or every possible application. No live external targets or unavailable remote premium services were used. Browser transport cannot supply raw TCP/request-smuggling, arbitrary WebSocket frames, or server-side OAST verification. Timing probes are observations, not confirmed TCP state. The special HTTP/2 helper refuses redirects that cannot pass per-hop admission; ordinary scoped replay supports redirects.

Source fixtures, contract tests, the pinned reference digest, and characterization expectations are retained so remaining differences can be reproduced and investigated without trusting a patched companion.

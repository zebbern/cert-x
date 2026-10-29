# Expanded browser parity evidence

These fixtures use isolated Chromium profiles and the hash-verified, unmodified PTK v10 source (`901619844a281628f9dc9eb17ff978cc3498cf05b9548cea15808c706c42c581`). Payloads are inert HTML/text markers. Script collection fixtures are local, and their cookie value is the synthetic `parity_session=local-fixture`. No user browser data or credentials are present.

## Current result

Messaging and the named frame gaps are resolved and tested. The historical failures and rejected hypotheses below remain as an audit trail; they are not the final status.

- `collection-parity-message-timing.json`: original early-handler first0/repeated1, owned first1/repeated1; both late-handler first1. It records the agent's loaded/authorized state when each application listener was registered.
- `iast-existing-message-diagnostic.json`: both runtimes fully ready before the first event; existing bubble callback precedes a later capture callback. Capture phase alone did not fix the ordering.
- `iast-existing-message.json`: the maintained native `MessageEvent.data` consumption hook passes first acquisition in an existing document while preserving string/object identity, descriptor/receiver behavior, application callback counts, safe controls and post-stop behavior.
- `iast-existing-oopif.json`: all 31 checks pass for existing/navigated allowed same-origin and OOPIF documents, immutable document IDs/no reloads, scope exclusions, permission revocation and independent debugger ownership.
- `collection-parity.json`: the nine-case matrix passes. First-event messaging and frame acquisition are explicit improvements over the reference; late-message/safe controls and authenticated SAST/SCA projections match.

The initial collection reader considered only canonical `evidence.iast.sources`. PTK keeps the first occurrence there and later occurrences in `samples`; this falsely made a later owned message appear to lack a source. `collection-projection.cjs` now selects the exact marker from canonical and aggregate sample records, retaining source kind and document location. A focused unit test and replay of the stored failure establish this correction. `collection-parity-primary-only-projection.json` preserves the failed reader output; `collection-parity-pre-timing-resolution.json` preserves the earlier strict comparison. No raw evidence was discarded to make the comparison pass.

Production API references: [Chrome debugger child sessions](https://developer.chrome.com/docs/extensions/reference/api/debugger), [scripting injection targets](https://developer.chrome.com/docs/extensions/reference/api/scripting), and [navigation document identity](https://developer.chrome.com/docs/extensions/reference/api/webNavigation). These describe the APIs used; the local browser fixtures establish the observed product behavior.

## Completed: inert stored workflow

`stored-marker-collection.json` records matching original/owned wire sequences: exactly one state-changing submission each, subsequent GET retrieval, and real browser-harness checks through each implementation's `DastPrivilegedBrowserAdapter`. Both leave the marker unconfirmed; neither reports execution. No browser-harness failures remain. This establishes the inert negative path, not positive stored-XSS confirmation.

The first attempt, preserved as `stored-marker-missing-adapter.json`, retrieved the marker but could not inject the browser harness. Its original null-result interpretation was corrected after reviewing runtime errors. The fixture now fails on those errors; adding the actual production dispatcher fixed the test setup without changing either implementation.

Command: `node tools/security/tests/stored-marker-collection.browser.cjs` — passed.

## Historical strict parity failure: messaging acquisition

`collection-parity.json` is the corrected full collection run. Original PTK produced no observation for the isolated message marker, while cert-x produced `dom_innerhtml_xss` with source kind `postMessage`, sink `dom.innerHTML`, and the exact inert message value. The marker is absent from the URL, and fixture selection uses opaque codes that do not occur in marker values.

`collection-parity-message-isolated.json` repeats only messaging in fresh profiles. The same difference persists, excluding earlier async activity as its cause. Both browser commands exit with a failed strict equality assertion. The test was not changed to accept the extra finding.

The maintained content agent differs from the original in boxed-string taint lookup, propagation reentrancy handling, and packaged path filtering. Existing unit tests characterize the first two fixes, but this browser experiment does not causally attribute the messaging difference to either change. It remains an unresolved differential, not a declared intentional improvement and not proof of exploit impact.

### Bounded causal ablations

`iast-message-ablation.json` records two targeted interventions in temporary copies of the owned extension. Each variant replaces exactly one named function with its unmodified PTK implementation; production and inspiration files remain unchanged. Source hashes and strict test output are retained alongside full variant snapshots.

| Implementation | Message observations |
|---|---:|
| Unmodified PTK reference | 0 |
| Owned implementation | 1 |
| Owned, boxed-string lookup reverted | 1 |
| Owned, propagation reentrancy guard reverted | 1 |

Both variant parity assertions still fail on the same extra `postMessage → dom.innerHTML` observation. Neither individual fix is necessary for the difference under this fixture. This does not rule out interactions between changes or differences elsewhere in injection timing/runtime setup. No causal basis was found to declare an intentional differential expectation, so the strict regression remains failing. No third variant was run.

Diagnostic command: `node tools/security/tests/iast-message-ablation.cjs`. Its wrapper completed both experiments and verified the production source hash; the two underlying strict parity tests each exited with status 1. Wrapper completion is not a parity pass.

Commands:

- `node tools/security/tests/collection-parity.browser.cjs` — failed on messaging parity.
- `$env:COLLECTION_CASES='message'; node tools/security/tests/collection-parity.browser.cjs` — failed with the same differential.

## Historical observations from the corrected full run

| Path | Original | cert-x | Interpretation |
|---|---:|---:|---|
| Async query-to-HTML flow | 1 | 1 | Observation acquired in both |
| Full navigation, query-to-HTML flow | 1 | 1 | Observation acquired in both; aggregation retains source details in samples |
| Storage-to-HTML flow | 1 | 1 | Both `localStorage` and `sessionStorage` appear in source evidence |
| Same-origin iframe | 0 | 0 | No acquisition proved; this is a gap, not passing coverage |
| Safe `textContent` control | 0 | 0 | No candidate emitted for the safe control |
| Authenticated external/dynamic script SAST | 21 | 21 | Projected rule/module/source-URL results match |
| Authenticated dynamic dependency SCA | 6 | 6 | Projected results match for the filename/version fixture |

The script endpoints reject an unauthenticated request with HTTP 401. Recorded browser wire traffic proves authenticated external and dynamic script fetches. SAST findings identify both `/auth-external.js` and `/auth-dynamic.js`; SCA findings identify the dynamically loaded `/jquery-1.12.4.js` fixture. This validates collection/detection of the supplied fixture, not an actual vulnerable jQuery implementation or every authenticated loading mechanism.

The full command stops its assertions at messaging. SAST/SCA equality was additionally checked from the retained final snapshots, without repeating traffic. Their raw evidence remains in the full-run file.

## Preserved measurement corrections

- `collection-parity-query-confounded.json`: message/storage markers also appeared in the URL query, so the initial observations did not isolate those sources.
- `collection-parity-label-confounded.json`: removing the marker from the main query value still left readable case names matching marker substrings. Aggregated evidence exposed that confound.
- The corrected fixture removes both confounds and extracts nested `evidence.iast` source/sink fields. Prior trials remain available to explain the changes in methodology.

The initial parity expansion changed no production code. Positive stored execution and the cause of the messaging differential remain unverified. Frame coverage was subsequently addressed in the separately validated follow-up below.

Static inspection identified separate frame restrictions in the initial trials: upstream dynamic registration omits `allFrames` (defaulting to the top frame), immediate injection targets only `tabId`, and its Firefox fallback explicitly sets `allFrames:false`. The owned runtime replaced registration with CDP document-start injection, but that injected source returned when `window !== window.top`. Thus its initial frame absence was directly explained by its own top-frame guard, rather than inferred solely from upstream registration. The content bridge's `all_frames` setting does not itself inject the main-world instrumentation. The follow-up below removes that owned restriction while testing scope exclusions; matching zero observations in the initial trial was not treated as proof of frame coverage.

## Validated follow-up: scoped frame acquisition

The subsequent production change replaces the owned top-frame guard with the existing origin/path scope predicate, serialized by `security/engine/iast-bootstrap.mjs`. It retains scope authorization and permits document-start instrumentation in allowed frames.

`iast-frame-scope.json` records the independent original/owned comparison after that change:

- Original PTK: no marker observation in the same-origin frame.
- Owned runtime: one query-to-`innerHTML` observation for the inert same-origin marker.
- A same-origin safe `textContent` frame receives instrumentation but emits no marker finding.
- Foreign-origin and excluded-path frames have `agentLoaded:false` and emit no marker findings.

`iast-frame-stop.json` is an additional owned-only lifecycle check. After stopping the parent scan, navigating the allowed frame to a fresh marker yields `agentLoaded:false`; exercising the sink leaves the saved findings byte-identical. This run does not claim an additional reference comparison.

Both commands passed:

- `node tools/security/tests/iast-frame-scope.browser.cjs`
- `$env:FRAME_SCOPE_OWNED_ONLY='1'; node tools/security/tests/iast-frame-scope.browser.cjs`

The fixture creates/navigates frames after registration. It does not establish immediate injection into already-loaded frames. The original0 → owned1 frame result is now an explicit regression expectation in the broader collection test, justified by this scoped implementation change and its positive/negative/exclusion evidence. The unrelated messaging differential remains strict and unresolved.

## Existing documents and out-of-process frames: initial failures

`iast-existing-oopif-before-fix.json` records an actual `KI_SECURITY` run with frames loaded before scanning starts and site isolation enabled. CDP identifies the allowed `localhost` child frames as separate `iframe` targets while the parent uses `127.0.0.1`.

The current-at-test implementation passed 17 checks but failed six assertions covering three missing paths: existing same-origin injection/evidence, existing allowed cross-origin injection/evidence, and navigated allowed cross-origin injection/evidence. Navigated same-origin acquisition worked. Excluded-path/foreign-origin frames remained uninstrumented, the safe sink emitted no finding, and disabling permissions terminated observation without subsequent reinjection or new persisted evidence.

The first fixture trial (`iast-existing-oopif-initial.json`) attempted to call the findings tool after disabling its permission and correctly received a denial. The corrected inspector reads retained local evidence after revocation; it does not re-enable or invoke the disabled tool.

Required implementation paths identified from those results are scope-filtered immediate injection into existing frame documents and owned document-start registration in child renderer sessions, with cleanup that preserves other debugger consumers. The updated fixture also checks document IDs to forbid an automatic reload as a substitute for existing-frame injection, and maintains a separate browser-agent debugger owner across revocation. Those additional checks require the follow-up run; the initial 17/6 counts do not include them.

### Fixed implementation: all 31 checks pass

`iast-existing-oopif.json` is the subsequent passing run against the production document/child-session registration changes. The same strict fixture now passes all 31 assertions:

- Already-loaded same-origin and allowed cross-origin OOPIF documents receive instrumentation without changing their document IDs.
- Both allowed frames produce actual inert query-to-`innerHTML` evidence before and after navigation.
- The instrumented safe frame produces no finding.
- Excluded-path and foreign-origin frames receive no agent and produce no marker evidence.
- Disabling the real security permission terminates the scan. Newly navigated frames receive no agent, and retained findings remain unchanged.
- A separately owned browser-agent debugger session still executes `Runtime.evaluate` after IAST revocation.

Command: `node tools/security/tests/iast-existing-oopif.browser.cjs` — passed, 31 checks, zero failures. CDP recorded four separate iframe targets, including the explicitly allowed cross-origin renderer. Initial failure evidence remains intact. These results cover the named local frame configurations and permission transition; they do not establish every nested-frame, worker-restart, or cross-origin HTTP-correlation path.

## Historical existing-document trial: capture-phase change insufficient

`iast-existing-message-before-fix.json` installs the application's bubble-phase message listener before scanning, keeps the same document, then sends one unique inert HTML marker and a distinct safe `textContent` marker. Both the original and owned runtime recorded zero first-message findings. Both application callbacks ran exactly once, and neither document reloaded.

`iast-existing-message-capture-trial.json` repeats the unchanged fixture after the maintained postMessage source observer was changed to `{capture:true}`. It records original0/owned0 for the first marker, safe0 in both, exact callback counts, and unchanged document IDs. The strict owned first-message assertion failed. The capture-phase change alone did not establish acquisition; this historical trial motivated the diagnostic and getter fix below.

Command: `node tools/security/tests/iast-existing-message.browser.cjs` — failed before and after the capture-phase-only change. No assertion was relaxed and no additional payload type was introduced. This existing-document result is separate from the earlier document-start timing comparison.

### One bounded readiness/order diagnostic

`iast-existing-message-diagnostic.json` uses the same inert markers and retains the strict first-event assertion. It adds read-only hook-state snapshots before the first event, after it, and after one repeated HTML event. A separate harmless listener-order message runs only afterward, so it cannot prime the first-event test.

Both original and owned pages were authorized, provisional hooks enabled, agent loaded, and propagation enabled before the first event. Each reported 96 active rules, 20 active modules, enabled postMessage/HTML-assignment hooks, normal runtime health, and no hook-group failures at all three snapshots. Both missed the first HTML message and recorded the repeated message as `postMessage → dom.innerHTML`. Both safe controls remained negative; application callbacks ran exactly twice for the two HTML events and once for the safe event, without reload.

The separate ordering probe recorded `bubble-existing` before `capture-late` in both runtimes. Thus the later capture listener did not precede the existing application listener in this tested Chromium Window-message dispatch. Readiness and marker eligibility are supported by these observations; the result motivated instrumentation at first consumption instead of relying on listener order. Diagnostic command: `$env:EXISTING_MESSAGE_DIAGNOSTIC='1'; node tools/security/tests/iast-existing-message.browser.cjs` — strict first-event assertion failed, full raw states preserved. No production code was changed for the diagnostic.

### Getter-based first-consumption fix: passing strict regression

The maintained implementation now observes the native `MessageEvent.data` getter for actual Window message consumption, with authorization/hook checks, internal-message filtering, reentrancy protection and per-event deduplication. It returns the original getter's value and retains the delivery observer as a fallback. The ineffective capture-phase change was reverted.

The final `iast-existing-message.json` passes the unchanged first-acquisition criterion: original first0, owned first1 with source `postMessage` and sink `dom.innerHTML`. Both safe controls remain at zero. No document reloaded, and the two marker callbacks each executed exactly once. The normal fixture contains no auxiliary ordering listener that could prime the first message.

Additional native-contract assertions passed: strings and objects retain identical values/references relative to the getter saved before scanning; repeated accesses retain identity; descriptor flags are preserved; invalid receivers produce the same native `TypeError`; an actual object-message callback runs once. A fresh inert HTML message after stopping adds no scan evidence in either implementation.

Command: `node tools/security/tests/iast-existing-message.browser.cjs` — passed. This proves the named existing-Window first-consumption improvement and native getter contracts. It does not establish exploit impact or imply additional MessagePort/Worker getter instrumentation.

## IAST HTTP correlation: initial multi-origin scope gaps

`iast-http-scope-before-fix.json` records five ordinary browser GETs, all completed with HTTP 200, followed by a stopped-scan native export. Six of ten initial checks passed. The explicitly allowed secondary origin had no retained HTTP events or route record; an excluded path on the primary origin incorrectly had both webRequest and DevTools events plus a route record. Foreign-origin and secondary excluded-path controls were absent as expected.

The relevant filtering paths are independent: `onCompleted` compares URL host with `scanResult.host`, while the capture lease uses a single target-origin scope and sends request/response callbacks directly to `recordHttpEvent`. That final method originally checked only that the URL was HTTP. Thus changing only the webRequest predicate would not exclude DevTools records for the excluded primary path. Navigation correlation also occurred before the old host filter.

The strict fixture is `tools/security/tests/iast-http-scope.browser.cjs`. Its follow-up criteria additionally check that allowed route records identify the actual target host, rather than inheriting the primary scan host. This is metadata/route-correlation coverage using ordinary local responses, not active vulnerability testing or proof of secondary-origin authentication-body capture.

### Fixed implementation: all 12 HTTP scope checks pass

`iast-http-scope.json` is the passing rerun after shared context-scope validation was added to IAST correlation and capture admission. Both declared origins retain a DevTools request event, webRequest completion, DevTools response, and route record identifying the actual target host. Foreign-origin and excluded paths on both declared origins retain neither HTTP events nor route records. All five ordinary fixture requests still complete with HTTP 200, demonstrating that the exclusion checks govern scanner evidence rather than preventing the application traffic.

Command: `node tools/security/tests/iast-http-scope.browser.cjs` — passed, 12 checks, zero failures, with unchanged assertions. Results come from the stopped native scan export. `iast-http-scope-before-fix.json` remains intact. This fixture proves metadata correlation and exclusion for the named GET requests; it does not claim additional validation of authentication-response body/token processing.

## Stored execution follow-up

`stored-positive.json` retains original and owned planner/mutation/request/confirmation records for five cases: executing, escaped, inert-template retrieval, absent retrieval, and authenticated execution. All five match with two browser-execution positives and three negative controls. The fixture derives an executable rule from canonical XSS; the supplied premium stored-XSS entry remains metadata. See `../stored-positive-verification.md` for the exact normalization, scope and limitations. Earlier negative and failed trial evidence remains historical.

## Additional collection combinations and screenshot handling

`collection-combinations.json` records five original/owned cases: async storage HTML/text controls, object-message HTML/text controls, and authenticated SPA dynamic script/dependency collection. Positive async-storage and targeted SAST/SCA observations match; object-message and SPA-history IAST acquisition are absent on both sides despite rendered sinks. `collection-spa-fetch-trace.json` traces additional owned anonymous script reads to SCA resource replay; equivalent authenticated body collection remains unverified. See `security/advanced-verification.md` for interpretation and fixture limitations.

`iast-http-host-scope.json` passes 12 real network correlation checks with one declared seed host, an allowed second port, a foreign hostname, and excluded paths. `cdp-screenshot.json` records compact metadata and image counts from actual CDP and ordinary screenshot calls through the chat path; no image bytes are placed in the text evidence.

`collection-host-scope.json` verifies SAST/SCA source acquisition on a second port under explicit same-host scope and retains an excluded-script control fetched by the browser. It complements HTTP-event scope checks with actual detector execution.

## Acquisition and execution completion follow-up

`iast-acquisition-browser.json` and `collection-iast-acquisition-full.json` record the intentional improvements over the earlier object/history baseline: four positive source/sink observations, safe controls, actual sender/receiver provenance, native identity and inactive-after-stop behavior. The first through fourth failed trials remain available and are interpreted in the verification report.

`sca-authenticated-browser.json` records real AngularJS content detection at opaque authenticated resource URLs, matched against original PTK for A/B/anonymous. `sca-authenticated-verify.cjs` independently compares findings and retained locations. `sca-preloaded-browser.json` covers pre-existing executable sources without refetch and extensionless JavaScript Fetch/XHR bodies. These replace the earlier unverified body-acquisition status; HTTP bodies and Debugger text are distinct evidence types.

`dast-public-smoke.json` records the bounded user-authorized training-site check: one reflected-XSS rule, two baseline requests and one probe, three HTTP responses, zero findings. It establishes execution only. Local DAST fixtures provide resettable positive/negative and no-traffic controls. `cdp-screenshot.json` now also verifies a PDF Outputs artifact rather than raw base64 text.

## Child-frame acquisition and stop follow-up

`sca-frames-stop-browser.json` records real HTTPS root/nested/OOPIF acquisition with an already-active browser Runtime owner, sequential A/B/anonymous identities, immediate stop after Fetch/XHR loadend, and a configured one-script/75 ms timeout. A and B each acquire four preloaded sources and two response bodies; only A has Angular findings. Failed cookie, shared-Runtime, repeated-attachment and disable-filter trials remain in adjacent named files.

`acquisition-flow-browser.json` exercises the actual service/runtime/automation path: inherited resource ceilings survive partial run options and engine-options overrides, persist in history, and appear with incomplete coverage in the Markdown report. Separate `report-coverage.browser.cjs` checks both PDF styles and retained native findings. These are bounded fixture results, not exhaustive application coverage.


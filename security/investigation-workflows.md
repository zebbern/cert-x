# Investigation operations

`candidate` and `evidencePackage` require the originating security scan's `runId`. The service checks chat ownership before resolving the native session. Candidate analysis runs on a private snapshot of that scan, never the engine's latest global result. Responses include `sourceRunId`, `snapshotScanId`, and `snapshotId`. Passing `snapshotId` rejects stale selections. `recompute` explicitly refreshes from the same native scan when its live evidence is available.

Candidate operations reuse PTK's readiness, object-swap, response-diff, workflow-overlay, reproduction-job, evidence-package and report-draft services. `list`, `get`, `suppress`, `readiness`, `objectswap`, `compare`, `workflow`, `workflowReplay`, and `draft` are exposed. Readiness is offline unless `check:true`. Reproduction requires an explicit managed `browserSessionId`; no default browser identity is substituted. Poll or stop a reproduction with its `executionRunId` and `jobId`.

`compare` normally analyzes supplied baseline/comparison responses. With `execute:true`, it requires both verified private account references. Optional mutation uses an exact `{location,name,index}` selector and string replacement, preserving unrelated query/form/JSON bytes. Both requests share the operation's admission, scope and budget checks. A differing response remains comparison evidence, not automatic proof of unauthorized access.

Evidence packages persist privately and are isolated by source run. Package actions are `create`, `list`, `get`, `export` and `draft`; export supports JSON and Markdown. Captured authentication headers and resolved account credential values are removed from public investigation results while original private snapshots remain available internally.

## API operations

`api.import` accepts supplied OpenAPI/Swagger JSON or YAML and returns a private `specRef`. `describe` lists operations. `prepare` resolves an operation's required path, query, header, cookie and request-body values into an owned `planRef`. JSON, URL-encoded forms, multipart values and Swagger formData are supported. No required value is invented. External references require an explicit URL-to-document map and must fall inside the selected scope; importing never fetches them implicitly.

`execute` runs one plan; `batch` runs an explicit list of plan references. Every request uses native replay admission and optional saved-account context. Transport errors retain partial batch results and stop the batch. Recursive schemas requiring unresolved references need a finite explicit schema/value; serialization styles beyond the implemented form/simple/deepObject forms require a manually prepared request.

## Local backends

Managed browser, raw transport, OAST and ZAP operations delegate through the native security executor. Persistent handles retain their original service run, owner, workspace and admission lease. Subsequent calls carry the original operation `runId`. Browser follow-ups inherit only session identity; a returned URL does not request another navigation. Candidate jobs use `security_candidates` status/stop with the reproduction `executionRunId` and source scan `runId`; the browser session lease is separate. A disconnected executor interrupts work; target requests are never automatically replayed. Terminal metadata reads use a control-only context, and explicit cleanup remains possible after revocation.

Thorough uses configured optional backends unless deselected through `options.backends`. PTK defaults remains native-only. Automatic OAST probes require an explicit exact input or an SSRF-correlated candidate with one unambiguous captured query occurrence. Duplicate occurrences, missing vectors and unavailable providers are coverage gaps. Other blind families remain available through explicit provider probe actions. Callback evidence is labelled `callback_observed`, with `impactConfirmed:false`.

Cookie import/export uses private, owner-bound `artifactRef` values. Model results contain cookie counts and identities, never exported values. Restoring checks current scope and permissions and reports partial failures. Managed browser storage-state import/export uses separate private native artifacts.

## Verification level

`investigation-api.test.mjs` compares imported PTK readiness, object-swap and response-diff outputs and exercises package ownership, private account comparison, required API inputs, multipart/form serialization, external references and partial failures. `backend-selection.test.mjs` verifies exact occurrence preservation, configured backend selection and honest missing-vector reporting. Service and cookie suites cover persistent leases, executor loss, cleanup, explicit caps, private artifacts and changed scope. These are focused contracts; they do not establish exhaustive network/browser parity for every candidate or every OpenAPI serialization feature.

# Managed security runtime

This directory contains reproducible dependency inputs, not installed runtimes. Setup is an explicit action in Security testing settings. The existing cert-x native host must first be updated using `tools/host/install.ps1`; browser-only scanning continues to work without the managed components.

Setup installs into `%LOCALAPPDATA%\cert-x\security-runtime` on Windows x64. It keeps versioned component directories, verifies archive hashes and sizes, installs npm dependencies from `package-lock.json` and Python wheels with `--require-hashes`, and publishes the active component manifest only after success. Cancelled/failed setup preserves the prior active manifest. Downloaded archives are cached by checksum. Setup never changes system PATH, browser proxy settings, or system certificate trust.

Installed components include isolated Chromium/Playwright, ChromeDriver, ZAP, a compatible Java 21 runtime, and Webhook MCP 3.0.0. Compatible existing Java/Python installations are reused. Pinned portable fallbacks are included for machines without compatible Python or Java; forced-missing installation, webhook imports, Java version, and keytool checks passed on the development Windows machine.

The webhook connection uses a private credential reference or an explicitly selected absolute environment-file path. Only `WEBHOOK_SITE_API_KEY` is resolved from that file. The project `.env.local` is a development input and is never packaged. The MCP descriptor contains a reference, never the resolved key. Callback creation defaults to seven-day expiry and explicit cleanup touches only the owned endpoint.

The local executor persists separately from Chrome's native-messaging connection. Admissions are associated with the exact connection and run lease. Disconnect revokes outgoing work; state-changing requests are not replayed. Browser sessions use private profile/state/artifact directories; ordinary model results contain references rather than saved credentials. Proxy credentials and certificate trust are confined to owned testing processes.

Host updates stage and validate all maintained files before publishing them, with rollback on publication failure. The host and daemon compare installed source revisions. Idle daemons can update automatically; active operations and browser sessions remain until explicitly stopped. A host that already loaded older files requires reconnecting the extension. **Restart local runtime** is a direct settings action that stops owned local testing; it is not an agent tool. Eight Windows lifecycle tests passed, including legacy-daemon process identity validation and refusal of a substituted PID.

## Validation

The broad repository test command covers extension/service contracts and the managed host tests in `tools/host/tests/security-*.test.cjs`. Those need this directory's packages (`npm ci --ignore-scripts --prefix tools/security/runtime`); the managed-browser ones skip unless `CERT_X_TEST_RUNTIME` selects a prepared runtime, and the browser runner supplies it when the default runtime is installed. Do not count missing dependencies or skipped tests as passes.

Useful standalone checks:

```text
node tools/security/tests/managed-zap-guard.cjs <managed-runtime-root>
node tools/security/tests/managed-zap.cjs <managed-runtime-root>
node tools/security/tests/managed-agent.browser.cjs
node tools/security/tests/managed-java-fallback.cjs <managed-runtime-root>
node tools/security/tests/managed-python-fallback.cjs <managed-runtime-root>
```

Set `ZAP_ACTIVE=1` or `ZAP_AJAX=1` for the respective ZAP fixture. The bounded live webhook test, `managed-oast-live.cjs <managed-runtime-root> <env-file>`, calls the real webhook service; it creates its own endpoint, sends marker-only events, retains evidence, and deletes only that endpoint.

`managed-agent.browser.cjs` uses a scripted model-protocol endpoint and real browser/native tools. It verifies chat-loop dispatch and results, not live model inference.

Managed conversation and upgrade tests default to `%LOCALAPPDATA%\cert-x\security-runtime\installed.json`. Override with `CERT_X_TEST_RUNTIME` (directory) or `CERT_X_MANAGED_COMPONENTS` (manifest). Conversation evidence defaults to `%LOCALAPPDATA%\cert-x\verification`; `CERT_X_EVIDENCE_ROOT` selects another location. Temp contains only disposable profiles, not the shared dependency installation or retained conversation reports.

Run summaries separate `probeUnits` (raw send attempts), `httpRequestsSent` (other admitted requests), and `connectionAttempts`. The existing `requestsSent` remains the combined budget counter for send attempts; opening a raw connection does not consume an extra probe. A raw operation holds a shared concurrency slot until it ends. Decoded targets supplied by a transport are rechecked before sending; unsupported routing forms are rejected; arbitrary nonconforming proxy interpretations are not guaranteed.

## Remaining implementation/verification boundaries

Raw HTTP/1 and HTTP/2 desync use paired controls and repeated backend observations; HTTP/1 also supports controlled response queues. WebSocket frames require a validated upgrade. Structured HTTP/2 uses pinned HPACK and 16,384-byte DATA frames, with the initial 65,535-byte flow-control limit. Private evidence supports paging after completion or errors. See `../raw-contract.md` for exact arguments and unsupported forms. Byte sends and timeouts alone never confirm a vulnerability.

Stored execution passes two positive and three negative original/owned browser cases using a fixture-derived rule. Messaging, existing/OOPIF documents and multi-origin HTTP correlation have separate passing browser fixtures. Candidate/API contracts and selected browser flows pass; that is not exhaustive parity across every original PTK path. See `security/advanced-verification.md` for the observed evidence and exact remaining work.

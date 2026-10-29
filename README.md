# cert-x

Chrome extension that lets an AI agent use the browser: open pages, click, fill forms, and read what is on screen. The side panel is the chat. Model providers, MCP servers, and approval settings live in the panel.

## Load it

1. Open `chrome://extensions`.
2. Turn on Developer mode.
3. Choose **Load unpacked** and select this folder.
4. Open the cert-x side panel. After a code change, click **Reload** on the extension card.

API keys and MCP tokens stay in Chrome storage on your machine. They are not in this repo.

## Rebuild the panel patches

The side panel and background are built files. Edits to the agent UI, live status bar, and extra tools live in `tools/picker` and are applied on top of the originals:

```text
node tools/picker/apply-picker.js
```

That rewrites `background/background.js`, `chunks/sidepanel-CUbsl7eV.js`, and `assets/sidepanel-DD7JAQkM.css`. Reload the extension after it finishes. The script checks that every file named in `manifest.json` is still on disk.

## Profiles and workspaces

Choose a profile beside the model picker. **Default** offers every tool and MCP server except security testing; **Research** starts with browser and file tools, while **Coding** and **Bug bounty** also include commands. Job status and Stop remain available. Research, Coding and Bug bounty start with no MCP servers selected; choose existing connections under **Settings → Profiles**. Profiles do not enable local access or change your approval mode.

Profiles contain instructions, an optional model preference, tool selections, MCP connections and permission preferences. Edit or duplicate any profile; reset built-ins or delete custom profiles. Advanced controls stay under **Model, tools & permissions**. Global Disabled and Always ask rules still apply; a profile cannot relax them.

Use **Settings → Workspaces** to create a project, then choose it above the composer. A workspace can hold a default profile, working folder, shared notes, pinned file/page references and optional model/tool/connection overrides. New chats started from a workspace inherit its workspace; existing chats can be moved with the selector. History offers All chats, No workspace and workspace filters. Workspace chats are retained until explicitly deleted; other chats keep the latest ten.

Chats share only saved workspace context and a workspace output view, not each other's transcripts. Pinned references are not automatically opened or read. File references require absolute paths; page references are selected from open HTTP(S) tabs. Notes can include project decisions, targets, exclusions or account/role details. There are no automatically generated cross-chat summaries or background model calls.

Model selection follows **explicit chat choice → workspace preference → profile preference → app default**. Existing chat model choices are preserved. **Use default model** clears a chat override. Missing preferred models block sending and ask you to choose an available model. Profile/workspace changes take effect on the next message; newly restricted tools are blocked immediately, including calls awaiting approval. Subagents inherit their parent's task configuration.

With a working folder, `local_run_command` may omit `cwd`; the extension resolves the absolute directory before approval. Other file paths remain absolute. A working folder and target notes are context, not access sandboxes. MCP discovery during a chat only starts selected connections; settings connection checks can still test configured servers explicitly. Removing a connection from one workspace does not stop another chat's jobs.

Expand **Outputs → Workspace** to see outputs from member chats, with their source chat identified, or use the workspace editor's output view. Files remain in place. Deleting a workspace removes its grouping/context only: chats, files, tabs, outputs and jobs remain. Removing a custom profile makes affected workspaces use Default; chats inherit their workspace profile or Default.

## Optional CSP control

Open **Settings → Tools & permissions → Browser → Page controls**, select a tab, then use **Unblock CSP**. The neutral switch changes response-header rules for that tab's exact origin. Click **Reload to apply** when ready; cert-x never reloads automatically. The side panel shows active controls and offers Turn off and Reload.

This is a manual browser control, independent of profiles and Full access. Rules survive service-worker suspension but clear on browser restart, tab closure/replacement or navigation to another origin. Turning the switch off requires a reload to restore the policy on the loaded page. Like the supplied CSP Unblock implementation, this removes CSP response headers; it does not remove HTML meta policies or policies from service-worker-generated responses. It does not require another debugger attachment.

## Security testing

The Bug bounty profile includes native security testing derived from PTK v10. No separate PTK extension, pairing, or build command is needed. Open **Settings → Security testing** or use the compact chat panel to select a target, engines, accounts, and scan preset. The agent can run the same capabilities through its security tools and use results for follow-up testing.

DAST, IAST, SAST and SCA share cert-x's permissions, browser controls, workspaces, findings and Outputs. Supporting agent tools provide request capture/replay, workflow recording/macros, JWT operations, reconnaissance, codecs and browser port observations. A successful start does not establish coverage; inspect readiness, progress, skips and evidence before drawing conclusions.

**Thorough** uses COMPREHENSIVE strategy and wide native controls. It follows in-scope HTML links up to the configurable `safe` discovery preference and gives newly ready request/module groups an early probe before deep repeats (`schedulerBreadthFirst`); both settings can be changed per run. **PTK defaults** retains the reference ordering and does not enable link discovery. Advanced settings contain editable performance options, optional total budgets and explicit user limits. Per-run agent choices may override preferences, but cannot raise explicit user limits. Full access follows existing Allow/Always ask/Disabled rules without approval for each internal scan request. Agent-facing status and finding lists are concise by default; request full status diagnostics or finding evidence by ID when needed.

For an agent-created text payload up to 256 KiB, the browser `upload` tool accepts `generated: { filename, content, mimeType? }` and a CSS file-input selector. It selects an in-memory file without a local download or native-host setup. Existing user attachment IDs and absolute local paths remain supported. Path-based selections return a zero-byte warning when Chrome cannot distinguish a missing source from an intentionally empty file, and a stalled debugger command returns a bounded error rather than holding the agent indefinitely.

Use a browser tab logged into the intended account for IAST/SAST/SCA. Verified saved header/cookie snapshots support DAST, replay and account comparisons; they do not create a separate browser identity. Configure workspace targets and exclusions, inspect protected evidence, and verify identities when comparing accounts. Request status alone does not prove an access-control issue.

Findings and evidence remain owned by their chat and aggregate through workspace outputs. Completed evidence survives worker restart; interrupted scans are not silently replayed. Old companion records remain historical and their saved reports remain available. Existing PTK installations are not removed automatically. See [security runtime, configuration and validation](security/README.md) for supported transports, recovery, test evidence and limitations.

## Knowledge graph

Recon and findings build a persistent map of the target, stored per workspace and shared across its chats (a chat outside a workspace keeps its own). `graph_write` adds typed nodes (origins, routes, params, tech, roles, accounts, findings, observations, evidence) and edges; `graph_find` filters or traverses; `graph_digest` returns the decision summary — coverage counts, unvisited routes, untested inputs, chainable findings and playbook suggestions. Playbook seeds distilled from common methodology (sources: `checkbox/bugbounty.html`, the file-upload attack map and the Agentic AI Red Team Checklist in `checkbox/`; file-upload chains, SQLi through WAF bypass, LFI wrappers, XXE, OAuth/2FA takeover, IDOR, business logic, SSRF, deserialization, agentic-AI/LLM attacks) are matched against the frontier on demand, never stored in the prompt. The map survives restarts and holds up to 500 nodes; past 2 MiB the oldest observations are dropped first. `graph_write` with `reset:true` clears it.

Tool-failure telemetry — per-tool call and error counts and which tool ran next after each error — is collected automatically and surfaced through `get_capabilities` under `telemetry`.

## Fast browse

Fast browse is a switch at the bottom of the model menu (also under **Settings → Models**). It is on by default once there is something to run it with: a saved OpenRouter provider needs nothing more; otherwise the switch asks for one key, TypeSafe or OpenRouter (recognized by its `sk-or-` prefix), and checks it with one real decision before saving it. While it is on, the agent gets a `browse` tool, one system-prompt line telling it to hand multi-step page tasks to it, and a hint on its first snapshot of each page with form fields (without these, models measured kept driving pages click by click and never called it). It finishes a multi-step page task — signing in, getting past a consent wall, reaching a form, walking an app so capture records its API — in one tool call instead of one model turn per click. A fast decision model picks each click, value, option and Enter until the goal is visibly done, then the tool returns the steps and the final page with live refs. A TypeSafe key runs Jev (about 200 ms per decision); OpenRouter runs Gemini 3.1 Flash Lite (about 0.7 s). Text to type goes in named `values`: the decision model gets the names, and their text is replaced by the name wherever it shows up in what is sent or returned (URL, page text, element names; a value under four characters only in the field it was typed into). The page's own text is sent to the decision model as data. Actions run through the normal click/fill/select tools, so the changed-element guard and the highlight apply, and Stop ends the loop. While the switch is off, or has nothing to run on, the tool is not offered.

## Live sessions

The extension can be exercised end-to-end against a practice target with a real model, unattended; the M4 evidence baseline was produced this way. See [docs/live-sessions.md](docs/live-sessions.md) for the runner, targets and how to read results; [docs/backlog.md](docs/backlog.md) tracks open items.

## MCP connections

In the side panel, open **Settings → MCP servers**. Choose **Add a server**, paste its URL, then **Connect** to test and save in one step. API keys and names are optional fields; servers that request OAuth open sign-in. Postman (US) uses sign-in. Postman (EU) uses a key from the EU account. Local stdio MCP servers run through the optional native host below.

## Local computer access (Windows)

The native host adds `local_run_command`, `local_read_file`, `local_write_file`, `local_list_directory`, `local_read_job`, `local_cancel_job`, and tools discovered from local stdio MCP servers. Install Node.js 22 or newer, reload the extension, then open **Settings → Local computer**. Expand **Set up connection**, select your browser, and use **Copy command** and run it from this repository folder:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\host\install.ps1 -ExtensionId YOUR_32_CHARACTER_EXTENSION_ID
```

The installer copies the host into `%LOCALAPPDATA%\cert-x\native-host\Chrome\<extension-id>` and registers `com.cert_x.host` for the current user and that exact extension ID. No administrator rights are required. Add `-Browser Edge` or `-Browser Chromium` for those browsers. Rerun the installer after editing the host; rebuilding the extension does not update the installed copy. `-GenerateOnly` prepares files without registration; `-Uninstall` unregisters the selected browser while preserving installed files.

The host connection is checked automatically. When connected, select **Allow local access**. The toggle saves immediately and shows the saved state next to it. Tools appear on the next agent message in the same conversation; a new conversation is not required. Manage remote and local servers separately under **Settings → MCP servers**. Unless a tool rule overrides it, **Full access** runs local commands, file operations, and local MCP tools without prompts. In the other approval mode, local calls require **Allow once**; denying it does not execute it. The approval displays the full arguments. Browser domain grants do not authorize local operations. The local-access toggle remains required in either mode. Disabling local access immediately disconnects the host and stops its active command/MCP processes.

Commands run as your current OS user in noninteractive Windows PowerShell, with an explicit absolute working directory. There is no filesystem sandbox: an approved command or configured MCP server has your account's access. File tools also require absolute paths. Writes create new files by default; replacing a file requires `overwrite: true`. Overwrites use a temporary sibling and rename, replacing the file identity/metadata. Symlink overwrite targets are rejected. Directory creation and other filesystem operations are available through approved commands.

Foreground command duration is limited to 120 seconds (30 seconds by default), with up to 128 KiB combined stdout/stderr (64 KiB by default). Use background mode for longer jobs. File reads return up to 512 KiB per call and support byte-offset pagination; use base64 for binary data or lossless chunks. Writes accept up to 512 KiB, subject to the 900 KiB encoded message limit. Result fields distinguish nonzero exits, timeout, cancellation, and truncated output. A timeout or cancellation, foreground or background, kills the command's whole process tree, including children started during the kill; if Windows cannot list processes (WMI), command results and job summaries carry a `warning` that child processes may still be running. Cancellation cannot undo changes already made. Operations are never automatically replayed after a disconnect.

### Local MCP servers

Open **Settings → MCP servers → Add local server**. Enter the executable in **Command** and one argument per line in **Arguments**. Name, working directory and environment variables are under **More options**. Use **Save server**; **Test** is optional. Existing stored configurations are retained. The equivalent stored configuration looks like:

```json
[
  {
    "label": "My server",
    "command": "node",
    "args": ["C:\\projects\\my-mcp\\server.js"],
    "cwd": "C:\\projects\\my-mcp",
    "env": { "EXAMPLE_SETTING": "value" }
  }
]
```

`command` is an executable and `args` is an argument array, not a shell command. `cwd` defaults to your home directory. Environment entries override the inherited host environment and are saved in local Chrome storage. `npx` and `npm` are supported on Windows through their Node entrypoints, without shell argument interpolation; include `-y` when using `npx` to avoid an interactive install prompt. Other `.cmd`/`.bat` launchers are rejected; use the underlying executable or Node entrypoint.

Saving and enabling a configuration authorizes starting those programs for tool discovery. **Test** also launches the entered program. Agent calls to discovered tools follow the selected approval mode and tool rules. Up to eight server processes persist for the native connection; changing the local server list resets MCP processes while preserving command jobs; disabling local access or disconnecting the host stops both. Discovery supports pagination (up to 256 tools/server), JSON-RPC errors and tool-level `isError`; cancellation/timeouts terminate the affected server, including other in-flight calls to it. It restarts on the next explicit request. The client exposes MCP tools; sampling, roots, elicitation, resources and prompts are not implemented. Non-text tool content is returned as structured JSON, not rendered as inline media.

The implementation follows [Chrome native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging) and [MCP stdio transport](https://modelcontextprotocol.io/specification/2025-03-26/basic/transports). Windows installation and Chromium are tested; macOS/Linux installation is not provided.

## Capability health, background jobs and task outputs

**Settings → Capability health** checks the native host and shows configured model providers, current MCP discovery, Browser control and permission overrides. Configured providers are not presented as credential-tested connections. The agent can use `get_capabilities` with an optional tool-name filter to inspect the same state. A missing job-capable host produces an update notice; rerun the installer, then reload the extension.

For long commands, use `local_run_command` with `background: true`. It shares the existing Run commands permission. `local_read_job` returns state and incremental stdout/stderr chunks; pass the returned `nextCursor` on the next read. `local_cancel_job` stops the process tree and returns terminal status. These operations are scoped to the task, including its subagents. Job reads/cancellation do not normally prompt, but explicit tool rules still apply.

Up to eight jobs run concurrently, for up to one hour each (30 minutes by default). The host retains up to 32 jobs and the latest 1 MiB of output per job; evicted output is explicitly marked truncated. **Local computer → Background jobs** shows status, incremental output and a Stop action. Jobs run between chat messages while the host stays connected. Stopping a chat does not stop an already-started job; use Stop. Closing the browser, reloading the extension or disabling local access terminates the host and its jobs. Interrupted status remains visible, but output held in the old host is unavailable after a restart.

Each chat has a collapsed **Outputs** tray. Native file writes, browser file saves/downloads and screenshots are captured automatically within retention limits. `save_as_pdf` saves its generated PDF to Downloads. For shell commands, list up to 16 absolute output paths in `outputs`; existing regular files are collected when the command ends. Commands without declared output paths are not scanned for file changes.

Use **Preview**, **Open** (a background browser tab), **Show** (reveal a browser download), or **Use in chat**. Preview renders text/images safely; binary files such as PDFs can be attached using the existing file parser. File previews/attachments are limited to 8 MiB, text previews to 64 KiB, and inline downloads/screenshots to 2 MiB. The tray retains up to 100 references and 12 MiB of inline data across tasks. Native file contents are read on demand; dropping an old reference never deletes its file.

**MCP servers → Import configuration** accepts a common `mcpServers` JSON object or a server array. Preview first, then select entries to add. Existing servers and credentials are preserved; duplicate remote URLs or identical local launch configurations are skipped. Unsupported transports, custom headers and disabled flags are reported, not silently discarded. Environment placeholders remain literal text. Import does not turn local access on, but an enabled local server may start during later discovery.

## Tools & permissions

Open **Settings → Tools & permissions** to set defaults for Browser, Local computer, all MCP servers, or an individual MCP server. Expand a group or search to set a per-tool override.

| Rule | Behavior |
| --- | --- |
| Use current mode / group default | Inherit the next default |
| Always ask | Ask for each call, including in Full access |
| Allow | Run without an approval prompt |
| Disabled | Hide from future model tool lists and block execution |

Individual rules override server/group defaults. Server defaults override the overall MCP default. Parent capabilities still win: disabling Local computer or removing a server blocks it regardless of an Allow rule. A group default of Disabled can have individual Allow exceptions; it is not a master capability switch.

Inherited Browser tools retain their existing safe-action and remembered-domain approval behavior. Inherited Local computer and MCP tools ask in Requires approval and run directly in Full access, except job status and cancellation, which are safe by default. Explicit Always ask ignores remembered domain approvals. A label beside the chat mode indicates custom overrides. **Reset defaults** removes all saved rules, including rules for unavailable servers.

Policy is checked at execution and again after approval, so changes apply to already-loaded tools and subagents. Disabled tools disappear from model schemas on the next turn; an old schema cannot bypass the execution check. Already-running operations are not undone. MCP rules identify the server configuration and original tool name, not the generated alias or discovery order. A local server's command, arguments, working directory or environment changes its identity. Remote credential refreshes at the same URL keep that endpoint's rules.

Browser control obeys the same rules. Calls needing approval appear in both its page and Tools & permissions; they expire after two minutes and are denied when the controller disconnects. Rules are tool controls, not a sandbox: an allowed command or script can still perform operations offered by another disabled tool.

## Browser control

**Settings → Browser control** lets an external WebBridge controller drive browser tools. This is separate from **Local computer**, which lets cert-x access local files and commands.

Start your installed companion, then choose **Connect → Allow & connect**. The default is `ws://127.0.0.1:10086/ws`. **Custom address** accepts local WebSocket endpoints or TLS (`wss://`) endpoints on other computers; credentials, query strings, fragments, and paths other than `/ws` are rejected. The installed Kimi WebBridge CLI supports `kimi-webbridge start`; the UI shows its Windows invocation without downloading or executing a remote installer.

Authorization is explicit and scoped to the normalized endpoint. Existing `ws_should_connect` settings alone do not grant access: after updating, authorize the controller once. A connection becomes **Connected** only after `hello_ack` and a successful `/status` response with `running: true` and a semantic `version`. If the acknowledgement provides `daemonVersion` or `version`, it must match `/status`. The page shows the controller's reported name (or WebBridge), version and address, and reports unavailable services, handshake failures and the companion's already-in-use response (4409).

**Disconnect & revoke** closes the connection, clears endpoint authorization and stops reconnection. New tool calls are blocked before verification and after revocation. Already-running actions may finish. Explicit connection changes are accepted only from extension pages; the authorization endpoint is restricted to the settings page.

The legacy companion does **not** authenticate individual agents. Endpoint authorization and TLS do not turn its reported name/version into a cryptographically verified identity. Only authorize a trusted companion; authenticated per-agent pairing requires changes to that companion. The companion executable and its live connection are not modified by this repository's build or tests.

## Validation

Build and run maintained contracts. The build refuses to write a bundle whose top scope binds one name twice (`tools/picker/scope-check.mjs`); rename the added binding when it reports one.

```text
node tools/picker/apply-picker.js
node --test tools/host/tests/*.test.js tools/picker/tests/*.test.js providers/*.test.js tools/ptk/*.test.cjs tools/ptk/*.test.mjs tools/security/tests/*.test.mjs
```

Real Chromium checks use temporary profiles and local fixtures. Run every check in the list below with real exit codes (nothing silently skips; the DVWA rehearsal is reported as skipped unless DVWA answers at `DVWA_ORIGIN`, default `http://127.0.0.1:4280/`) via:

```text
node tools/run-browser-tests.cjs
```

Individual checks:

```text
node tools/picker/tests/native-test.js
node tools/picker/tests/dvwa-rehearsal.cjs
node tools/picker/tests/browser-control-ui-test.js
node tools/picker/tests/contexts-ui-test.js
node tools/picker/tests/csp-ui-test.js
node tools/picker/tests/record-arm.browser.cjs
node tools/picker/tests/model-404.browser.cjs
node tools/security/tests/browser-smoke.cjs
node tools/security/tests/ui.browser.cjs
node tools/security/tests/utilities.browser.cjs
node tools/security/tests/lifecycle.browser.cjs
node tools/picker/tests/iast-real-test.js
node tools/picker/tests/dast-real-test.js
node tools/picker/tests/dast-coverage-real-test.js
node tools/picker/tests/authz-real-test.js
node tools/security/tests/browser-parity.cjs
node tools/security/tests/runtime-browser-dast.cjs
```

`tools/picker/tests/ref-guard.browser.cjs` (non-blocking interact highlight, changed-element ref refusal), `tools/picker/tests/browse.browser.cjs` (the browse loop with a scripted decision model), `tools/picker/tests/fast-browse-ui.browser.cjs` (the Fast browse switch and key check in the model menu and Settings) and `tools/picker/tests/stream-liveness.browser.cjs` (a subagent that streams reasoning or only keep-alive comments past the stall budget finishes; a silent or cut stream reaches the orchestrator as its own error after the retries; a refusal or a missing model is not retried and comes back marked not retryable) use test hooks, so they need a test build first: `KI_TEST_HOOKS=1 node tools/picker/apply-picker.js`. Rebuild without the variable afterwards. Two scripts make real, paid model calls and belong to neither suite. `node tools/picker/tests/browse-ab.cjs --model=<openrouter model>` compares whole chats with Fast browse on and off on the same fixtures (a real chat model and real Fast browse, keys `OPENROUTER_API_KEY` and `TYPESAFE_API_KEY` from `.env.local`, never printed; production build): tasks done, time, chat-model calls and how often the model chose `browse`. On the test build, `node tools/picker/tests/browse-live.cjs typesafe:jev-latest openrouter:<model>` runs real decision models (keys from `.env.local`, never printed) on seven local fixtures and reports pass rate and latency per backend; a scenario passes on what the fixture server received, not on the model's own "done".

The native-host test checks same-conversation tool enablement, Full access, approval overrides, files, commands, local/remote MCP, jobs and outputs. It uses temporary Chromium host registration and refuses to replace an existing registration. Chrome/Edge registrations are unaffected. Browser control tests use a local WebSocket fixture, never the user's running controller.

Use `PLAYWRIGHT_MODULE` and `CHROMIUM_PATH` to select installed browser-test dependencies (Chromium defaults to the newest build Playwright has installed, `tools/chromium-path.cjs`); three unit files (`providers/authz.test.js`, `providers/security.test.js`, `tools/security/tests/detectors-analysis.test.mjs`) launch Chromium too. The expanded targeted fixtures also require Node's SQLite support and Python with Jinja2. Security detector tests include isolated browser execution; see [security verification](security/README.md) for the independent PTK reference and per-engine parity commands. Historical companion-specific fixtures are preserved under `tools/security/reference`; they are not the current installation workflow.

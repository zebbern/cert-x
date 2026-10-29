# Model provider notes

- Connections accept a `modelIds` allowlist (max 40) that filters the
  provider catalog. To pin a model: add it to the connection's `modelIds`
  and set the workspace model to `{connectionId, modelId}`. Verified with
  `xiaomi/mimo-v2.6-flash` and `-pro` (tool-capable, ~1M context).
- **Anthropic models via OpenRouter blanket-refuse cert-x's security-testing
  prompt at the provider level** (`refusal` + `finish_reason:
  content_filter` on the first turn of an authorized lab session). The
  provider-compat fetch wrapper names this in the turn error with a
  model-switch recovery suggestion; non-chat endpoints and the data lines of
  clean streams pass through untouched, and SSE keep-alive comments on
  chat-completion streams become liveness events so the 90 s stall timer
  does not cut a quietly working model (`ki-provider-compat.js`,
  unit-tested). Non-Anthropic models tested (MiMo) proceed normally.
- **Large-context streaming**: early live sessions died mid-stream at
  ~170–340 KB contexts while the provider completes the identical requests
  standalone — a client-side drop. Keeping the side panel resident
  (`bringToFront` in the runner) coincided with zero stream deaths across
  the final runs. If it recurs, first look for a `NET-FAIL` about 90 s after
  `NET-RES` 200 in the runner log (the stall timer, which since 2026-10-27
  also counts reasoning chunks as liveness), then page lifecycle, before the
  provider.

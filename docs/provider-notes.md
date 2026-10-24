# Model provider notes

- Connections accept a `modelIds` allowlist (max 40) that filters the
  provider catalog. To pin a model: add it to the connection's `modelIds`
  and set the workspace model to `{connectionId, modelId}`. Verified with
  `xiaomi/mimo-v2.6-flash` and `-pro` (tool-capable, ~1M context).
- **Anthropic models via OpenRouter blanket-refuse cert-x's security-testing
  prompt at the provider level** (`refusal` + `finish_reason:
  content_filter` on the first turn of an authorized lab session). The
  provider-compat fetch wrapper now names this in the turn error with a
  model-switch recovery suggestion; clean streams and non-chat endpoints
  pass through untouched (`ki-provider-compat.js`, unit-tested). Non-Anthropic
  models tested (MiMo) proceed normally.
- **Large-context streaming**: early live sessions died mid-stream at
  ~170–340 KB contexts while the provider completes the identical requests
  standalone — a client-side drop. Keeping the side panel resident
  (`bringToFront` in the runner) coincided with zero stream deaths across
  the final runs. If it recurs, suspect page lifecycle before the provider.

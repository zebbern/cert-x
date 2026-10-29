// MiMo V2.6 Flash can flood an agent with dependent/repeated calls before seeing
// any tool feedback. Request one call at a time unless explicitly overridden.
// This is a provider request option, not a rewrite of generated tool results.
function kiProviderToolOptions(request) {
  if (request?.tools?.length && /^(?:xiaomi\/)?mimo-v2\.6-flash(?:-\d{8})?$/.test(request.model || '')
      && request.parallel_tool_calls === undefined) request.parallel_tool_calls = false;
  return request;
}

// The provider answered 404 for the chosen model: name it, quote the provider and
// say where to pick another. Shared by the turn notice and the compaction and
// flow failure reasons.
function kiModelUnavailableText(failure) {
  return `Model ${failure.model} isn't available (provider said: ${failure.detail}). Pick another model in the model menu.`;
}

// Surface provider-level refusals as actionable errors instead of dead turns.
// Anthropic via OpenRouter blanket-refuses security-testing conversations with
// finish_reason "content_filter" plus a non-empty refusal delta INSIDE an
// HTTP 200 SSE stream (captured 2026-10-23, evidence/m4-live-baseline); the
// SDK surfaces that as a generic interrupted turn. Wrap the worker's fetch
// for chat-completion endpoints, scan the stream, and fail fast with a
// message that names the actual cause and the fix. Pass-through untouched
// for every other request and for streams without refusal markers.
var KI_REFUSAL_MARKER = /"finish_reason"\s*:\s*"content_filter"|"refusal"\s*:\s*"[^"]+/;
var KI_REFUSAL_TEXT = 'The model provider refused this request';
function kiRefusalError() {
  return Error(KI_REFUSAL_TEXT + ' (Anthropic content filter on this conversation). This is a provider-side block, not a cert-x failure. Recovery: switch the model to a non-Anthropic one (for example xiaomi/mimo-v2.6-pro or xiaomi/mimo-v2.6-flash) and resend.');
}
// OpenRouter keeps a quiet stream open with SSE comments (": OPENROUTER
// PROCESSING") while the model works without streaming anything. The SDK drops
// comments, so the worker's stall timer (90 s per parsed part) saw nothing and
// cut the stream. On chat-completion streams each comment line becomes this
// event, which the parser counts as liveness and otherwise ignores.
var KI_ALIVE_EVENT = 'data: {"choices":[{"index":0,"delta":{"ki_alive":true},"finish_reason":null}]}\n\n';
function kiRefusalFetchWrapper(original) {
  return async function (input, init) {
    const response = await original.apply(this, arguments);
    try {
      const url = typeof input === 'string' ? input : input && input.url || String(input && input || '');
      if (!/\/(chat\/completions|messages)(\?|$)/.test(url)) return response;
      const type = (response.headers && response.headers.get && response.headers.get('content-type')) || '';
      if (!/event-stream|application\/json/.test(type)) return response;
      const body = response.body;
      if (!body || typeof body.pipeThrough !== 'function') return response;
      const alive = /event-stream/.test(type) && /\/chat\/completions(\?|$)/.test(url);
      const decoder = new TextDecoder(), encoder = new TextEncoder();
      let carry = '', lines = '';
      const transform = new TransformStream({
        transform(chunk, controller) {
          if (typeof chunk !== 'string' && !(chunk instanceof Uint8Array)) { controller.enqueue(chunk); return; }
          const part = typeof chunk === 'string' ? chunk : decoder.decode(chunk, { stream: true });
          const text = carry + part;
          // Keep a tail so a marker split across network chunks is still seen.
          carry = text.slice(-64);
          if (KI_REFUSAL_MARKER.test(text)) { controller.error(kiRefusalError()); return; }
          if (!alive) { controller.enqueue(chunk); return; }
          // Whole lines only, so a comment split across chunks is still one line.
          lines += part;
          const end = lines.lastIndexOf('\n') + 1;
          if (!end) return;
          controller.enqueue(encoder.encode(lines.slice(0, end).replace(/^:.*\r?\n/gm, KI_ALIVE_EVENT)));
          lines = lines.slice(end);
        },
        flush(controller) {
          if (alive && (lines += decoder.decode())) controller.enqueue(encoder.encode(lines));
        }
      });
      return new Response(body.pipeThrough(transform), { status: response.status, statusText: response.statusText, headers: response.headers });
    } catch { return response; }
  };
}
// Whether running the same request or subagent again can work. A rejected key,
// no credit, a missing model or connection, bad connection settings and a
// provider refusal fail the same way every time; only the user can change them.
// cls is the vendor's failure class for the error.
var KI_USER_FIXES = new Set(['auth', 'quota-exhausted', 'connection-gone', 'no-api-key', 'model-unavailable', 'client-config']);
function kiRetryable(error, cls) {
  return !KI_USER_FIXES.has(cls) && !String(error && error.message || error).includes(KI_REFUSAL_TEXT);
}
// What the orchestrator gets back from a subagent that failed.
function kiSubagentFailure(error, cls) {
  const message = error instanceof Error ? error.message : String(error);
  if (!kiRetryable(error, cls)) return JSON.stringify({ error: 'Subagent failed: ' + message, retryable: false, userAction: true, recovery: 'Delegating again fails the same way. Stop and tell the user what the error says; only they can change the key, credit, model or connection.' });
  // A stream death loses the final summary but not the work.
  return JSON.stringify({ error: 'Subagent interrupted: ' + message, retryable: true, recovery: 'Its graph_write calls persist in the workspace graph. Do not repeat the same enumeration from scratch: delegate a resume brief ("a previous subagent already mapped the surface with graph_write; read graph_digest and graph_find, fill only visible gaps, then produce the final summary"). If the subagent wrote no graph, re-delegate the original task.' });
}

var kiFetchWrappedForRefusals = false;
function kiWrapFetchForRefusals() {
  if (kiFetchWrappedForRefusals || typeof globalThis.fetch !== 'function') return;
  try { globalThis.fetch = kiRefusalFetchWrapper(globalThis.fetch); kiFetchWrappedForRefusals = true; } catch {}
}
if (typeof chrome === 'object' && chrome.runtime && chrome.runtime.id) kiWrapFetchForRefusals();

if (typeof module === 'object' && module.exports) module.exports = { kiProviderToolOptions, kiRefusalFetchWrapper, kiWrapFetchForRefusals, kiRefusalError, kiRetryable, kiSubagentFailure, KI_REFUSAL_MARKER, KI_ALIVE_EVENT };

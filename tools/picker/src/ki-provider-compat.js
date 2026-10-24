// MiMo V2.6 Flash can flood an agent with dependent/repeated calls before seeing
// any tool feedback. Request one call at a time unless explicitly overridden.
// This is a provider request option, not a rewrite of generated tool results.
function kiProviderToolOptions(request) {
  if (request?.tools?.length && /^(?:xiaomi\/)?mimo-v2\.6-flash(?:-\d{8})?$/.test(request.model || '')
      && request.parallel_tool_calls === undefined) request.parallel_tool_calls = false;
  return request;
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
function kiRefusalError() {
  return Error('The model provider refused this request (Anthropic content filter on this conversation). This is a provider-side block, not a cert-x failure. Recovery: switch the model to a non-Anthropic one (for example xiaomi/mimo-v2.6-pro or xiaomi/mimo-v2.6-flash) and resend.');
}
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
      const decoder = new TextDecoder();
      let carry = '';
      const transform = new TransformStream({
        transform(chunk, controller) {
          if (typeof chunk !== 'string' && !(chunk instanceof Uint8Array)) { controller.enqueue(chunk); return; }
          const text = carry + (typeof chunk === 'string' ? chunk : decoder.decode(chunk, { stream: true }));
          // Keep a tail so a marker split across network chunks is still seen.
          carry = text.slice(-64);
          if (KI_REFUSAL_MARKER.test(text)) { controller.error(kiRefusalError()); return; }
          controller.enqueue(chunk);
        }
      });
      return new Response(body.pipeThrough(transform), { status: response.status, statusText: response.statusText, headers: response.headers });
    } catch { return response; }
  };
}
var kiFetchWrappedForRefusals = false;
function kiWrapFetchForRefusals() {
  if (kiFetchWrappedForRefusals || typeof globalThis.fetch !== 'function') return;
  try { globalThis.fetch = kiRefusalFetchWrapper(globalThis.fetch); kiFetchWrappedForRefusals = true; } catch {}
}
if (typeof chrome === 'object' && chrome.runtime && chrome.runtime.id) kiWrapFetchForRefusals();

if (typeof module === 'object' && module.exports) module.exports = { kiProviderToolOptions, kiRefusalFetchWrapper, kiWrapFetchForRefusals, KI_REFUSAL_MARKER };

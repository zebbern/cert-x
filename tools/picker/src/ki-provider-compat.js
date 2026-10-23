// MiMo V2.6 Flash can flood an agent with dependent/repeated calls before seeing
// any tool feedback. Request one call at a time unless explicitly overridden.
// This is a provider request option, not a rewrite of generated tool results.
function kiProviderToolOptions(request) {
  if (request?.tools?.length && /^(?:xiaomi\/)?mimo-v2\.6-flash(?:-\d{8})?$/.test(request.model || '')
      && request.parallel_tool_calls === undefined) request.parallel_tool_calls = false;
  return request;
}

// Normalize image-producing CDP calls at the agent boundary. Keep the raw CDP
// executor unchanged for protocol clients; DP handles sizing and image parts.
function kiBrowserResult(name, args, value) {
  if (name !== "cdp" || args?.method !== "Page.captureScreenshot") return value;
  if (typeof value?.data !== "string" || !value.data.length) throw Error("Screenshot capture returned no image. Retry with screenshot.");
  const format = args.params?.format || "png";
  const mimeType = { png: "image/png", jpeg: "image/jpeg", webp: "image/webp" }[format];
  if (!mimeType) throw Error("Unsupported screenshot format: " + format);
  return { ...value, format, mimeType, dataLength: value.data.length };
}
async function kiBrowserAgentResult(name, args, value, session) {
  if (name !== 'cdp' || args?.method !== 'Page.printToPDF') return kiBrowserResult(name, args, value);
  // Stream callers explicitly asked for an IO handle; keep that protocol path.
  if (value?.stream && !value.data) return value;
  const data = value?.data;
  if (typeof data !== 'string' || !data.length || data.length % 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(data) || !atob(data.slice(0, 12)).startsWith('%PDF-')) throw Error('PDF capture returned invalid data. Retry with save_as_pdf.');
  const bytes = data.length * 3 / 4 - (data.endsWith('==') ? 2 : data.endsWith('=') ? 1 : 0);
  if (bytes > 8 * 1024 * 1024) throw Error('PDF exceeds the Outputs preview size. Use save_as_pdf or request ReturnAsStream.');
  const output = await kiWorkspaceOutput(session, { name: 'Page.pdf', kind: 'file', data, encoding: 'base64', mime: 'application/pdf', size: bytes });
  return { format: 'pdf', outputId: output.id, name: output.name, bytes, location: 'Outputs' };
}

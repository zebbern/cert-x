// Parse common mcpServers exports without executing commands or expanding env.
export function parseMcpImport(source) {
  if (source.length > 256 * 1024) throw Error("Configuration exceeds 256 KiB.");
  const parsed = JSON.parse(source);
  const entries = Array.isArray(parsed) ? parsed.map((value, index) => [value?.label || value?.name || "Server " + (index + 1), value])
    : parsed?.mcpServers && typeof parsed.mcpServers === "object" && !Array.isArray(parsed.mcpServers) ? Object.entries(parsed.mcpServers) : null;
  if (!entries || !entries.length) throw Error("Paste an mcpServers object or a server array.");
  if (entries.length > 40) throw Error("Import up to 40 servers at a time.");
  return entries.map(([label, value]) => {
    try {
      if (!value || typeof value !== "object") throw Error("Invalid server configuration");
      if (value.command && value.url) throw Error("Choose either command or URL");
      if (value.command) {
        const unsupported = Object.keys(value).filter(key => !["command", "args", "env", "cwd", "type", "name", "label", "id"].includes(key));
        if (unsupported.length) throw Error("Unsupported fields: " + unsupported.join(", "));
        if (value.type && value.type !== "stdio") throw Error("Unsupported transport: " + value.type);
        if (typeof value.command !== "string" || !value.command.trim() || value.command.includes("\0")) throw Error("Invalid command");
        if (value.args && (!Array.isArray(value.args) || value.args.some(arg => typeof arg !== "string" || arg.includes("\0")))) throw Error("args must contain strings");
        if (value.env && (typeof value.env !== "object" || Array.isArray(value.env) || Object.entries(value.env).some(([key, val]) => !key || /[=\0]/.test(key) || typeof val !== "string" || val.includes("\0")))) throw Error("env must map names to strings");
        if (value.cwd && (typeof value.cwd !== "string" || !/^(?:[A-Za-z]:[\\/]|\\\\|\/)/.test(value.cwd))) throw Error("cwd must be an absolute path");
        return { label, kind: "local", server: { label, command: value.command, args: value.args || [], ...(value.cwd ? { cwd: value.cwd } : {}), ...(value.env ? { env: value.env } : {}) } };
      }
      const url = new URL(value.url);
      const unsupported = Object.keys(value).filter(key => !["url", "headers", "token", "type", "name", "label", "id"].includes(key));
      if (unsupported.length) throw Error("Unsupported fields: " + unsupported.join(", "));
      if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) throw Error("Use an HTTP(S) URL without embedded credentials");
      if (value.type && !["http", "streamable-http"].includes(value.type)) throw Error("Only HTTP MCP is supported");
      const headers = value.headers || {};
      if (Object.keys(headers).some(key => key.toLowerCase() !== "authorization")) throw Error("Custom headers are not supported; nothing was discarded");
      const authorization = Object.entries(headers).find(([key]) => key.toLowerCase() === "authorization")?.[1];
      if (authorization !== undefined && (typeof authorization !== "string" || !/^Bearer\s+\S+/i.test(authorization))) throw Error("Only Bearer authorization is supported");
      const token = value.token ?? authorization?.replace(/^Bearer\s+/i, "") ?? "";
      if (typeof token !== "string") throw Error("Token must be text");
      return { label, kind: "remote", server: { label, url: url.toString(), token } };
    } catch (error) { return { label, error: error.message }; }
  });
}

export function mergeMcpImport(selected, remote, local) {
  const nextRemote = [...remote], nextLocal = [...local]; let added = 0, skipped = 0;
  for (const item of selected) {
    if (item.error) continue;
    if (item.kind === "remote") {
      if (nextRemote.some(server => server.url.replace(/\/$/, "") === item.server.url.replace(/\/$/, ""))) { skipped++; continue; }
      nextRemote.push({ ...item.server, id: crypto.randomUUID().slice(0, 8) });
    } else {
      const identity = server => JSON.stringify([server.command, server.args || [], server.cwd || "", Object.entries(server.env || {}).sort(([a], [b]) => a.localeCompare(b))]);
      if (nextLocal.some(server => identity(server) === identity(item.server))) { skipped++; continue; }
      if (nextLocal.length >= 8) throw Error("Up to 8 local servers are supported. Select fewer entries.");
      nextLocal.push(item.server);
    }
    added++;
  }
  return { remote: nextRemote, local: nextLocal, added, skipped };
}

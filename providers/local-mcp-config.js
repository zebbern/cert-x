// The editor passes an executable and argument array directly to the host.
// Never interpret the form as a shell command or split arguments on spaces.
export function serverFromForm(form, original = null) {
  const command = form.command.trim();
  if (!command || command.includes("\0")) throw Error("Enter a command, such as npx or node.");
  const cwd = form.cwd.trim();
  if (cwd && !/^(?:[A-Za-z]:[\\/]|\\\\|\/)/.test(cwd)) throw Error("Use an absolute working directory.");
  const originalEnvText = Object.entries(original?.env || {}).map(([key, value]) => key + "=" + value).join("\n");
  const env = {};
  if (original && originalEnvText === form.env) for (const [key, value] of Object.entries(original.env || {})) Object.defineProperty(env, key, { value, enumerable: true, configurable: true });
  else for (const line of form.env.split(/\r?\n/).filter(line => line.trim())) {
    const index = line.indexOf("=");
    if (index < 1) throw Error("Use NAME=value for each environment variable.");
    const key = line.slice(0, index).trim(), value = line.slice(index + 1);
    if (!key || key.includes("\0") || value.includes("\0")) throw Error("Invalid environment variable.");
    Object.defineProperty(env, key, { value, enumerable: true, configurable: true });
  }
  const args = original && (original.args || []).join("\n") === form.args ? original.args || [] : form.args.split(/\r?\n/).filter(line => line !== "");
  if (args.some(arg => arg.includes("\0"))) throw Error("Arguments cannot contain null characters.");
  const result = { ...original, command, args, label: form.label.trim() || command, env };
  if (cwd) result.cwd = cwd; else delete result.cwd;
  if (Object.hasOwn(form, 'envFileRef')) {
    const envFileRef = form.envFileRef.trim();
    if (envFileRef && (!/^(?:[A-Za-z]:[\\/]|\\\\|\/)/.test(envFileRef) || envFileRef.includes('\0'))) throw Error('Use an absolute environment file path.');
    if (envFileRef) result.envFileRef = envFileRef; else delete result.envFileRef;
  }
  return result;
}

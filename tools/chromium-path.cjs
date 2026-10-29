// Browser checks run on the newest Chromium build Playwright has installed: the
// extension is verified on current Chromium (older builds fail the macro and
// port-probe checks), and a pinned revision disappears when Playwright updates.
// CHROMIUM_PATH overrides it.
const fs = require("node:fs"), path = require("node:path");

function newest() {
  const root = path.join(process.env.LOCALAPPDATA || "", "ms-playwright");
  let builds = [];
  try { builds = fs.readdirSync(root).filter(name => /^chromium-\d+$/.test(name)).sort((a, b) => b.slice(9) - a.slice(9)); } catch {}
  for (const name of builds) {
    const exe = path.join(root, name, "chrome-win64", "chrome.exe");
    if (fs.existsSync(exe)) return exe;
  }
  return path.join(root, "chromium-<none installed>", "chrome-win64", "chrome.exe");
}

module.exports = process.env.CHROMIUM_PATH || newest();

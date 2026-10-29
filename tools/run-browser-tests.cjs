#!/usr/bin/env node
// Runs every real-Chromium validation check with real exit codes so red stays
// red — the default node --test glob does not include these .cjs/.js checks
// and they silently skip otherwise. Open problems are tracked in
// docs/backlog.md; this runner reports reality and exits non-zero on any failure.
// Usage: node tools/run-browser-tests.cjs [filter ...]
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const root = path.resolve(__dirname, "..");
const tests = [
  ["native host (real Chromium)", "tools/picker/tests/native-test.js"],
  ["browser control UI", "tools/picker/tests/browser-control-ui-test.js"],
  ["contexts UI", "tools/picker/tests/contexts-ui-test.js"],
  ["csp UI", "tools/picker/tests/csp-ui-test.js"],
  ["targeted DAST (fixtures)", "tools/picker/tests/dast-real-test.js"],
  ["targeted DAST coverage", "tools/picker/tests/dast-coverage-real-test.js"],
  ["IAST real", "tools/picker/tests/iast-real-test.js"],
  ["authz real", "tools/picker/tests/authz-real-test.js"],
  ["authz isolated transport", "tools/picker/tests/authz-transport-real-test.js"],
  ["DAST start contract", "tools/picker/tests/dast-start-real-test.js"],
  ["CDP screenshots and PDF", "tools/picker/tests/cdp-screenshot.browser.cjs"],
  ["upload and save_file", "tools/picker/tests/upload-lifecycle.browser.cjs"],
  ["security browser smoke", "tools/security/tests/browser-smoke.cjs"],
  ["security settings UI", "tools/security/tests/ui.browser.cjs"],
  ["security utilities", "tools/security/tests/utilities.browser.cjs"],
  ["security lifecycle", "tools/security/tests/lifecycle.browser.cjs"],
  ["engine parity", "tools/security/tests/browser-parity.cjs"],
  ["runtime DAST", "tools/security/tests/runtime-browser-dast.cjs"],
  ["CVE wire parity", "tools/security/tests/cve-wire-parity.browser.cjs"],
  ["DAST link discovery", "tools/security/tests/html-discovery.browser.cjs"],
  ["candidate investigation", "tools/security/tests/investigation.browser.cjs"],
  ["recording follows tabs", "tools/picker/tests/record-arm.browser.cjs"],
  ["model 404 message", "tools/picker/tests/model-404.browser.cjs"],
  ["managed browser accounts", "tools/host/tests/security-browser.test.cjs"],
  ["managed browser workers", "tools/host/tests/security-browser-workers.test.cjs"],
  ["DVWA demo rehearsal", "tools/picker/tests/dvwa-rehearsal.cjs"],
];
async function main() {
  const filter = process.argv.slice(2);
  const selected = tests.filter(([label, file]) => !filter.length || filter.some(term => label.includes(term) || file.includes(term)));
  if (!selected.length) { console.error("no test matches:", filter.join(" ")); process.exit(2); }
  const dvwaOrigin = process.env.DVWA_ORIGIN || "http://127.0.0.1:4280/";
  const dvwaUp = await fetch(dvwaOrigin, { redirect: "manual", signal: AbortSignal.timeout(2500) }).then(() => true).catch(() => false);
  // The managed-browser host tests run against the installed local runtime and never download one.
  const runtime = process.env.CERT_X_TEST_RUNTIME || path.join(process.env.LOCALAPPDATA || "", "cert-x", "security-runtime");
  const runtimeUp = fs.existsSync(path.join(runtime, "installed.json"));
  let failed = 0, skipped = 0;
  for (const [label, file] of selected) {
    if (file.endsWith("dvwa-rehearsal.cjs") && !dvwaUp) {
      console.log("SKIP  " + label.padEnd(28) + " (DVWA not reachable at " + dvwaOrigin + ")"); skipped++; continue;
    }
    if (file.includes("/security-browser") && !runtimeUp) {
      console.log("SKIP  " + label.padEnd(28) + " (no managed runtime at " + runtime + "; set it up under Security testing → Local runtime & connections)"); skipped++; continue;
    }
    const env = runtimeUp ? { ...process.env, CERT_X_TEST_RUNTIME: runtime } : process.env;
    const result = spawnSync(process.execPath, [path.join(root, file)], { cwd: root, env, timeout: 480000, encoding: "utf8" });
    const lines = String(result.stdout || "").trim().split("\n").filter(Boolean);
    const tail = (lines[lines.length - 1] || "").slice(0, 110);
    if (result.status === 0) console.log("PASS  " + label.padEnd(28) + (tail ? " " + tail : ""));
    else { failed++; console.log("FAIL  " + label.padEnd(28) + " exit=" + result.status + (tail ? " " + tail : "")); }
  }
  console.log("\n" + (selected.length - skipped) + " run, " + failed + " failed" + (skipped ? ", " + skipped + " skipped" : "") + (failed ? " — rerun a failing check alone before treating it as a regression" : ""));
  process.exit(failed ? 1 : 0);
}
main();

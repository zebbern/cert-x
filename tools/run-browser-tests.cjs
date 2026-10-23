#!/usr/bin/env node
// Runs every real-Chromium validation check with real exit codes so red stays
// red — the default node --test glob does not include these .cjs/.js checks
// and they silently skip otherwise. Known failures are documented in
// HANDOFF.md; this runner reports reality and exits non-zero on any failure.
// Usage: node tools/run-browser-tests.cjs [filter ...]
const { spawnSync } = require("node:child_process");
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
  ["security browser smoke", "tools/security/tests/browser-smoke.cjs"],
  ["security settings UI", "tools/security/tests/ui.browser.cjs"],
  ["security utilities", "tools/security/tests/utilities.browser.cjs"],
  ["security lifecycle", "tools/security/tests/lifecycle.browser.cjs"],
  ["engine parity", "tools/security/tests/browser-parity.cjs"],
  ["runtime DAST", "tools/security/tests/runtime-browser-dast.cjs"],
  ["DVWA demo rehearsal", "tools/picker/tests/dvwa-rehearsal.cjs"],
];
async function main() {
  const filter = process.argv.slice(2);
  const selected = tests.filter(([label, file]) => !filter.length || filter.some(term => label.includes(term) || file.includes(term)));
  if (!selected.length) { console.error("no test matches:", filter.join(" ")); process.exit(2); }
  const dvwaOrigin = process.env.DVWA_ORIGIN || "http://127.0.0.1:4280/";
  const dvwaUp = await fetch(dvwaOrigin, { redirect: "manual", signal: AbortSignal.timeout(2500) }).then(() => true).catch(() => false);
  let failed = 0, skipped = 0;
  for (const [label, file] of selected) {
    if (file.endsWith("dvwa-rehearsal.cjs") && !dvwaUp) {
      console.log("SKIP  " + label.padEnd(28) + " (DVWA not reachable at " + dvwaOrigin + ")"); skipped++; continue;
    }
    const result = spawnSync(process.execPath, [path.join(root, file)], { cwd: root, timeout: 480000, encoding: "utf8" });
    const lines = String(result.stdout || "").trim().split("\n").filter(Boolean);
    const tail = (lines[lines.length - 1] || "").slice(0, 110);
    if (result.status === 0) console.log("PASS  " + label.padEnd(28) + (tail ? " " + tail : ""));
    else { failed++; console.log("FAIL  " + label.padEnd(28) + " exit=" + result.status + (tail ? " " + tail : "")); }
  }
  console.log("\n" + (selected.length - skipped) + " run, " + failed + " failed" + (skipped ? ", " + skipped + " skipped" : "") + (failed ? " — rerun a failing check alone before treating it as a regression; security lifecycle is known timing-flaky under load" : ""));
  process.exit(failed ? 1 : 0);
}
main();

# Targeted testing regression tests

cert-x includes its security runtime. There is no separate extension setup or pairing step.

This directory retains the selected-request, exact-input, Boolean/SSTI, and isolated-account regression suites. They import the maintained implementations from `security/compat/`; there are no duplicate runtime copies here.

Run:

```powershell
node --test tools/ptk/*.test.cjs tools/ptk/*.test.mjs
```

The original companion preparation scripts, patches, coordinator, contracts, and their previous tests are preserved under `tools/security/reference/companion/` for migration evidence and reproduction. They are not part of the active build. Restore their original directory layout in a separate test checkout before running those historical scripts; do not run them against the maintained runtime.

See `security/README.md` for native scanning, configurable testing, and current validation commands.

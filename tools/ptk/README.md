# Targeted testing regression tests

cert-x includes its security runtime. There is no separate extension setup or pairing step.

This directory retains the selected-request, exact-input, Boolean/SSTI, and isolated-account regression suites. They import the maintained implementations from `security/compat/`; there are no duplicate runtime copies here.

Run:

```powershell
node --test tools/ptk/*.test.cjs tools/ptk/*.test.mjs
```

See `security/README.md` for native scanning, configurable testing, and current validation commands.

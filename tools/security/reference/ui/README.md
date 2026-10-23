# Historical companion settings

These are the superseded PTK and targeted-DAST settings modules, styles, and browser tests. They are retained to reproduce the earlier companion UI; they are not loaded by cert-x and are not part of the current regression test count.

Current settings use `providers/security.js`. Legacy `section=ptk` and `section=dast` links resolve to Security testing; `section=authz` opens its accounts view. Active comparison status cards use `providers/security.css`.

The old browser tests can be run explicitly with `node --test tools/security/reference/ui/*.test.js`. Their mocked companion protocol and installation instructions are historical behavior, not the current installation workflow.

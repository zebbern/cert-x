# Verification references

`baseline.json` pins the unmodified supplied PTK v10 extension used by differential browser tests. The reference preparation helper verifies the full source-tree digest before accepting an oracle, including paths supplied through `PTK_REFERENCE_ROOT`.

Current acceptance tests live in `tools/security/tests`, `tools/picker/tests`, `tools/host/tests`, `providers/*.test.js`, and the compatibility tests in `tools/ptk`. The previous two-extension companion implementation and its tests were removed on 2026-10-29 because they targeted code that no longer exists; git history keeps them (last present at a81b057).

# Verification references

`baseline.json` pins the unmodified supplied PTK v10 extension used by differential browser tests. The reference preparation helper verifies the full source-tree digest before accepting an oracle, including paths supplied through `PTK_REFERENCE_ROOT`.

The companion and UI files here preserve the previous two-extension implementation and its test assumptions for reproduction and review. They retain their original paths and instructions in their text; restore the original layout if investigating that historical implementation. The maintained runtime is under `security/`, and current installation/build instructions are in the root README.

Current acceptance tests live in `tools/security/tests`, `tools/picker/tests`, `tools/host/tests`, `providers/*.test.js`, and the retained compatibility tests in `tools/ptk`. Archived tests are not counted as passing evidence for the native implementation.

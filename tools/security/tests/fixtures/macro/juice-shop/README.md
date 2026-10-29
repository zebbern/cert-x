# Juice Shop macro release fixtures

This directory holds the authenticated OWASP Juice Shop journey used by PTK
macro import, replay, and macro-guided scan release tests. Its source of truth
is the `pentestkit` repository (`fixture-set.json`); in cert-x,
`tools/security/tests/runtime-macroFlow.test.mjs` imports
`recordings/chrome-recorder.json`.

The journey is defined in `journey.json`. Every recording must represent that
same browser journey. `fixture-set.json` records the producer, format, expected
filename, and integrity hash once a recording has been accepted.

## Recordings

Accepted recordings live in `recordings/`:

- `ptk-flow.json` - native PTK Flow export from the PTK recorder.
- `ptk-xml.rec` - XML export from the same PTK recording.
- `zap-zest.zst` - Zest recording produced by the ZAP recorder.
- `chrome-recorder.json` - Chrome DevTools Recorder export.
- `katalon.xml` - supported Katalon/Selenese XML. The recorder's initial
  `chrome://newtab/` navigation was removed because PTK imports only HTTP(S)
  target navigation.
- `selenium.side` - copy of the Firefox Selenium IDE recording with an explicit
  second product-A click added after Selenium IDE failed to save the new run.
  This is a repaired fixture, not a newly saved native recording.

The original Firefox recording remains at `../selenium-juice-shop.side` for
provenance. It is not the release-matrix fixture. Katalon Recorder 7.1.0 does
not expose a `.side` export in its current UI.

Accepted external recordings retain their producer-native commands except for
the narrowly documented acceptance repairs above. All six must perform the
same login, profile, product A → A → B, basket removal and search journey;
search starts directly from the basket after removal.

The six required recordings are listed in `fixture-set.json`. The Agent copy
must retain the same six IDs, producer identities and SHA-256 hashes.

## Credentials and sanitisation

The fixture account is a deliberately public, local-only demo account. Literal
credentials remain in recordings because PTK import and automation must replay
the document exactly as supplied. These files must never contain production
credentials, session cookies, JWTs, browser-profile paths, or unrelated local
storage.

Before a recording is committed it must:

1. replay successfully in its producer when that producer supports replay;
2. import into PTK without required-step loss;
3. finish at the search result defined in `journey.json`;
4. pass the fixture integrity and sensitive-data checks (the only allowed
   literal credential is the public local demo account in `journey.json`); and
5. be copied, with matching hashes, into the standalone `ptk-agent` release
   test fixtures.

## Release matrix

With Juice Shop available at `http://localhost:3001`, rebuild both Chromium
artifacts and run the complete matrix from the `pentestkit` repository:

```sh
npm run build_pkg
npm run test:macro-release
```

The matrix runs the scripted smoke baseline and every accepted macro against
both the Full and Automation artifacts. Each run uses an isolated temporary
browser profile. Before each measured cell, a separate no-extension browser
clears the basket through visible UI controls, reopens it and verifies a fresh
server response with zero products; missing or failed preflight evidence blocks
the cell. That preparation traffic never counts as scan evidence. The measured
run must finish the visible journey and return findings from
DAST, IAST, SAST and SCA, and must retain the release-critical SQL injection,
JWT, SPA DOM XSS, IAST, SAST and SCA rules. The generated Markdown report
compares each macro only with the smoke baseline for the same extension mode.

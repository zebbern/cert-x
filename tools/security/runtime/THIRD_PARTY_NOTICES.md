# Managed dependencies

All installed archives and packages retain their original license and notice files. The lockfiles record exact versions and integrity values; this index does not replace the upstream license texts.

| Component | License information |
| --- | --- |
| Playwright Core 1.64.1 | Apache-2.0 |
| ws 8.18.3 | MIT |
| hpack.js 2.1.6 | MIT |
| node-forge 1.4.0 | BSD-3-Clause OR GPL-2.0 |
| Chromium / ChromeDriver | Chromium notices and bundled third-party notices in the downloaded distribution |
| ZAP 2.17.0 | Distribution license/notice files, including separate add-on licenses |
| Eclipse Temurin Java 21 | OpenJDK distribution license and Classpath Exception notices |
| Python build standalone | Python and bundled-library licenses in the pinned distribution |
| webhook-mcp-server 3.0.0 | MIT; Python dependency licenses remain in installed wheel metadata |

The source and checksum for each managed binary are recorded in `assets.lock.json`. JavaScript transitive licenses are recorded in `package-lock.json`; Python dependencies and wheel hashes are fixed in `requirements.lock`. Updating a component requires refreshing these records and running the affected verification, not following a moving branch during a normal build.

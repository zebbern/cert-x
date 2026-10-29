// Focused original-PTK/owned comparison: asynchronous storage, object messages,
// and authenticated SPA script collection. The shared browser fixture retains
// raw snapshots and wire traffic in a separate evidence file.
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const result = spawnSync(process.execPath, [path.join(__dirname, 'collection-parity.browser.cjs')], {
  env: {
    ...process.env,
    COLLECTION_CASES: 'asyncStorage,asyncStorageSafe,messageObject,messageObjectSafe,spaDynamic',
    COLLECTION_EVIDENCE_NAME: 'collection-combinations.json',
    COLLECTION_MESSAGE_TIMING: '0',
    COLLECTION_VARIANT: ''
  },
  stdio: 'inherit'
});
if (result.error) throw result.error;
process.exitCode = result.status ?? 1;

'use strict';
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto');
// Snapshot installed execution code when the process loads it. An updated
// client must distinguish a still-running older daemon from the new runtime.
function runtimeRevision(directory = __dirname) {
  const hash = crypto.createHash('sha256');
  for (const name of fs.readdirSync(directory).filter(name => name.endsWith('.cjs')).sort()) {
    hash.update(name + '\0'); hash.update(fs.readFileSync(path.join(directory, name))); hash.update('\0');
  }
  return hash.digest('hex');
}
module.exports = { runtimeRevision };

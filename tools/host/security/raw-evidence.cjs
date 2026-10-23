'use strict';
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');

function createEvidenceStore(root) {
  if (!root) throw Error('Persistent raw evidence root is required');
  const directory = path.join(root, 'raw-evidence');
  function authorize(record, context) {
    if (!record || !context.owner || record.owner !== context.owner || record.runId !== context.runId || record.workspaceId !== (context.workspaceId || null)) {
      throw Error('Raw evidence is unavailable or belongs to another chat/workspace');
    }
  }
  return {
    async save(result, context) {
      const evidenceId = crypto.randomUUID();
      const record = { schema: 'cert-x-raw-evidence/v1', evidenceId, owner: context.owner, workspaceId: context.workspaceId || null, runId: context.runId, createdAt: Date.now(), result };
      const data = Buffer.from(JSON.stringify(record));
      await fs.mkdir(directory, { recursive: true, mode: 0o700 });
      await fs.writeFile(path.join(directory, evidenceId + '.json'), data, { flag: 'wx', mode: 0o600 });
      return { evidenceId, evidenceBytes: data.length, evidenceSha256: crypto.createHash('sha256').update(data).digest('hex'), evidencePersisted: true };
    },
    async read(args, context) {
      if (!/^[a-f0-9-]{36}$/.test(args.evidenceId || '')) throw Error('Invalid raw evidence identifier');
      const offset = args.offset ?? 0, limit = args.limit ?? 65536;
      if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > 131072) throw Error('Use a non-negative offset and a page size from 1 to 131072 bytes');
      let record, data;
      try { data = await fs.readFile(path.join(directory, args.evidenceId + '.json')); record = JSON.parse(data); }
      catch { throw Error('Raw evidence is unavailable'); }
      authorize(record, context);
      return { evidenceId: args.evidenceId, sourceRunId: record.runId, encoding: 'base64', base64: data.subarray(offset, offset + limit).toString('base64'), offset, total: data.length, nextOffset: offset + limit < data.length ? offset + limit : null };
    }
  };
}
module.exports = { createEvidenceStore };

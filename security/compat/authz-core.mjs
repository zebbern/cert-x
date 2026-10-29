import './dast-inputs.js';
import { canonicalOrigin, canonicalPath, scopedUrl } from './dast-core.mjs';
import { DEFAULT_CREDENTIAL_HEADERS } from './authz-transport.mjs';

const clone = value => JSON.parse(JSON.stringify(value));
const inputs = globalThis.CertXDastInputs;
const terminal = new Set(['completed', 'stopped', 'failed', 'expired', 'budget_exhausted', 'interrupted']);
const fail = (state, message) => Object.assign(Error(message), { state });
const endpoint = request => { const url = new URL(request.url); return url.origin + url.pathname; };
export const isCredentialField = name => /^(?:auth|authorization|authentication|authtoken|accesstoken|refreshtoken|idtoken|token|tokentype|session|sessionid|csrf|csrftoken|xsrf|xsrftoken|password|passwd|apikey|jwt|bearer|credentials?|secret)$/i.test(String(name).replace(/[^a-z0-9]/gi, ''));
export function rejectBodyCredentials(value) {
  const bad = name => isCredentialField(name) || String(name).split(/[.\[\]]/).some(isCredentialField);
  if ([...new URL(value.url).searchParams.keys()].some(bad)) throw Error('Access tests currently support header/cookie authentication only. Remove credential fields from the captured query or use a different read request.');
  if (!value.body) return;
  const media = (value.headers.find(header => header.name.toLowerCase() === 'content-type')?.value || '').split(';')[0].trim();
  let names;
  if (/^application\/(?:json|[a-z0-9!#$&^_.+-]+\+json)$/i.test(media)) names = inputs.parseJson(value.body).flatMap(leaf => leaf.name.split('/').slice(1).map(part => part.replaceAll('~1', '/').replaceAll('~0', '~')));
  else if (/^application\/x-www-form-urlencoded$/i.test(media)) names = [...new URLSearchParams(value.body).keys()];
  else throw Error('Access tests support inspectable JSON or URL-encoded read-only bodies only.');
  if (names.some(bad)) throw Error('Access tests currently support header/cookie authentication only. Captured body credentials or CSRF fields cannot be compared safely.');
}
function headers(value) {
  if (!Array.isArray(value) || value.length > 100) throw Error('Invalid captured access headers.');
  const names = new Set(); let bytes = 0;
  for (const header of value) {
    if (!header || !/^[!#$%&'*+.^_`|~0-9a-z-]+$/i.test(header.name) || typeof header.value !== 'string' || /[\r\n\x00]/.test(header.value) || names.has(header.name.toLowerCase())) throw Error('Malformed or repeated access headers.');
    names.add(header.name.toLowerCase()); bytes += header.name.length + header.value.length;
  }
  if (bytes > 32768) throw Error('Access headers exceed the supported limit.');
}
function request(value, plan, readOnly) {
  if (!value || !['GET', 'POST'].includes(value.method) || readOnly !== true) throw Error('Declare every access request read-only.');
  const url = scopedUrl(value.url, plan.scope); if (url.origin !== plan.origin) throw Error('Access request is outside the selected origin.');
  headers(value.headers);
  value.body ??= '';
  if (typeof value.body !== 'string' || new TextEncoder().encode(value.body).length > 65536 || value.method === 'GET' && value.body) throw Error('Unsupported access request body.');
  rejectBodyCredentials(value);
}
function claims(value) {
  if (!Array.isArray(value) || !value.length || value.length > 10) throw Error('Select one to ten identity claims.');
  const pointers = new Set();
  for (const claim of value) {
    if (!claim || typeof claim.pointer !== 'string' || claim.pointer.length > 1024 || !/^(?:\/(?:[^~]|~[01])*)*$/.test(claim.pointer) || typeof claim.expected !== 'string' || claim.expected.length > 2048 || pointers.has(claim.pointer)) throw Error('Invalid scalar identity or evidence mapping.');
    pointers.add(claim.pointer);
  }
}
export function validateAccessPlan(value, verifying = false) {
  const plan = clone(value);
  if (typeof plan.owner !== 'string' || !plan.owner || plan.owner.length > 150 || !Number.isInteger(plan.tabId) || plan.tabId < 0) throw Error('Invalid access-test owner or tab.');
  canonicalOrigin(plan.origin);
  if (!plan.scope || !Array.isArray(plan.scope.origins) || !plan.scope.origins.length || plan.scope.origins.length > 16 || !Array.isArray(plan.scope.excludePaths) || plan.scope.excludePaths.length > 50) throw Error('Specify an exact access-test scope.');
  plan.scope.origins = [...new Set(plan.scope.origins.map(canonicalOrigin))]; plan.scope.excludePaths = plan.scope.excludePaths.map(canonicalPath);
  if (!plan.scope.origins.includes(plan.origin)) throw Error('Access-test origin is outside scope.');
  const budget = plan.budget;
  if (!budget || !Number.isInteger(budget.maxRequests) || budget.maxRequests < 1 || (!Number.isFinite(budget.maxRequestsPerSecond) || budget.maxRequestsPerSecond <= 0) || budget.concurrency !== 1 || !Number.isInteger(budget.durationSeconds) || budget.durationSeconds < 1) throw Error('Access tests require positive request, rate and duration budgets; account isolation requires concurrency one.');
  const accounts = verifying ? [plan.account] : plan.accounts;
  if (!Array.isArray(accounts) || !accounts.length || accounts.length > 4) throw Error('Select one to four saved accounts.');
  const ids = new Set();
  for (const account of accounts) {
    if (!account || typeof account.id !== 'string' || !account.id || account.id === 'anonymous' || ids.has(account.id) || typeof account.label !== 'string' || !account.label || account.label.length > 100 || !Number.isInteger(account.revision) || account.revision < 1) throw Error('Invalid saved account identity.');
    ids.add(account.id); headers(account.headers);
    if (account.headers.some(header => ['host', 'content-length', 'connection', 'transfer-encoding', 'origin', 'referer', 'content-type'].includes(header.name.toLowerCase()))) throw Error('Transport and representation headers cannot be used as account credentials.');
    if (!account.headers.length || !account.probe) throw Error('An account needs explicit credentials and an identity probe.');
    request(account.probe.request, plan, account.probe.request?.method === 'GET' || account.probe.readOnly === true || account.probe.request?.readOnly === true);
    claims(account.probe.claims);
    if (!account.probe.claims.some(claim => claim.expected !== '' && claim.expected !== 'null')) throw Error('An account needs a non-null principal identity claim.');
  }
  if (verifying) return plan;
  if (!/^[\w-]{1,100}$/.test(plan.batchId || '') || typeof plan.workspaceId !== 'string' || !plan.workspaceId) throw Error('Invalid access batch or workspace.');
  if (!Array.isArray(plan.cases) || !plan.cases.length || plan.cases.length > 10) throw Error('Select one to ten access cases.');
  const caseIds = new Set();
  for (const item of plan.cases) {
    if (!item || typeof item.id !== 'string' || !item.id || caseIds.has(item.id) || typeof item.label !== 'string' || item.label.length > 150 || !ids.has(item.ownerAccountId)) throw Error('Invalid access case owner or label.'); caseIds.add(item.id);
    request(item.request, plan, item.readOnly);
    const evidence = [item.evidence?.object, item.evidence?.protected]; claims(evidence);
    if (!evidence[1].expected || evidence[1].expected === 'null') throw Error('Protected evidence requires a nonempty application-specific value.');
    if (!Array.isArray(item.expectations) || !item.expectations.length || item.expectations.length > 5) throw Error('Choose expected account access for each case.');
    const seen = new Set();
    for (const expectation of item.expectations) {
      if (!expectation || !ids.has(expectation.accountId) && expectation.accountId !== 'anonymous' || seen.has(expectation.accountId) || !['allow', 'deny'].includes(expectation.expected)) throw Error('Invalid access expectation.'); seen.add(expectation.accountId);
      if (expectation.accountId === item.ownerAccountId && expectation.expected === 'deny') throw Error('The legitimate baseline owner cannot also be expected to have denied access.');
    }
  }
  return plan;
}
function jsonResponse(response, allowNonSuccess = false) {
  if (response.opaque || response.status < 200 || response.status >= 600 || response.status >= 300 && response.status < 400 || !allowNonSuccess && response.status >= 300 || !/^application\/(?:json|[a-z0-9!#$&^_.+-]+\+json)(?:\s*;|$)/i.test(response.contentType || '')) return null;
  try {
    const leaves = inputs.parseJson(response.body), parsed = JSON.parse(response.body);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed) && (Object.hasOwn(parsed, 'errors') && (!Array.isArray(parsed.errors) || parsed.errors.length) || Object.hasOwn(parsed, 'error') && parsed.error)) return null;
    return leaves;
  } catch { return null; }
}
function matches(leaves, expected) {
  return !!leaves && expected.every(claim => { const leaf = leaves.find(item => item.name === claim.pointer); return leaf && String(leaf.value) === claim.expected; });
}
function identity(response, account, anonymous = false) {
  if (anonymous && [401, 403].includes(response.status)) return true;
  const leaves = jsonResponse(response);
  if (anonymous) return !!leaves && account.probe.claims.every(claim => leaves.find(leaf => leaf.name === claim.pointer)?.valueType === 'null');
  return matches(leaves, account.probe.claims);
}
function sameIdentityClaims(left, right) {
  const canonical = account => JSON.stringify(account.probe.claims.map(claim => [claim.pointer, claim.expected]).sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  return canonical(left) === canonical(right);
}
function evidence(response, item) {
  const leaves = jsonResponse(response, true), object = matches(leaves, [item.evidence.object]), protectedValue = matches(leaves, [item.evidence.protected]);
  return { status: response.status, objectPointer: item.evidence.object.pointer, protectedPointer: item.evidence.protected.pointer,
    responseByteLength: Math.min(1024 * 1024, Math.max(0, Number(response.responseByteLength) || new TextEncoder().encode(response.body || '').length)),
    objectMatched: object, protectedMatched: protectedValue, validJson: !!leaves, redirect: !!response.opaque || response.status >= 300 && response.status < 400 };
}
function denied(response, item) {
  if (![401, 403, 404].includes(response.status) || response.opaque || /text\/html/i.test(response.contentType || '') || /csrf|xsrf|\bexpired\b|token\s+invalid|invalid\s+(?:access\s+)?token/i.test(String(response.body || ''))) return false;
  // A denial status does not erase disclosed data. Even an ambiguous error
  // envelope containing the protected scalar cannot count as expected denial.
  try { if (matches(inputs.parseJson(response.body), [item.evidence.protected])) return false; }
  catch {
    // A declared JSON denial with duplicate keys, malformed data or an exceeded
    // analysis bound is ambiguous, not evidence of successful enforcement.
    if (/^application\/(?:json|[a-z0-9!#$&^_.+-]+\+json)(?:\s*;|$)/i.test(response.contentType || '')) return false;
  }
  try { const parsed = JSON.parse(response.body); if (parsed && (parsed.errors || parsed.error?.code && /csrf|expired/i.test(parsed.error.code))) return false; } catch { /* Plain denial text is supported. */ }
  return true;
}

export function createAccessRunner({ send, persist = async () => {}, interrupted = [], now = () => Date.now(), sleep = ms => new Promise(resolve => setTimeout(resolve, ms)), isBusy = () => false, acquire = () => true, release = () => {} }) {
  const records = new Map(interrupted.map(record => [record.batchId, { ...record, state: terminal.has(record.state) ? record.state : 'interrupted', inFlight: 0, unavailable: true }]));
  let active = false;
  const status = record => ({ batchId: record.batchId, owner: record.owner, workspaceId: record.workspaceId, state: record.state, startedAt: record.startedAt, deadline: record.deadline, requestsSent: record.requestsSent, maxRequests: record.maxRequests, inFlight: record.inFlight, progress: clone(record.progress), findingsCount: record.cells?.filter(cell => cell.outcome === 'unexpected_access').length || record.findingsCount || 0, errors: record.errors || [], warnings: record.warnings || [] });
  const save = () => persist([...records.values()].map(status));
  const get = input => { const record = records.get(input.batchId); if (!record || record.owner !== input.owner) throw Error('Access batch is unavailable or belongs to another chat.'); return record; };
  const reserve = async () => { if (active || await isBusy() || active || !acquire()) throw Error('A PTK analysis or account verification is already active.'); active = true; };
  function session(plan, record, shouldSave = true) {
    const credentialNames = [...new Set([...DEFAULT_CREDENTIAL_HEADERS, ...(plan.accounts || [plan.account]).flatMap(account => account.headers.map(header => header.name.toLowerCase()))])];
    const check = () => { if (record.cancelled) throw fail('stopped', 'Access batch stopped.'); if (now() >= record.deadline) throw fail('expired', 'Access-test time budget exhausted.'); if (record.requestsSent >= plan.budget.maxRequests) throw fail('budget_exhausted', 'Access-test request budget exhausted.'); };
    const dispatch = async (request, account, anonymous = false) => {
      check(); scopedUrl(request.url, plan.scope);
      while (now() < (record.nextRequestAt || 0)) { check(); await sleep(Math.min(100, record.nextRequestAt - now())); }
      check();
      const result = await send({ request: clone(request), credentials: anonymous ? [] : clone(account.headers), credentialNames, scope: plan.scope, deadline: record.deadline,
        beforeDispatch: async () => {
          if (await isBusy()) throw fail('failed', 'Another PTK analysis started; the access batch stopped.');
          check(); record.inFlight = 1; if (shouldSave) await save(); check(); scopedUrl(request.url, plan.scope);
          record.requestsSent++; record.nextRequestAt = now() + 1000 / plan.budget.maxRequestsPerSecond;
        } });
      record.inFlight = 0; if (shouldSave) await save();
      if (record.cancelled) throw fail('stopped', 'Access batch stopped after its in-flight request settled.');
      if (now() >= record.deadline) throw fail('expired', 'Access-test time budget exhausted.');
      if (result.status === 429) throw fail('failed', 'Target rate limit reached; access batch stopped.');
      return result;
    };
    const probe = async (account, anonymous = false) => identity(await dispatch(account.probe.request, account, anonymous), account, anonymous);
    return { dispatch, probe };
  }
  async function execute(plan, record) {
    try {
      const { dispatch, probe } = session(plan, record);
      for (const item of plan.cases) {
        const owner = plan.accounts.find(account => account.id === item.ownerAccountId);
        const ownerBefore = await probe(owner);
        const baseline = ownerBefore ? await dispatch(item.request, owner) : null;
        const ownerAfter = ownerBefore ? await probe(owner) : false;
        const baseEvidence = baseline ? evidence(baseline, item) : null;
        const validBaseline = ownerBefore && ownerAfter && baseEvidence?.objectMatched && baseEvidence?.protectedMatched;
        for (const expectation of item.expectations) {
          const anonymous = expectation.accountId === 'anonymous', account = anonymous ? owner : plan.accounts.find(account => account.id === expectation.accountId);
          const cell = { caseId: item.id, caseLabel: item.label, endpoint: endpoint(item.request), method: item.request.method, ownerAccountId: owner.id, accountId: expectation.accountId, accountLabel: anonymous ? 'Anonymous' : account.label, expected: expectation.expected,
            outcome: 'inconclusive', baseline: baseEvidence, identityBefore: false, identityAfter: false, reason: 'The owner baseline or identity could not be verified.' };
          if (validBaseline && !anonymous && expectation.expected === 'deny' && sameIdentityClaims(owner, account)) {
            cell.reason = 'Configured identity claims do not distinguish this account from the owner. Add a distinct principal, role or tenant claim before comparing denied access.';
          } else if (validBaseline) {
            cell.identityBefore = await probe(account, anonymous);
            if (cell.identityBefore) {
              const response = await dispatch(item.request, account, anonymous); cell.evidence = evidence(response, item);
              cell.identityAfter = await probe(account, anonymous);
              if (cell.identityAfter) {
                const access = cell.evidence.objectMatched && cell.evidence.protectedMatched;
                if (access && expectation.expected === 'allow') { cell.outcome = 'expected_access'; cell.reason = 'The configured object and protected evidence matched with the verified identity.'; }
                else if (denied(response, item) && expectation.expected === 'deny') { cell.outcome = 'expected_denial'; cell.reason = 'This request was denied for the verified identity.'; }
                else if (access && expectation.expected === 'deny') {
                  const repeatBefore = await probe(account, anonymous);
                  if (repeatBefore) {
                    const repeat = await dispatch(item.request, account, anonymous); cell.confirmation = evidence(repeat, item); cell.confirmationIdentity = await probe(account, anonymous);
                    if (cell.confirmationIdentity && cell.confirmation.objectMatched && cell.confirmation.protectedMatched) { cell.outcome = 'unexpected_access'; cell.reason = 'Unexpected protected access reproduced with verified identity before and after both requests.'; }
                    else cell.reason = 'Unexpected access did not reproduce with a stable verified identity.';
                  } else cell.reason = 'Identity changed before the confirmation request.';
                } else cell.reason = 'The response did not establish the expected access policy; redirects, error pages and missing evidence are inconclusive.';
              } else cell.reason = 'Identity verification failed after the object request.';
            } else cell.reason = 'Identity verification failed before the object request.';
          }
          record.cells.push(cell); record.progress.tested++; await save();
        }
      }
      record.state = 'completed';
    } catch (error) { record.state = error.state || (record.cancelled ? 'stopped' : 'failed'); record.errors.push(error.state ? error.message : 'Isolated access request failed; no automatic retry was made.'); }
    finally { record.inFlight = 0; active = false; release(); await save(); }
  }
  return {
    hasActive: () => active,
    async verify(input) {
      const plan = validateAccessPlan(input, true); await reserve();
      const record = { deadline: now() + plan.budget.durationSeconds * 1000, requestsSent: 0, inFlight: 0 };
      try { const verified = await session(plan, record, false).probe(plan.account); return { state: verified ? 'verified' : 'inconclusive', verified, accountId: plan.account.id, requestsSent: record.requestsSent, reason: verified ? 'Configured JSON identity claims matched.' : 'Identity claims could not be verified; check the probe and saved account.' }; }
      catch { return { state: 'inconclusive', verified: false, accountId: plan.account.id, requestsSent: record.requestsSent, reason: 'The isolated identity probe could not complete.' }; }
      finally { active = false; release(); }
    },
    async run(input) {
      const plan = validateAccessPlan(input), old = records.get(plan.batchId);
      if (old) { if (old.owner !== plan.owner) throw Error('Access batch belongs to another chat.'); return { accepted: false, ...status(old) }; }
      if (records.size >= 32) throw Error('Save reports and restart the browser before starting more access batches.');
      await reserve();
      const record = { batchId: plan.batchId, owner: plan.owner, workspaceId: plan.workspaceId, state: 'running', startedAt: now(), deadline: now() + plan.budget.durationSeconds * 1000,
        requestsSent: 0, maxRequests: plan.budget.maxRequests, inFlight: 0, progress: { tested: 0, total: plan.cases.reduce((sum, item) => sum + item.expectations.length, 0) }, cells: [], errors: [], warnings: ['Results cover only the selected read requests, identities and explicit expected access.'] };
      records.set(record.batchId, record);
      try { await save(); } catch { record.state = 'failed'; active = false; release(); throw Error('Could not reserve the access batch safely.'); }
      record.completion = execute(plan, record); record.completion.catch(() => {}); return { accepted: true, ...status(record) };
    },
    status: input => status(get(input)),
    async stop(input) { const record = get(input); if (!terminal.has(record.state)) { record.cancelled = true; record.state = 'stopping'; await save(); } return status(record); },
    result(input) { const record = get(input); if (record.unavailable) throw Error('Access report is unavailable after restart; open any saved report in Outputs.'); const cells = clone(record.cells), findings = cells.filter(cell => cell.outcome === 'unexpected_access'); return { ...status(record), cells, findings, report: { schema: 'cert-x-authz/v1', ...status(record), cells, findings, note: 'Configured credentials, expected values and response bodies are omitted. Matches refer only to the selected evidence mappings.' } }; },
    wait: input => get(input).completion,
  };
}

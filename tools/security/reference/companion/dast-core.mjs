// Targeted execution coordinator. Payload construction and validation are supplied by PTK.
import './dast-inputs.js';
export const DAST_PROTOCOL = 1;
export const DAST_FAMILIES = ['xss', 'sql_injection', 'open_redirect', 'sql_boolean', 'ssti', 'jsonp_callback_injection', 'response_checks'];
const jsonInputs = globalThis.CertXDastInputs;
const isJson = seed => /^application\/(?:json|[a-z0-9!#$&^_.+-]+\+json)$/i.test((seed.headers.find(header => header.name.toLowerCase() === 'content-type')?.value || '').split(';')[0].trim());
const clone = value => JSON.parse(JSON.stringify(value));
const terminal = new Set(['completed', 'stopped', 'failed', 'budget_exhausted', 'expired', 'interrupted']);
export function canonicalOrigin(value) {
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || value !== url.origin) throw Error('Scope origins must be exact HTTP(S) origins without credentials or paths.');
  return url.origin;
}
export function canonicalPath(value) {
  if (typeof value !== 'string' || !value.startsWith('/') || value.includes('//') || /[\\;?#\x00-\x20]/.test(value) || /%(?:2f|5c|2e|25)/i.test(value) || /%(?![0-9a-f]{2})/i.test(value) || /(?:^|\/)\.{1,2}(?:\/|$)/.test(value)) throw Error('Ambiguous or unsupported URL path.');
  const decoded = decodeURIComponent(value);
  if (/[\\;\x00-\x20]/.test(decoded)) throw Error('Ambiguous or unsupported URL path.');
  return decoded.replace(/\/+$/, '') || '/';
}
export function scopedUrl(value, scope) {
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash) throw Error('Requests require HTTP(S) URLs without credentials or fragments.');
  const rawPath = /^[a-z]+:\/\/[^/?#]*(\/[^?#]*)?/i.exec(value)?.[1] || '/';
  canonicalPath(rawPath);
  const pathname = canonicalPath(url.pathname);
  if (!scope.origins.includes(url.origin)) throw Error('Request is outside the selected origin scope.');
  if (scope.excludePaths.some(prefix => prefix === '/' || pathname === prefix || pathname.startsWith(prefix + '/'))) throw Error('Request path is excluded from this batch.');
  return url;
}
function pairs(value) {
  return jsonInputs.parseEncoded(value).map(field => [field.name, field.value]);
}
export function validatePlan(value) {
  const plan = clone(value);
  if (!/^[\w-]{1,100}$/.test(plan.batchId || '') || typeof plan.owner !== 'string' || !plan.owner || plan.owner.length > 150) throw Error('Invalid batch identity.');
  if (!Number.isInteger(plan.tabId) || plan.tabId < 0) throw Error('Select a browser tab.');
  if (!plan.scope || !Array.isArray(plan.scope.origins) || !plan.scope.origins.length || plan.scope.origins.length > 16) throw Error('Specify target origins.');
  plan.scope.origins = [...new Set(plan.scope.origins.map(canonicalOrigin))];
  if (!Array.isArray(plan.scope.excludePaths) || plan.scope.excludePaths.length > 50) throw Error('Invalid excluded paths.');
  plan.scope.excludePaths = [...new Set(plan.scope.excludePaths.map(canonicalPath))];
  if (!plan.origin || canonicalOrigin(plan.origin) !== plan.origin || !plan.scope.origins.includes(plan.origin)) throw Error('The selected origin is outside scope.');
  if (!Array.isArray(plan.families) || !plan.families.length || plan.families.length > DAST_FAMILIES.length || new Set(plan.families).size !== plan.families.length || plan.families.some(family => !DAST_FAMILIES.includes(family))) throw Error('Select supported targeted test families.');
  const budget = plan.budget;
  if (!budget || !Number.isInteger(budget.maxRequests) || budget.maxRequests < 1 || budget.maxRequests > 100 || budget.maxRequestsPerSecond !== 1 || budget.concurrency !== 1 || !Number.isInteger(budget.durationSeconds) || budget.durationSeconds < 1 || budget.durationSeconds > 300) throw Error('Use up to 100 requests, one request/second, concurrency one and up to 300 seconds.');
  if (!Array.isArray(plan.requests) || !plan.requests.length || plan.requests.length > 10) throw Error('Select one to ten captured requests.');
  const ids = new Set();
  for (const request of plan.requests) {
    if (typeof request.id !== 'string' || !request.id || ids.has(request.id)) throw Error('Captured request IDs must be unique.'); ids.add(request.id);
    const url = scopedUrl(request.url, plan.scope);
    if (url.origin !== plan.origin) throw Error('All selected requests must belong to the selected tab origin.');
    if (!['GET', 'POST'].includes(request.method) || request.allowReplay !== true) throw Error('Select GET/POST requests and explicitly allow their replay.');
    if (!Array.isArray(request.headers) || request.headers.length > 100) throw Error('Invalid captured request headers.');
    let headerBytes = 0;
    for (const header of request.headers) {
      if (!header || !/^[!#$%&'*+.^_`|~0-9a-z-]+$/i.test(header.name) || typeof header.value !== 'string' || /[\r\n\x00]/.test(header.value)) throw Error('Malformed captured headers are unsupported.');
      headerBytes += header.name.length + header.value.length;
    }
    if (headerBytes > 32768) throw Error('Captured headers exceed the batch limit.');
    const contentType = request.headers.find(header => header.name.toLowerCase() === 'content-type')?.value || '';
    if (request.body != null && typeof request.body !== 'string') throw Error('Captured bodies must be text.');
    request.body ||= '';
    if (new TextEncoder().encode(request.body).length > 65536) throw Error('Captured body exceeds 64 KiB.');
    if (request.method === 'GET' && request.body) throw Error('GET requests with bodies are unsupported.');
    const json = isJson(request), leaves = json ? jsonInputs.parseJson(request.body) : [];
    if (json && contentType.includes(';') && !/^\s*charset\s*=\s*(?:utf-8|"utf-8"|'utf-8')\s*$/i.test(contentType.slice(contentType.indexOf(';') + 1))) throw Error('JSON bodies require UTF-8 without unsupported media parameters.');
    if (request.body && !json && !/^application\/x-www-form-urlencoded(?:\s*;\s*charset\s*=\s*["']?utf-8["']?)?\s*$/i.test(contentType)) throw Error('Only UTF-8 URL-encoded forms and JSON bodies are supported.');
    const collections = { query: pairs(url.search.slice(1)), form: json ? [] : pairs(request.body), json: leaves.map(leaf => [leaf.name, leaf.value]) };
    if (!Array.isArray(request.parameters) || !request.parameters.length && plan.families.some(family => family !== 'response_checks') || request.parameters.length > 20) throw Error('Active checks require one to twenty selected inputs; response checks can omit inputs.');
    const selected = new Set();
    for (const parameter of request.parameters) {
      if (!['query', 'form', 'json'].includes(parameter.location) || typeof parameter.name !== 'string' || !Number.isInteger(parameter.index) || parameter.index < 0 || collections[parameter.location][parameter.index]?.[0] !== parameter.name || parameter.location === 'json' && leaves[parameter.index]?.valueType !== 'string') throw Error('Selected parameter no longer matches a supported captured string field.');
      if (/^(?:csrf|_csrf|xsrf|session(?:id)?|authorization|password|passwd|access_token|refresh_token)$/i.test(parameter.location === 'json' ? parameter.name.split('/').at(-1).replaceAll('~1', '/').replaceAll('~0', '~') : parameter.name)) throw Error('Authentication/session parameters are not mutated by this preset.');
      const key = parameter.location + ':' + parameter.index + ':' + parameter.name; if (selected.has(key)) throw Error('Parameter selected more than once.'); selected.add(key);
    }
  }
  return plan;
}
function selectedDifference(seed, schema) {
  if (schema.request.method !== seed.method) throw Error('PTK attempted to change the selected HTTP method.');
  const beforeUrl = new URL(seed.url), afterUrl = new URL(schema.request.url);
  if (beforeUrl.origin !== afterUrl.origin || beforeUrl.pathname !== afterUrl.pathname) throw Error('PTK attempted to change the selected endpoint.');
  const json = isJson(seed), nextBody = schema.request.body?.text || '';
  const before = { query: pairs(beforeUrl.search.slice(1)), form: json ? [] : pairs(seed.body) };
  const after = { query: pairs(afterUrl.search.slice(1)), form: json ? [] : pairs(nextBody) };
  let expectedWire = { url: seed.url, body: seed.body };
  let observedWire = { url: schema.request.url, body: nextBody };
  let changed = 0;
  for (const location of ['query', 'form']) {
    if (before[location].length !== after[location].length) throw Error('PTK attempted to add or remove request fields.');
    before[location].forEach(([name, value], index) => {
      if (after[location][index]?.[0] !== name) throw Error('PTK attempted to reorder or rename request fields.');
      if (after[location][index][1] !== value) {
        const selected = seed.parameters.find(item => item.location === location && item.name === name && item.index === index);
        if (!selected) throw Error('PTK attempted to mutate an unselected field.'); changed++;
        expectedWire = jsonInputs.replaceRequestInput(expectedWire, selected, 'certx-selected-value');
        observedWire = jsonInputs.replaceRequestInput(observedWire, selected, 'certx-selected-value');
      }
    });
  }
  if (json && nextBody !== seed.body) {
    const previous = jsonInputs.parseJson(seed.body), next = jsonInputs.parseJson(nextBody);
    if (previous.length !== next.length) throw Error('PTK attempted to add or remove JSON fields.');
    for (let index = 0; index < previous.length; index++) {
      const leaf = previous[index], other = next[index];
      if (leaf.name !== other.name || leaf.valueType !== other.valueType) throw Error('PTK attempted to change JSON structure or field types.');
      if (leaf.value !== other.value) {
        const selected = seed.parameters.find(item => item.location === 'json' && item.name === leaf.name && item.index === index);
        if (!selected || leaf.valueType !== 'string') throw Error('PTK attempted to mutate an unselected JSON field.');
        expectedWire = jsonInputs.replaceRequestInput(expectedWire, selected, 'certx-selected-value');
        observedWire = jsonInputs.replaceRequestInput(observedWire, selected, 'certx-selected-value'); changed++;
      }
    }
  }
  if (expectedWire.url !== observedWire.url || expectedWire.body !== observedWire.body) throw Error('PTK attempted to rewrite unselected request bytes.');
  return changed;
}
function evidence(schema) {
  const response = schema.response || {};
  return { method: schema.request.method, endpoint: new URL(schema.request.url).origin + new URL(schema.request.url).pathname,
    status: Number(response.statusCode) || 0, responseLength: typeof response.body === 'string' ? response.body.length : 0,
    responseExcerpt: String(response.body || '').slice(0, 4096), responseTruncated: String(response.body || '').length > 4096,
    durationMs: Number(response.timeMs) || 0,
    ...(Number(response.statusCode) >= 300 && Number(response.statusCode) < 400 ? { location: String(response.headers?.find(header => header.name.toLowerCase() === 'location')?.value || '').slice(0, 4096), redirectFollowed: false } : {}) };
}
export function redirectVerdict(attack, original, task) {
  const destination = value => {
    if (![301, 302, 303, 307, 308].includes(Number(value.response?.statusCode))) return null;
    const headers = value.response.headers?.filter(header => header.name.toLowerCase() === 'location') || [];
    if (headers.length !== 1) return null;
    try { const url = new URL(headers[0].value, value.request.url); return !url.username && !url.password ? url : null; } catch { return null; }
  };
  const actual = destination(attack), prior = destination(original), marker = new URL(task.payload);
  const success = marker.origin === 'https://cert-x-redirect.invalid' && actual?.origin === marker.origin && actual?.href === marker.href && prior?.href !== marker.href;
  return { success, proof: success ? actual.href : '' };
}
const parameterKey = parameter => parameter.location + ':' + parameter.index + ':' + parameter.name;
const mediaType = schema => String(schema.response?.headers?.find(header => header.name.toLowerCase() === 'content-type')?.value || '').split(';')[0].trim().toLowerCase();
export function normalizeReflectedInput(body, mutated, original) {
  if (!mutated || mutated === original) return body;
  const html = value => value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');
  const forms = value => [value, html(value), html(value).replaceAll('&#39;', '&#x27;'), html(value).replaceAll('&#39;', '&#039;'), JSON.stringify(value).slice(1, -1), encodeURIComponent(value),
    encodeURIComponent(value).replace(/[!'()*]/g, character => '%' + character.charCodeAt(0).toString(16).toUpperCase()), new URLSearchParams([['v', value]]).toString().slice(2)];
  const from = forms(mutated), to = forms(original), mappings = from.map((value, index) => [value, to[index]]).sort((a, b) => b[0].length - a[0].length);
  let result = body; const replaced = new Set();
  for (const [value, replacement] of mappings) if (value && !replaced.has(value)) { replaced.add(value); result = result.split(value).join(replacement); }
  return result;
}
function responseSignature(schema, mutated, original) {
  const code = Number(schema.response?.statusCode);
  if (code < 200 || code >= 300 || typeof schema.response?.body !== 'string') return null;
  return JSON.stringify([code, mediaType(schema), normalizeReflectedInput(schema.response.body, mutated, original)]);
}
async function booleanCheck(task, originalSchema, baseline, secondBaseline, mutate, send) {
  const original = task.originalValue, signature = responseSignature(baseline), second = responseSignature(secondBaseline);
  if (signature === null || signature !== second) return { inconclusive: true, reason: 'The two baseline responses were not stable enough for boolean comparison.' };
  const trueResults = [], falseResults = [], evidenceRows = [];
  const values = (a, b) => task.context === 'numeric' ? original + ' AND ' + a + '=' + b : original + (task.context === 'single-quoted' ? "' AND '" + a + "'='" + b : '" AND "' + a + '"="' + b);
  for (let round = 0; round < 2; round++) for (const [a, b] of [[23, 29], [37, 41]]) for (const truth of [true, false]) {
    const payload = values(a, truth ? a : b), response = await send(mutate(originalSchema, task.parameter, payload));
    (truth ? trueResults : falseResults).push(responseSignature(response, payload, original)); evidenceRows.push({ truth, round, ...evidence(response) });
  }
  if ([...trueResults, ...falseResults].some(value => value === null) || !trueResults.every(value => value === trueResults[0]) || !falseResults.every(value => value === falseResults[0])) return { inconclusive: true, reason: 'True/false controls were unstable or unusable.', evidenceRows };
  if (trueResults[0] === falseResults[0]) return { matched: false, evidenceRows };
  if (trueResults[0] !== signature) return { inconclusive: true, reason: 'The true predicate responses did not preserve either baseline.', evidenceRows };
  return { matched: falseResults[0] !== signature, evidenceRows, proof: 'Two independent constant predicates each repeated: true responses matched both baselines, false responses were stable and different.' };
}
async function templateCheck(task, originalSchema, baseline, mutate, send) {
  const marker = () => 'certx' + crypto.randomUUID().replaceAll('-', '');
  const controlMarker = marker(), controlText = controlMarker + '23*29' + controlMarker;
  const control = await send(mutate(originalSchema, task.parameter, task.originalValue + controlText));
  if (responseSignature(control) === null || !control.response.body.includes(controlText)) return { inconclusive: true, reason: 'The unevaluated arithmetic control was not returned intact.' };
  const probes = [[17, 19], [23, 29]].map(([a, b]) => {
    const tag = marker(), expression = a + '*' + b, wrapped = task.template === 'mustache' ? '{{' + expression + '}}' : task.template === 'dollar' ? '${' + expression + '}' : '<%=' + expression + '%>';
    return { payload: task.originalValue + tag + wrapped + tag, expected: tag + a * b + tag };
  });
  const rows = [], matches = [];
  for (const probe of probes) {
    const response = await send(mutate(originalSchema, task.parameter, probe.payload)); rows.push(evidence(response));
    matches.push(responseSignature(response) !== null && response.response.body.includes(probe.expected) && !baseline.response.body.includes(probe.expected) && !control.response.body.includes(probe.expected));
  }
  if (!matches.every(Boolean)) return { matched: false, evidenceRows: rows };
  for (const probe of probes) {
    const response = await send(mutate(originalSchema, task.parameter, probe.payload)); rows.push(evidence(response));
    if (responseSignature(response) === null || !response.response.body.includes(probe.expected)) return { inconclusive: true, reason: 'Template arithmetic did not reproduce.', evidenceRows: rows };
  }
  return { matched: true, evidenceRows: rows, proof: 'Two distinct arithmetic products appeared between unique markers and reproduced; the unevaluated control remained literal.' };
}
function callbackInvocation(schema, callback) {
  if (!/^(?:application|text)\/(?:[a-z0-9.+-]*\+)?(?:javascript|ecmascript|json)$/i.test(mediaType(schema)) || responseSignature(schema) === null) return false;
  const body = schema.response.body.trim(), prefix = body.replace(/^\/\*[^*]*\*\/\s*/, '');
  const match = new RegExp('^' + callback + '\\s*\\(([\\s\\S]*)\\)\\s*;?$').exec(prefix);
  if (!match) return false;
  try { JSON.parse(match[1]); return true; } catch { return false; }
}
export function createTargetedRunner({ loadPtk, persist = async () => {}, interrupted = [], now = () => Date.now(), sleep = ms => new Promise(resolve => setTimeout(resolve, ms)), isBusy = () => false, acquire = () => true, release = () => {} }) {
  const records = new Map(interrupted.map(record => [record.batchId, { ...record, state: terminal.has(record.state) ? record.state : 'interrupted', inFlight: 0, resultsUnavailable: true, warnings: ['Companion restarted; this batch will not be replayed. Saved reports remain available in cert-x Outputs.'] }]));
  let active = null, reservation = Promise.resolve();
  const publicStatus = record => ({ batchId: record.batchId, owner: record.owner, state: record.state, startedAt: record.startedAt, deadline: record.deadline,
    requestsSent: record.requestsSent, inFlight: record.inFlight, maxRequests: record.maxRequests, progress: record.progress, findingsCount: record.findings ? record.findings.length : record.findingsCount || 0,
    observationsCount: record.observations?.length || record.observationsCount || 0,
    coverageSummary: record.coverage ? Object.fromEntries(['tested', 'skipped', 'unsupported', 'inconclusive'].map(state => [state, record.coverage.filter(item => item.state === state).length])) : record.coverageSummary,
    warnings: record.warnings || [], errors: record.errors || [] });
  const save = async () => persist(Array.from(records.values()).map(publicStatus));
  const get = (batchId, owner) => { const value = records.get(batchId); if (!value || value.owner !== owner) throw Error('Batch is unavailable or belongs to another chat.'); return value; };
  const stateError = (state, message) => Object.assign(Error(message), { state });
  async function execute(plan, record) {
    let currentCoverage;
    try {
      const ptk = await loadPtk();
      const check = () => {
        if (record.cancelled) throw stateError('stopped', 'Batch stopped by the user.');
        if (now() >= record.deadline) throw stateError('expired', 'Batch time budget exhausted.');
        if (record.requestsSent >= plan.budget.maxRequests) throw stateError('budget_exhausted', 'Batch request budget exhausted.');
      };
      const send = async (schema, seed, phase, allowRedirect = false, coverage) => {
        currentCoverage = coverage;
        check(); scopedUrl(schema.request.url, plan.scope); selectedDifference(seed, schema);
        while (now() < (record.nextRequestAt || 0)) { check(); await sleep(Math.min(100, record.nextRequestAt - now())); }
        check();
        schema.opts = { ...schema.opts, follow_redirect: false, retry_on_transport_failure: false, transport_retry_count: 0, transport_retry_delay_ms: 0, keepalive: false,
          // PTK strips explicit Cookie headers under credentials:'omit'. With
          // a captured Cookie, its DNR transport sets that exact frozen value;
          // without one, omit ambient browser cookies rather than changing identity.
          override_headers: true, preserve_browser_headers: true, strict_cookie_override: true,
          credentials: schema.request.headers?.some(header => header.name.toLowerCase() === 'cookie') ? 'include' : 'omit',
          requestTimeoutMs: Math.max(1, Math.min(10000, record.deadline - now())) };
        record.requestsSent++; record.inFlight = 1; await save();
        let response, dispatched = false;
        try {
          if (record.cancelled) throw stateError('stopped', 'Batch stopped before dispatch.');
          if (now() >= record.deadline) throw stateError('expired', 'Batch time budget exhausted before dispatch.');
          scopedUrl(schema.request.url, plan.scope); selectedDifference(seed, schema);
          // PTK's parser can normalize forms before we restore captured text.
          // Its DNR rules consume the header array, not the later fetch header
          // map, so a parser-generated Content-Length can truncate the body.
          // Let fetch frame the actual UTF-8 bytes for every replay variant.
          schema.request.headers = (schema.request.headers || []).filter(header => header.name.toLowerCase() !== 'content-length');
          if (typeof schema.request.body?.text === 'string') schema.request.bodySize = new TextEncoder().encode(schema.request.body.text).length;
          record.nextRequestAt = now() + 1000; dispatched = true;
          if (coverage) { coverage.probesSent++; coverage.state = 'inconclusive'; coverage.reason = 'Selected checks have not finished.'; }
          response = await ptk.send(schema);
        } finally { if (!dispatched) record.requestsSent--; record.inFlight = 0; await save(); }
        if (record.cancelled) throw stateError('stopped', 'Batch stopped; its last in-flight request has settled.');
        if (now() >= record.deadline) throw stateError('expired', 'Batch time budget exhausted.');
        if (!response?.response || response.response.errorName || response.response.errorMessage) throw Error('Request transport failed; no automatic retry was made.');
        if (typeof response.response.body !== 'string' || response.response.body.length > 1024 * 1024) throw Error('The response body exceeds the one-MiB analysis limit or is not text.');
        const code = Number(response.response.statusCode);
        if (!Number.isFinite(code) || code < 100 || code >= 300 && code < 400 && !allowRedirect) throw Error('Redirect or opaque response blocked; no redirect hop was followed.');
        if ([401, 403].includes(code)) throw Error('Authentication or access was rejected; recheck the selected account before testing.');
        if (code === 429) throw Error('Target rate limit reached; the batch stopped.');
        if (phase === 'baseline' && !plan.families.includes('response_checks') && (code < 200 || code >= (allowRedirect ? 400 : 300))) throw Error('The baseline did not return a successful HTTP response.');
        return response;
      };
      const prepared = plan.requests.map(seed => {
        const originalSchema = ptk.parse(seed), tasks = ptk.build(originalSchema, seed.parameters, plan.families);
        if (!Array.isArray(tasks)) throw Error('PTK returned invalid selected-check metadata.');
        const groups = record.coverage.filter(item => item.requestId === seed.id).map(coverage => {
          const matching = tasks.filter(task => (task.family || 'xss') === coverage.family && (!coverage.parameter || task.parameter && parameterKey(task.parameter) === parameterKey(coverage.parameter)));
          if (!matching.length) { coverage.state = 'unsupported'; coverage.reason = 'No compatible bounded checks exist for this selected input and family.'; }
          return { coverage, tasks: matching };
        });
        const controls = new Map();
        for (const task of tasks) if (!task.strategy && (task.family || 'xss') !== 'jsonp_callback_injection') {
          const key = parameterKey(task.parameter);
          if (!controls.has(key)) { const control = ptk.control(originalSchema, task.parameter); if (selectedDifference(seed, control) !== 1) throw Error('The benign control did not isolate the selected input occurrence.'); controls.set(key, task.parameter); }
        }
        return { seed, originalSchema, groups, controls };
      });
      record.progress.total = prepared.reduce((sum, item) => sum + item.groups.reduce((n, group) => n + group.tasks.length, 0), 0); await save();
      for (const { seed, originalSchema, groups, controls } of prepared) {
        const taskSchema = task => task.schema ? clone(task.schema) : ptk.taskSchema(originalSchema, task);
        const runnable = groups.filter(group => group.tasks.length); if (!runnable.length) continue;
        check();
        const firstCoverage = (runnable.find(group => group.coverage.family === 'response_checks') || runnable[0]).coverage;
        const allowRedirect = plan.families.includes('open_redirect');
        const original = await send(clone(originalSchema), seed, 'baseline', allowRedirect, firstCoverage);
        const entry = { requestId: seed.id, baseline: evidence(original), controls: [], attacks: [] }; record.evidence.push(entry);
        const goodBaseline = Number(original.response.statusCode) >= 200 && Number(original.response.statusCode) < 300;
        const needsSecond = goodBaseline && runnable.some(group => ['sql_injection', 'sql_boolean'].includes(group.coverage.family));
        const secondCoverage = (runnable.find(group => ['sql_injection', 'sql_boolean'].includes(group.coverage.family)) || runnable[0]).coverage;
        const repeatedBaseline = needsSecond ? await send(clone(originalSchema), seed, 'baseline', allowRedirect, secondCoverage) : original;
        if (repeatedBaseline !== original) entry.repeatedBaseline = evidence(repeatedBaseline);
        const controlResponses = new Map();
        // Passive checks inspect only this already-requested response, including
        // error responses. They never schedule probes or follow discovered URLs.
        for (const group of runnable.filter(group => group.coverage.family === 'response_checks')) {
          const coverage = group.coverage; let uncertain = false;
          for (const task of group.tasks) {
            try {
              const analyzed = clone(original); analyzed.metadata = clone(task.metadata);
              const verdict = ptk.validate(analyzed, original, task);
              if (verdict.success === true) {
                coverage.matched = true;
                record.observations.push({ id: record.batchId + ':' + seed.id + ':' + task.attackId, requestId: seed.id, family: 'response_checks', moduleId: task.moduleId,
                  classification: 'response_observation', title: task.attackName, attackId: task.attackId, status: Number(original.response.statusCode), endpoint: entry.baseline.endpoint,
                  proof: 'The bundled PTK response rule matched the selected baseline.', verifiedImpact: false, note: 'Passive response observation only; exploitability and application impact are not established.' });
              }
            } catch { uncertain = true; }
            record.progress.tested++;
          }
          coverage.state = uncertain ? 'inconclusive' : 'tested'; coverage.reason = uncertain ? 'One or more bundled passive rules could not assess this response.' : undefined; await save();
        }
        for (const { coverage, tasks } of runnable.filter(group => group.coverage.family !== 'response_checks')) {
          if (!goodBaseline && coverage.family !== 'open_redirect') { coverage.state = 'inconclusive'; coverage.reason = 'The baseline status is unsuitable for active comparisons.'; continue; }
          let uncertain = false, reason;
          for (const task of tasks) {
            check();
            const family = task.family || 'xss', runProbe = schema => send(schema, seed, 'mutation', family === 'open_redirect', coverage);
            if (task.strategy === 'boolean' || task.strategy === 'ssti') {
              const result = task.strategy === 'boolean'
                ? await booleanCheck(task, originalSchema, original, repeatedBaseline, ptk.mutate, runProbe)
                : await templateCheck(task, originalSchema, original, ptk.mutate, runProbe);
              entry.attacks.push({ family, attackId: task.attackId, parameter: task.parameter, matched: result.matched === true, probes: result.evidenceRows || [] });
              if (result.inconclusive) { uncertain = true; reason = result.reason; }
              if (result.matched) {
                coverage.matched = true;
                record.findings.push({ id: record.batchId + ':' + seed.id + ':' + task.attackId + ':' + parameterKey(task.parameter), requestId: seed.id, family, parameter: task.parameter, attackId: task.attackId,
                  title: family === 'sql_boolean' ? 'Reproduced boolean response difference' : 'Reproduced template arithmetic evaluation',
                  classification: family === 'sql_boolean' ? 'reproduced_boolean_difference' : 'reproduced_template_evaluation', proof: result.proof,
                  baseline: entry.baseline, comparisons: result.evidenceRows, verifiedImpact: false,
                  note: family === 'sql_boolean' ? 'Bounded true/false predicates produced stable differences. No data extraction or timing tests were performed.' : 'Marker-delimited arithmetic evaluated in HTTP responses. This does not establish code execution or RCE.' });
              }
              record.progress.tested++; await save(); continue;
            }
            if (family === 'jsonp_callback_injection') {
              const callback = task.payload, otherCallback = 'certxJsonp_' + crypto.randomUUID().replaceAll('-', '');
              const schema = taskSchema(task), first = await runProbe(schema);
              const otherSchema = ptk.mutate(originalSchema, task.parameter, otherCallback); otherSchema.metadata = clone(schema.metadata);
              otherSchema.metadata.jsonpCallbackProofRegex = otherSchema.metadata.jsonpCallbackProofRegex.replaceAll(callback, otherCallback);
              const other = await runProbe(otherSchema);
              const matched = callbackInvocation(first, callback) && callbackInvocation(other, otherCallback) && ptk.validate(first, original, task).success === true && ptk.validate(other, original, task).success === true;
              entry.attacks.push({ family, parameter: task.parameter, attackId: task.attackId, matched, ...evidence(first) });
              if (matched) {
                const repeated = await runProbe(taskSchema(task));
                if (callbackInvocation(repeated, callback) && ptk.validate(repeated, original, task).success === true) {
                  coverage.matched = true;
                  record.observations.push({ id: record.batchId + ':' + seed.id + ':' + task.attackId + ':' + parameterKey(task.parameter), requestId: seed.id, family, parameter: task.parameter, attackId: task.attackId,
                    classification: 'callback_control', title: 'JSONP callback control', proof: 'Two unique callback identifiers selected valid JSON callback invocations; the first reproduced.', verifiedImpact: false,
                    note: 'Callback control is an observation. Sensitive cross-origin data exposure and exploitability are not established.' });
                } else { uncertain = true; reason = 'Callback control did not reproduce.'; }
              }
              record.progress.tested++; await save(); continue;
            }
            const key = parameterKey(task.parameter);
            if (!controlResponses.has(key)) {
              const schema = ptk.control(originalSchema, controls.get(key));
              const response = await send(schema, seed, 'control', allowRedirect, coverage); controlResponses.set(key, response); entry.controls.push({ parameter: task.parameter, ...evidence(response) });
            }
            const schema = taskSchema(task); selectedDifference(seed, schema);
            const validate = (attack, baseline) => family === 'open_redirect' ? redirectVerdict(attack, baseline, task) : ptk.validate(attack, baseline, task);
            const attack = await runProbe(schema), verdict = validate(attack, original), control = controlResponses.get(key);
            const matched = verdict.success === true && validate(attack, control).success === true && validate(attack, repeatedBaseline).success === true;
            const item = { family, parameter: task.parameter, attackId: task.attackId, attackName: task.attackName, ...evidence(attack), matched }; entry.attacks.push(item); record.progress.tested++;
            if (matched) {
              const repeated = await send(taskSchema(task), seed, 'confirmation', family === 'open_redirect', coverage);
              const reproduced = validate(repeated, original).success === true && validate(repeated, control).success === true && validate(repeated, repeatedBaseline).success === true;
              if (!reproduced) { uncertain = true; reason = 'A matching probe did not reproduce.'; }
              if (reproduced || family === 'xss') {
                coverage.matched ||= reproduced;
                record.findings.push({ id: record.batchId + ':' + seed.id + ':' + task.attackId + ':' + parameterKey(task.parameter), requestId: seed.id, family,
                  title: ({ xss: 'Reflected XSS candidate', sql_injection: 'SQL error injection candidate', open_redirect: 'HTTP redirect' })[family] + ': ' + task.parameter.name,
                  classification: reproduced ? ({ xss: 'reproduced_reflection', sql_injection: 'reproduced_sql_error', open_redirect: 'reproduced_redirect' })[family] : 'candidate',
                  parameter: task.parameter, attackId: task.attackId, payload: String(task.payload || '').slice(0, 2000), proof: String(verdict.proof || '').slice(0, 4096), baseline: entry.baseline, attack: item, confirmation: evidence(repeated), verifiedImpact: false,
                  note: ({ xss: 'PTK detected payload reflection. Browser execution and application impact are not established.', sql_injection: 'Database-error signatures reproduced and were absent from both baselines and the benign control. Query control and data access are not established.', open_redirect: 'The HTTP Location exactly matched the unique reserved destination on repeated probes. No redirect was followed.' })[family] });
              }
            }
            await save();
          }
          coverage.state = uncertain && !coverage.matched ? 'inconclusive' : 'tested'; coverage.reason = coverage.state === 'inconclusive' ? reason : undefined; await save();
        }
      }
      record.state = 'completed';
    } catch (error) {
      record.state = error.state || (record.cancelled ? 'stopped' : 'failed'); record.errors.push(error.message);
      if (currentCoverage && currentCoverage.state !== 'tested') { currentCoverage.state = 'inconclusive'; currentCoverage.reason = error.message; }
      for (const coverage of record.coverage) if (coverage.state === 'skipped') coverage.reason = 'Not reached: ' + error.message;
    }
    finally { record.inFlight = 0; record.finishedAt = now(); active = null; release(); await save(); }
  }
  return {
    hasActive: () => active !== null,
    async run(input) {
      const operation = reservation.then(async () => {
        const plan = validatePlan(input), old = records.get(plan.batchId);
        if (old) { if (old.owner !== plan.owner) throw Error('Batch identity belongs to another chat.'); return { accepted: false, ...publicStatus(old) }; }
        if (active || await isBusy()) throw Error('A PTK scan or targeted batch is already active. Stop it first.');
        if (records.size >= 32) throw Error('This browser session has retained 32 batches. Save reports, then restart the browser before starting more batches.');
        if (!acquire()) throw Error('A PTK scan or account verification is already active. Stop it first.');
        const record = { batchId: plan.batchId, owner: plan.owner, state: 'running', startedAt: now(), deadline: now() + plan.budget.durationSeconds * 1000,
          requestsSent: 0, inFlight: 0, maxRequests: plan.budget.maxRequests, progress: { tested: 0, total: 0 },
          warnings: ['Selected HTTP checks only; redirect following, browser execution proof, crawling, time-delay SQL, data extraction and out-of-band checks are disabled. Shared baselines/controls are counted once in coverage probe totals.'], errors: [], findings: [], observations: [], evidence: [],
          coverage: plan.requests.flatMap(seed => plan.families.flatMap(family => (family === 'response_checks' ? [undefined] : seed.parameters).map(parameter => ({ requestId: seed.id, family, ...(parameter ? { parameter: clone(parameter) } : {}), state: 'skipped', reason: 'Not reached yet.', probesSent: 0, matched: false })))) };
        records.set(record.batchId, record); active = record.batchId;
        try { await save(); } catch { record.state = 'failed'; active = null; release(); throw Error('Could not reserve the targeted batch safely.'); }
        record.completion = execute(plan, record); record.completion.catch(() => {});
        return { accepted: true, ...publicStatus(record) };
      }); reservation = operation.catch(() => {}); return operation;
    },
    status: ({ batchId, owner }) => publicStatus(get(batchId, owner)),
    async stop({ batchId, owner }) { const record = get(batchId, owner); if (!terminal.has(record.state)) { record.cancelled = true; record.state = 'stopping'; await save(); } return publicStatus(record); },
    result: ({ batchId, owner }) => { const record = get(batchId, owner); if (record.resultsUnavailable) throw Error('Report contents are no longer retained after the companion restarted. Open any previously saved report in Outputs.'); return { ...publicStatus(record), findings: clone(record.findings || []), observations: clone(record.observations || []), coverage: clone(record.coverage || []), requests: clone(record.evidence || []),
      report: { schema: 'cert-x-dast/v1', ...publicStatus(record), findings: clone(record.findings || []), observations: clone(record.observations || []), coverage: clone(record.coverage || []), requests: clone(record.evidence || []), note: 'Request authentication headers are omitted; response evidence may contain application data.' } }; },
    wait: ({ batchId, owner }) => get(batchId, owner).completion,
  };
}

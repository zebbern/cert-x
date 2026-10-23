// cert-x owns these preferences. PTK's native option names remain available.
export const SETTINGS_KEY = 'ki_security_settings';
export const ACQUISITION_DEFAULTS = Object.freeze({ maxResourceBytes: 8 * 1024 * 1024, maxTotalBytes: 32 * 1024 * 1024, maxScripts: 128, drainTimeoutMs: 5000 });
// These finite bounds protect the shared extension process. Per-run
// preferences and explicit user ceilings are resolved separately below.
export const ACQUISITION_MAXIMA = Object.freeze({ maxResourceBytes: 8 * 1024 * 1024, maxTotalBytes: 32 * 1024 * 1024, maxScripts: 4096, drainTimeoutMs: 60000 });
export const PRESETS = Object.freeze({
  thorough: Object.freeze({ preset: 'thorough', scanStrategy: 'COMPREHENSIVE', dastScanStrategy: 'COMPREHENSIVE', scanControlProfile: 'wide', allowCaptureWithoutInteraction: true, enableHtmlLinkDiscovery: true, htmlLinkDiscoveryBudget: 'safe', schedulerBreadthFirst: true, maxRequestsPerSecond: 5, concurrency: 3, planningConcurrency: 2, runCve: true, follow_redirect: true, maxRequests: null, durationSeconds: null }),
  'ptk-defaults': Object.freeze({ preset: 'ptk-defaults', scanStrategy: 'SMART', dastScanStrategy: 'SMART', scanControlProfile: 'safe', allowCaptureWithoutInteraction: false, schedulerBreadthFirst: false, maxRequestsPerSecond: 5, concurrency: 3, planningConcurrency: 2, runCve: true, follow_redirect: true, maxRequests: null, durationSeconds: null }),
});
const NUMBERS = new Set(['maxRequestsPerSecond', 'concurrency', 'planningConcurrency', 'maxRequests', 'durationSeconds', 'requestTimeoutMs', 'originalRequestTimeoutMs']);
const INTEGERS = new Set(['concurrency', 'planningConcurrency', 'maxRequests']);
const BOOLEAN = new Set(['runCve', 'follow_redirect', 'followRedirect', 'override_headers', 'update_content_length', 'use_content_type', 'allowCaptureWithoutInteraction', 'enableHtmlLinkDiscovery', 'enableSyntheticRedirectRequests', 'schedulerBreadthFirst']);
const STRUCTURED = new Set(['modules', 'moduleIds', 'excludeModules', 'scanControls', 'globalExcludes', 'confirm', 'rulepack', 'cveRulepack', 'engineOptions', 'blacklist', 'htmlDiscovery', 'inputSelection', 'backends', 'oast']);
const MODULE_SELECTIONS = new Set(['modules', 'moduleIds', 'excludeModules']);
const ENUMS = { scanStrategy: ['FAST', 'SMART', 'COMPREHENSIVE'], dastScanStrategy: ['FAST', 'SMART', 'COMPREHENSIVE'], scanControlProfile: ['strict', 'safe', 'wide'], safetyProfile: ['strict', 'safe', 'wide'], dastScanPolicy: ['ACTIVE', 'PASSIVE', 'RECON', 'RECONNAISSANCE'], htmlLinkDiscoveryBudget: ['strict', 'safe', 'wide'] };
export function copy(value) { return value === undefined ? undefined : JSON.parse(JSON.stringify(value)); }
function plain(value, name) { if (!value || typeof value !== 'object' || Array.isArray(value)) throw Error(name + ' must be an object.'); }
function rejectKeys(value) { if (!value || typeof value !== 'object') return; for (const [key, child] of Object.entries(value)) { if (['__proto__', 'constructor', 'prototype'].includes(key)) throw Error('Unsafe configuration key.'); rejectKeys(child); } }
function validateModuleSelections(value, prefix = '') {
  for (const key of MODULE_SELECTIONS) if (Object.hasOwn(value, key)) {
    const selection = value[key];
    if (!Array.isArray(selection) || selection.some(id => typeof id !== 'string' || !id.trim())) throw Object.assign(Error(prefix + key + ' must be an array of module ID strings, for example ["xss"]. Do not wrap the array in an object.'), { code:'invalid_scan_options', retryable:false, recovery:'Use options.moduleIds:["module_id"] or engineOptions.ENGINE.moduleIds:["module_id"] with IDs from security_capabilities. Correct the value before retrying; no scan was started.' });
  }
}
export function validateAcquisition(value = {}, { ceilings = false } = {}) {
  plain(value, 'Acquisition settings'); rejectKeys(value); const result = {};
  for (const [key, item] of Object.entries(value)) {
    if (!Object.hasOwn(ACQUISITION_MAXIMA, key)) throw Error('Unknown acquisition option: ' + key);
    if (ceilings && item === null) { result[key] = null; continue; }
    if (!Number.isSafeInteger(item) || item < 1 || item > ACQUISITION_MAXIMA[key]) throw Error('acquisition.' + key + ' must be an integer from 1 to ' + ACQUISITION_MAXIMA[key] + '.');
    result[key] = item;
  }
  return result;
}
export function validateOptions(value = {}) {
  plain(value, 'Security options'); rejectKeys(value); validateModuleSelections(value); const result = {};
  for (const [key, item] of Object.entries(value)) {
    if (key === 'acquisition') { result[key] = validateAcquisition(item); continue; }
    if (key === 'engineOptions') {
      plain(item, 'engineOptions');
      for (const [engine, settings] of Object.entries(item)) { plain(settings, 'engineOptions.' + engine); validateModuleSelections(settings, 'engineOptions.' + engine + '.'); }
    }
    if (key === 'preset') { if (!Object.hasOwn(PRESETS, item)) throw Error('Unknown security preset.'); }
    else if (NUMBERS.has(key)) { if (item === null && ['maxRequests', 'durationSeconds'].includes(key)) { result[key] = null; continue; } if (typeof item !== 'number' || !Number.isFinite(item) || item <= 0 || (INTEGERS.has(key) && !Number.isSafeInteger(item))) throw Error(key + ' must be a positive ' + (INTEGERS.has(key) ? 'integer.' : 'number.')); }
    else if (BOOLEAN.has(key)) { if (typeof item !== 'boolean') throw Error(key + ' must be a boolean.'); }
    else if (Object.hasOwn(ENUMS, key)) { if (!ENUMS[key].includes(item)) throw Error('Invalid ' + key + '.'); }
    else if (STRUCTURED.has(key)) { if (!item || typeof item !== 'object') throw Error(key + ' must be structured configuration.'); }
    else throw Error('Unknown security option: ' + key);
    result[key] = copy(item);
  }
  if (result.scanStrategy) result.dastScanStrategy = result.scanStrategy;
  else if (result.dastScanStrategy) result.scanStrategy = result.dastScanStrategy;
  return result;
}
export function validateLimits(value = {}) {
  plain(value, 'Security limits'); const result = {};
  for (const [key, item] of Object.entries(value)) {
    if (key === 'acquisition') { result[key] = validateAcquisition(item, { ceilings: true }); continue; }
    if (!['maxRequests', 'durationSeconds', 'maxRequestsPerSecond', 'concurrency', 'planningConcurrency'].includes(key)) throw Error('Unknown security limit: ' + key);
    if (item === null) result[key] = null;
    else result[key] = validateOptions({ [key]: item })[key];
  }
  return result;
}
export function cleanSettings(raw = {}) {
  if (raw.version != null && raw.version !== 1) throw Error('Security settings require a newer cert-x version.');
  const settings = { version: 1, defaults: validateOptions(raw.defaults || {}), limits: validateLimits(raw.limits || {}), workspaces: {} };
  for (const [id, value] of Object.entries(raw.workspaces || {})) { if (!/^[a-zA-Z0-9_-]{1,100}$/.test(id) || ['__proto__', 'constructor', 'prototype'].includes(id)) throw Error('Invalid workspace identifier.'); settings.workspaces[id] = { defaults: validateOptions(value.defaults || {}), limits: validateLimits(value.limits || {}) }; }
  return settings;
}
export function resolveConfig(settings = {}, workspaceId, options = {}) {
  settings = cleanSettings(settings); const workspace = settings.workspaces[workspaceId] || {}, explicit = validateOptions(options);
  const preset = explicit.preset || workspace.defaults?.preset || settings.defaults.preset || 'thorough';
  const config = { ...PRESETS[preset], ...settings.defaults, ...workspace.defaults, ...explicit, preset };
  config.acquisition = { ...ACQUISITION_DEFAULTS, ...settings.defaults.acquisition, ...workspace.defaults?.acquisition, ...explicit.acquisition };
  if (explicit.preset && !Object.hasOwn(explicit, 'scanStrategy')) { config.scanStrategy = PRESETS[preset].scanStrategy; config.dastScanStrategy = PRESETS[preset].dastScanStrategy; config.scanControlProfile = explicit.scanControlProfile || PRESETS[preset].scanControlProfile; }
  const limits = {};
  for (const key of new Set([...Object.keys(settings.limits), ...Object.keys(workspace.limits || {})])) {
    if (key === 'acquisition') continue;
    const candidates = [settings.limits[key], workspace.limits?.[key]].filter(value => value != null); if (!candidates.length) continue;
    limits[key] = Math.min(...candidates);
    if (Object.hasOwn(explicit, key) && (explicit[key] === null || explicit[key] > limits[key])) throw Error(key + ' exceeds the explicit user limit of ' + limits[key] + '.');
    config[key] = config[key] == null ? limits[key] : Math.min(config[key], limits[key]);
  }
  for (const key of Object.keys(ACQUISITION_DEFAULTS)) {
    const candidates = [settings.limits.acquisition?.[key], workspace.limits?.acquisition?.[key]].filter(value => value != null);
    if (!candidates.length) continue;
    const ceiling = Math.min(...candidates);
    if (explicit.acquisition?.[key] > ceiling) throw Error('acquisition.' + key + ' exceeds the explicit user limit of ' + ceiling + '.');
    (limits.acquisition ||= {})[key] = ceiling;
    config.acquisition[key] = Math.min(config.acquisition[key], ceiling);
  }
  return { ...config, limits };
}
export function scopeAllows(url, scope = {}) {
  let parsed; try { parsed = new URL(url); } catch { return false; }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) return false;
  const origins = scope.origins || [];
  if (!origins.some(origin => {
    if (scope.matchMode !== 'host') return origin === parsed.origin;
    let base; try { base = new URL(origin); } catch { return false; }
    return parsed.hostname === base.hostname || scope.includeSubdomains === true && !base.hostname.startsWith('[') && !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(base.hostname) && parsed.hostname.endsWith('.' + base.hostname);
  })) return false;
  if (scope.also && !scopeAllows(url, scope.also)) return false;
  const exclusions = scope.excludePaths || []; if (!exclusions.length) return true;
  let pathname = parsed.pathname;
  // Exclusions must survive common server-side decoding/normalization. Query
  // values are payload data and deliberately do not participate in path scope.
  for (let depth = 0; depth < 5; depth++) {
    const canonical = new URL(pathname.replaceAll('\\', '/').split('/').map(segment => segment.split(';')[0]).join('/').replace(/\/{2,}/g, '/'), parsed.origin).pathname;
    if (exclusions.some(path => path === '/' || canonical === path || canonical.startsWith(path.endsWith('/') ? path : path + '/'))) return false;
    let decoded; try { decoded = decodeURIComponent(pathname); } catch { return false; }
    if (decoded === pathname) return true;
    pathname = decoded;
  }
  return false;
}
export function validateScope(scope = {}) {
  if (!Array.isArray(scope.origins) || !scope.origins.length || !Array.isArray(scope.excludePaths || [])) throw Error('Select at least one target origin.');
  if (scope.matchMode != null && !['origin', 'host'].includes(scope.matchMode)) throw Error('Choose exact origins or same host for target scope.');
  if (scope.includeSubdomains != null && typeof scope.includeSubdomains !== 'boolean') throw Error('Subdomain selection must be on or off.');
  if (scope.includeSubdomains && scope.matchMode !== 'host') throw Error('Subdomains require same-host matching.');
  const origins = [...new Set(scope.origins.map(value => { const url = new URL(value); if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.pathname !== '/' || url.search || url.hash || url.hostname.includes('*')) throw Error('Targets must be exact HTTP(S) origins.'); return url.origin; }))];
  const excludePaths = [...new Set((scope.excludePaths || []).map(value => { if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//') || /[?#\\\x00-\x1f]/.test(value)) throw Error('Excluded paths must be absolute URL paths.'); return value; }))];
  return { origins, excludePaths, ...(scope.matchMode === 'host' ? { matchMode: 'host', ...(scope.includeSubdomains ? { includeSubdomains: true } : {}) } : {}) };
}
export function scopeWithin(requested, allowed) {
  if (!allowed?.origins?.length) return false;
  if (requested.matchMode === 'host' && allowed.matchMode !== 'host') return false;
  if (requested.includeSubdomains && !allowed.includeSubdomains) return false;
  return requested.origins.every(origin => scopeAllows(origin, { ...allowed, excludePaths: [] }));
}

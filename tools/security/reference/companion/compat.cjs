// Small, source-anchored compatibility changes in the prepared companion only.
// The upstream source and its license remain untouched. Fail on unknown edits.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto');
const revision = 1;
const hash = text => crypto.createHash('sha256').update(text).digest('hex');
function once(text, before, after) {
  const index = text.indexOf(before);
  if (index < 0 || text.indexOf(before, index + before.length) >= 0) throw Error('PTK compatibility anchor changed: ' + before.slice(0, 90));
  return text.slice(0, index) + after + text.slice(index + before.length);
}
function patch(relative, source) {
  let text = source.replaceAll('\r\n', '\n');
  if (relative.endsWith('/ptkAgentAutomation.js')) {
    return once(text, 'agentApiVersion: PTK_AGENT_API_VERSION,', 'agentApiVersion: PTK_AGENT_API_VERSION,\n                certXIntegrationRevision: 1,');
  }
  if (relative.endsWith('/background/automation.js')) {
    text = once(text, "const started = await iast.runBackgroundScan(tabId, host, options?.policyCode || 'SMART', iastOpts)",
      "const certXExclusive = String(this.automationModule?.sessions?.get(sessionId)?.project || '').startsWith('cert-x:')\n            if (certXExclusive) iastOpts.certXSingleTab = true\n            const started = await iast.runBackgroundScan(tabId, host, options?.policyCode || 'SMART', iastOpts)");
    text = once(text, 'if (started === false) {\n                const activeTabId = Number(iast?.scanResult?.tabId)',
      "if (started === false) {\n                if (certXExclusive) return { ok: false, status: ENGINE_STATUS_ERROR, error: 'iast_exclusive_session_busy' }\n                const activeTabId = Number(iast?.scanResult?.tabId)");
    text = once(text, "if (engineUpper === 'IAST') {\n                const iast = this.app?.iast || null",
      "if (engineUpper === 'IAST') {\n                result.relatedTab = engineState.relatedTab === true\n                result.ownerTabId = this.app?.iast?.scanResult?.tabId ?? null\n                result.relatedTabIds = Array.from(this.app?.iast?.relatedScanTabs?.keys?.() || [])\n                result.completionStatus = engineState.completionStatus || null\n                result.drained = engineState.drained === true\n                result.stopTimedOut = engineState.stopTimedOut === true\n                const iast = this.app?.iast || null");
    text = once(text, 'let bestFindings = []\n            try {',
      `// cert-x evidence remains bound to this session's native scan, even
            // after a different manual or automation scan replaces the engine.
            if (engineName === 'IAST' && String(session.project || '').startsWith('cert-x:')) {
                const ownedId = session.scanIds?.IAST
                const live = this.app?.iast?.scanResult
                const owned = ownedId && (live?.scanId === ownedId ? live : resultsRegistry.get('IAST', ownedId))
                if (!owned || owned.scanId !== ownedId) throw new Error('iast_session_result_unavailable')
                allFindings.push(...this.engines._extractFindings(owned, normalizedLimit + 1, 'IAST'))
                continue
            }
            let bestFindings = []
            try {`);
    return text;
  }
  if (relative.endsWith('/background/iast.js')) {
    text = once(text, 'async runBackgroundScan(tabId, host, scanStrategy, opts = {}) {',
      `async runBackgroundScan(tabId, host, scanStrategy, opts = {}) {
        if (this._certXStarting || this._certXStopping || this.isScanRunning) return false
        this._certXStarting = true
        try { return await this._certXRunBackgroundScan(tabId, host, scanStrategy, opts) }
        finally { this._certXStarting = false }
    }

    async _certXRunBackgroundScan(tabId, host, scanStrategy, opts = {}) {`);
    text = once(text, "iastScanStrategy: scanStrategy || 'SMART'", "iastScanStrategy: scanStrategy || 'SMART',\n            certXSingleTab: effectiveOpts.certXSingleTab === true");
    text = once(text, 'registerRelatedScanTab(tabId, meta = {}) {', 'registerRelatedScanTab(tabId, meta = {}) {\n        if (this.scanResult?.settings?.certXSingleTab === true) return false');
    text = once(text, 'const scopeAllowed = hasScopedSession\n            ? this.scopedTabCoordinator.isUrlInScope',
      "const certXTarget = normalizeIastRegistrationTarget(this.scanResult?.targetUrl)\n        const certXCurrent = normalizeIastRegistrationTarget(navigationUrl)\n        const scopeAllowed = this.scanResult?.settings?.certXSingleTab === true\n            ? normalizedTabId === primaryTabId && !!certXTarget && certXCurrent?.origin === certXTarget.origin\n            : hasScopedSession\n            ? this.scopedTabCoordinator.isUrlInScope");
    text = once(text, "await this.scopedTabCoordinator?.registerSession?.('IAST', {", "if (!this.scanResult.settings.certXSingleTab) await this.scopedTabCoordinator?.registerSession?.('IAST', {");
    text = once(text, "await this.registerScript(this.scanResult.settings.iastScanStrategy || 'SMART', {", "if (!this.scanResult.settings.certXSingleTab) await this.registerScript(this.scanResult.settings.iastScanStrategy || 'SMART', {");
    text = once(text, 'async stopBackgroundScan(options = {}) {',
      `async stopBackgroundScan(options = {}) {
        if (this._certXStopping) return this._certXStopping
        this._certXStopping = this._certXStopBackgroundScan(options)
        try { return await this._certXStopping }
        finally { this._certXStopping = null }
    }

    async _certXStopBackgroundScan(options = {}) {`);
    return text;
  }
  throw Error('Unknown companion patch target');
}
const targets = ['src/ptk/ptkAgentAutomation.js', 'src/ptk/background/automation.js', 'src/ptk/background/iast.js'];
function apply(sourceRoot, outputRoot, previous = {}) {
  const changes = targets.map(relative => {
    const original = fs.readFileSync(path.join(sourceRoot, relative), 'utf8'), next = patch(relative, original);
    const target = path.join(outputRoot, relative), current = fs.readFileSync(target, 'utf8'), currentHash = hash(current);
    if (current !== original && current !== next && currentHash !== previous?.files?.[relative]?.sha256) throw Error('Prepared PTK file has unrecognized edits; preserve them and choose a new OutputDirectory: ' + relative);
    return { relative, target, current, next, originalSha256: hash(original), sha256: hash(next) };
  });
  // All source anchors and existing files are checked before writing any patch.
  for (const item of changes) if (item.current !== item.next) fs.writeFileSync(item.target, item.next);
  return { revision, purpose: 'Exclusive cert-x IAST ownership, single-tab instrumentation and readiness/drain diagnostics',
    files: Object.fromEntries(changes.map(item => [item.relative, { originalSha256: item.originalSha256, sha256: item.sha256 }])) };
}
module.exports = { revision, patch, apply, targets };

import { securityBrowser as browser, securityChrome as chrome } from "../../engine/platform.mjs";
/* Author: Denis Podgurskii */
import { ptk_utils, ptk_logger, ptk_queue, ptk_storage, ptk_ruleManager } from "../background/utils.js"
import {
    createScanResultEnvelope
} from "./common/scanResults.js"
import CryptoES from '../packages/crypto-es/index.js';
import {
    normalizeComponentEntry,
    buildFindingsFromComponents,
    buildFindingsFromLegacyScan,
    normalizeExistingScaFindings,
    isFlatScaFindingList,
    mergeScaFindingLists
} from "./sca/findingBuilder.js"
import buildExportScanResult from "./export/buildExportScanResult.js"
import { applyScanAnalysis } from "./analysis/scanAnalysisEngine.js"
import { compressScanPayload } from "./export/compressScanPayload.js"
import { ExportChunkStore } from "./export/exportChunkStore.js"
import { parseDownloadedScanPayload } from "./export/parseDownloadedScanPayload.js"
import { parseUploadedScanFile } from "./export/parseUploadedScanFile.js"
import retireModule from "../packages/retire/retire.js"
import { isScaBodyCandidate, scaCaptureKey, scaRequestKey, decodeScaBody, decodeScaExecutedSource } from './sca/capturedBody.js'
import {
    buildStoredCredentialPortalUrl,
    initializePortalRuntimeConfig
} from "../common/portalConfig.js"

const worker = self

export class ptk_sca {

    constructor(settings) {
        this.settings = settings
        this.storageKey = "ptk_sca"
        this.repoReady = null
        this.retire = null
        this.activeTabId = null
        this._persistTimer = null
        this._persistDebounceMs = 1000
        this.exportChunkStore = new ExportChunkStore({ prefix: "sca" })
        this.scopedTabCoordinator = null
        this.resetScanResult()

        this.addMessageListeners()
    }


    setBrowserCaptureManager(manager) {
        this.browserCaptureManager = manager
        this.captureLeases ||= new Map()

        return this
    }

    isBrowserCaptureOwnerActive({ ownerId, tabId }) {
        return this.captureLeases?.get(tabId)?.ownerId === ownerId
    }

    async _acquireBrowserCapture(tabId, settings = {}) {
        if (!this.browserCaptureManager) throw new Error('capture_manager_unavailable')
        this.captureLeases ||= new Map()
        if (this.captureLeases.has(tabId)) return this.captureLeases.get(tabId).promise
        const scanId = this.scanResult?.scanId
        const ownerId = 'SCA:' + scanId
        let targetUrl = settings.targetUrl || settings.zapTiming?.targetUrl
        if (!targetUrl) targetUrl = (await browser.tabs.get(tabId))?.url
        const entry = { ownerId, lease: null, scan: this.scanResult, requests: new Map(), sourceTasks: new Set(),
            analyzedBodies: new Set(), analyzedScripts: new Set(), sourceUrls: new Set(),
            acquisition: settings.acquisition || {}, acquiredBytes: 0, controller: new AbortController() }
        this.captureLeases.set(tabId, entry)
        entry.promise = this.browserCaptureManager.acquire({
            ownerId, tabId, acquisition: entry.acquisition, signal: entry.controller.signal, capabilities: ['network', 'authBodies', 'sources', 'executedSources'],
            selectResource: (record, capability) => capability === 'sources' ? record.executedSource === true
                : capability === 'authBodies' && isScaBodyCandidate(record),
            scope: { targetUrl, mode: settings.zapManaged === true ? 'path' : 'origin', ...this.getCaptureScope?.(tabId) }
        }).then(async lease => {
            if (this.captureLeases.get(tabId) !== entry || entry.stopping) {
                await lease.release('replaced')
                throw new Error('capture_owner_unavailable')
            }
            entry.lease = lease
            entry.unsubscribe = lease.subscribe(event => this._onCapturedResource(entry, lease, event))
            entry.unsubscribeSources = lease.subscribeSourceBatches?.(batch => {
                const task = this._onSourceBatch(entry, lease, batch).finally(() => entry.sourceTasks.delete(task))
                entry.sourceTasks.add(task)
            })
            const current = () => this.captureLeases.get(tabId) === entry && this.scanResult === entry.scan && !entry.stopping
            try {
                const previousGaps = this.scanResult.scaSourceCoverage?.gaps || 0
                entry.executedSourceResult = await lease.collectExecutedSources?.()
                if (!current()) throw new Error('capture_owner_unavailable')
                this.scanResult.scaAcquisitionLimits = { requested: entry.acquisition, effective: entry.executedSourceResult?.effectiveLimits }
                await Promise.allSettled([...entry.sourceTasks])
                if (!current()) throw new Error('capture_owner_unavailable')
                if (entry.executedSourceResult?.gaps > (this.scanResult.scaSourceCoverage?.gaps || 0) - previousGaps)
                    this._bodyGap(null, 'script_source_acquisition_incomplete', { tabId }, 'source')
                if (entry.executedSourceResult?.childDocumentsUninspected) this._bodyGap(null,
                    'preexisting_child_sources_uninspected', { tabId }, 'source')
            } catch (error) {
                if (!current()) throw new Error('capture_owner_unavailable')
                this._bodyGap(null, error?.message || 'preexisting_script_source_unavailable', { tabId }, 'source')
            }
            return lease
        }).catch(error => {
            if (this.captureLeases.get(tabId) === entry) this.captureLeases.delete(tabId)
            throw error
        })
        return entry.promise
    }

    async _releaseBrowserCapture(tabId, reason = 'stopped') {
        const entry = this.captureLeases?.get(tabId)
        if (!entry) return
        entry.stopping = true
        const deadline = Date.now() + (entry.acquisition?.drainTimeoutMs || 5000)
        const remaining = () => Math.max(1, deadline - Date.now())
        const bounded = async promise => {
            let timer
            try { return await Promise.race([Promise.resolve(promise).then(value => ({ value }), error => ({ error })),
                new Promise(resolve => { timer = setTimeout(() => resolve({ timeout: true }), remaining()) })]) }
            finally { clearTimeout(timer) }
        }
        const persistOutcome = outcome => {
            const tabs = { ...(entry.scan.scaDrain?.tabs || {}) }
            tabs[tabId] = { ...tabs[tabId], ...outcome }
            const values = Object.values(tabs), failure = values.find(value => value.complete === false)
            entry.scan.scaDrain = { complete: values.every(value => value.complete === true),
                ...(failure?.reason ? { reason: failure.reason } : {}),
                gaps: values.reduce((sum, value) => sum + (Number.isFinite(value.gaps) ? value.gaps : 0), 0),
                cleanupPending: values.some(value => value.cleanupPending === true), tabs }
            if (this.scanResult === entry.scan) this._schedulePersistScanResult()
        }
        if (reason === 'reset' || reason === 'tab_released') this.captureLeases.delete(tabId)
        try {
            if (!entry.lease) {
                // Revoke pending acquisition immediately. Its native command may
                // finish later, but its continuation cannot subscribe or publish.
                entry.controller?.abort()
                const acquisition = await bounded(entry.promise)
                if (acquisition.timeout) {
                    persistOutcome({ complete: false, reason: 'capture_acquisition_stop_timeout', cleanupPending: true })
                    if (this.scanResult === entry.scan) this._bodyGap(null, 'capture_acquisition_stop_timeout', { tabId })
                    Promise.resolve(entry.promise).catch(() => {}).then(() => persistOutcome({ cleanupPending: false }))
                    return
                }
            }
            if (entry.lease) {
                let drained = false
                try {
                    if (reason !== 'reset' && reason !== 'tab_released') {
                        const result = entry.lease.stopAndDrain ? await entry.lease.stopAndDrain({ timeoutMs: remaining() })
                            : (entry.lease.freeze(), await entry.lease.drain())
                        drained = result.complete === true
                        persistOutcome(result)
                        if (!result.complete) this._bodyGap(null, result.reason || 'capture_drain_incomplete', { tabId })
                    }
                } finally {
                    for (const [key, request] of entry.requests) {
                        if (this.scanResult === entry.scan) this._bodyGap(request.url, 'response_body_unavailable', request)
                        entry.requests.delete(key)
                    }
                    if (drained) {
                        const analysis = await bounded(Promise.allSettled([...entry.sourceTasks || []]))
                        if (analysis.timeout) {
                            persistOutcome({ complete: false, reason: 'capture_analysis_timeout' })
                            if (this.scanResult === entry.scan) this._bodyGap(null, 'capture_analysis_timeout', { tabId })
                        }
                    }
                    entry.unsubscribeSources?.()
                    entry.unsubscribe?.()
                    // release synchronously revokes grants before awaiting native
                    // cleanup. A blocked CDP command must not hold Stop forever.
                    const release = Promise.resolve(entry.lease.release(reason))
                    const cleanup = await bounded(release)
                    if (cleanup.timeout) {
                        persistOutcome({ complete: false, reason: entry.scan.scaDrain?.tabs?.[tabId]?.reason || 'capture_cleanup_pending', cleanupPending: true, cleanupReason: 'capture_cleanup_pending' })
                        if (this.scanResult === entry.scan) this._bodyGap(null, 'capture_cleanup_pending', { tabId })
                        release.then(() => persistOutcome({ cleanupPending: false }), () => persistOutcome({ cleanupPending: false, cleanupReason: 'capture_cleanup_failed' }))
                    } else if (cleanup.error) {
                        persistOutcome({ complete: false, reason: 'capture_cleanup_failed', cleanupPending: false })
                        if (this.scanResult === entry.scan) this._bodyGap(null, 'capture_cleanup_failed', { tabId })
                        throw cleanup.error
                    }
                }
            }
        } finally {
            if (this.captureLeases.get(tabId) === entry) this.captureLeases.delete(tabId)
        }
    }

    async _releaseAllBrowserCapture(reason = 'stopped') {
        await Promise.all([...this.captureLeases?.keys() || []].map(tabId => this._releaseBrowserCapture(tabId, reason)))
    }

    setScopedTabCoordinator(coordinator) {
        this.scopedTabCoordinator = coordinator || null
        return this
    }

    isTrackedScanTab(tabId) {
        const normalized = Number(tabId)
        if (!this.isScanRunning || !Number.isInteger(normalized) || normalized < 0) return false
        if (normalized === this.activeTabId) return true
        return this.scopedTabCoordinator?.isTrackedTab?.('SCA', normalized) === true
    }

    async init() {

        if (!this.isScanRunning) {
            this.storage = await ptk_storage.getItem(this.storageKey) || {}
            if (Object.keys(this.storage).length > 0) {
                this.scanResult = this._normalizeEnvelope(this.storage)
            }
        }
    }

    async initRepo() {
        if (this.repoReady) {
            return this.repoReady
        }
        this.repoReady = fetch(browser.runtime.getURL('security/ptk/packages/retire/jsrepository.json'))
            .then(async (response) => {
                const data = await response.text()
                this.retire = retireModule
                this.repo = JSON.parse(retireModule.replaceVersion(data))
                return this.repo
            })
            .catch(error => {
                ptk_logger.log(error, "Failed to initialize SCA repository", "warning")
                this.repo = {}
                this.retire = null
                this.repoReady = null
                throw error
            })
        return this.repoReady
    }

    resetScanResult() {
        this.urls = []
        this.repo = {}
        this.retire = null
        this.repoReady = null
        this.hasher = {
            sha1: function (data) {
                return CryptoES.SHA1(data).toString(CryptoES.enc.Hex)
            }
        }
        this.isScanRunning = false
        this.activeTabId = null
        this.scanResult = this.getScanResultSchema()
        if (this._persistTimer) {
            clearTimeout(this._persistTimer)
            this._persistTimer = null
        }
    }

    getScanResultSchema() {
        const envelope = createScanResultEnvelope({
            engine: "SCA",
            scanId: ptk_utils.UUID(),
            host: null,
            tabId: null,
            startedAt: new Date().toISOString(),
            settings: {}
        })
        envelope.packages = []
        envelope.scaBodyCoverage = { captured: 0, analyzed: 0, gaps: 0 }
        envelope.scaSourceCoverage = { captured: 0, analyzed: 0, gaps: 0 }
        return envelope
    }

    _normalizeEnvelope(raw) {
        if (!raw || typeof raw !== 'object') {
            return this.getScanResultSchema()
        }
        const startedAt = raw.startedAt || raw.date || raw.started_at || raw.created_at || raw.timestamp || new Date().toISOString()
        const finishedAt = raw.finishedAt || raw.finished || raw.finished_at || raw.completed_at || null
        const scanId = raw.scanId || raw.id || ptk_utils.UUID()
        const envelope = createScanResultEnvelope({
            engine: "SCA",
            scanId,
            host: raw.host || raw.hostname || raw.domain || null,
            tabId: null,
            startedAt,
            settings: raw.settings || {}
        })
        envelope.finishedAt = finishedAt
        const rawFindings = Array.isArray(raw.findings) ? raw.findings : []
        let findings = []
        if (isFlatScaFindingList(rawFindings)) {
            findings = normalizeExistingScaFindings(rawFindings, { scanId })
        } else {
            findings = buildFindingsFromLegacyScan(raw, { scanId, createdAt: startedAt })
        }
        envelope.findings = findings
        envelope.packages = this._buildPackagesFromFindings(findings)
        envelope.stats = this._recalculateStats(findings, envelope.packages)
        envelope.scaBodyCoverage = raw.scaBodyCoverage && typeof raw.scaBodyCoverage === 'object'
            ? Object.fromEntries(['captured', 'analyzed', 'gaps'].map(key =>
                [key, Math.max(0, Number(raw.scaBodyCoverage[key]) || 0)]))
            : { captured: 0, analyzed: 0, gaps: 0 }
        envelope.scaSourceCoverage = raw.scaSourceCoverage && typeof raw.scaSourceCoverage === 'object'
            ? Object.fromEntries(['captured', 'analyzed', 'gaps'].map(key =>
                [key, Math.max(0, Number(raw.scaSourceCoverage[key]) || 0)]))
            : { captured: 0, analyzed: 0, gaps: 0 }
        if (raw.scaAcquisitionLimits && typeof raw.scaAcquisitionLimits === 'object') {
            const limits = {}, maxima = { maxResourceBytes: 8388608, maxTotalBytes: 33554432, maxScripts: 4096, drainTimeoutMs: 60000 }
            for (const kind of ['requested', 'effective']) if (raw.scaAcquisitionLimits[kind] && typeof raw.scaAcquisitionLimits[kind] === 'object') {
                limits[kind] = Object.fromEntries(Object.entries(maxima).filter(([key, max]) =>
                    Number.isSafeInteger(raw.scaAcquisitionLimits[kind][key]) && raw.scaAcquisitionLimits[kind][key] > 0
                        && raw.scaAcquisitionLimits[kind][key] <= max).map(([key]) => [key, raw.scaAcquisitionLimits[kind][key]]))
            }
            envelope.scaAcquisitionLimits = limits
        }
        if (typeof raw.scaDrain?.complete === 'boolean') envelope.scaDrain = {
            complete: raw.scaDrain.complete,
            ...(typeof raw.scaDrain.cleanupPending === 'boolean' ? { cleanupPending: raw.scaDrain.cleanupPending } : {}),
            ...(typeof raw.scaDrain.reason === 'string' && /^[a-z_]{1,100}$/.test(raw.scaDrain.reason) ? { reason: raw.scaDrain.reason } : {}),
            ...(Number.isSafeInteger(raw.scaDrain.gaps) && raw.scaDrain.gaps >= 0 ? { gaps: raw.scaDrain.gaps } : {})
        }
        if (envelope.scaDrain && raw.scaDrain.tabs && typeof raw.scaDrain.tabs === 'object') {
            const tabs = {}
            for (const [tabId, value] of Object.entries(raw.scaDrain.tabs).slice(0, 1024)) {
                if (!/^\d+$/.test(tabId) || typeof value?.complete !== 'boolean') continue
                tabs[tabId] = { complete: value.complete,
                    ...(typeof value.reason === 'string' && /^[a-z_]{1,100}$/.test(value.reason) ? { reason: value.reason } : {}),
                    ...(typeof value.cleanupPending === 'boolean' ? { cleanupPending: value.cleanupPending } : {}),
                    ...(typeof value.cleanupReason === 'string' && /^[a-z_]{1,100}$/.test(value.cleanupReason) ? { cleanupReason: value.cleanupReason } : {}),
                    ...(Number.isSafeInteger(value.gaps) && value.gaps >= 0 ? { gaps: value.gaps } : {}) }
            }
            envelope.scaDrain.tabs = tabs
            if (Object.values(tabs).some(value => !value.complete)) envelope.scaDrain.complete = false
            if (Object.values(tabs).some(value => value.cleanupPending)) envelope.scaDrain.cleanupPending = true
        }
        if (Array.isArray(raw.coverageWarnings)) envelope.coverageWarnings = raw.coverageWarnings.slice(0, 200)
        if (raw.analysis && typeof raw.analysis === "object") {
            try {
                envelope.analysis = JSON.parse(JSON.stringify(raw.analysis))
            } catch (_) {
                envelope.analysis = raw.analysis
            }
        }
        if (raw.analysisVersion) {
            envelope.analysisVersion = raw.analysisVersion
            if (envelope.analysis && !envelope.analysis.version) {
                envelope.analysis.version = raw.analysisVersion
            }
        }
        return envelope
    }

    _cloneScanResultForUi({ ensureAnalysis = false } = {}) {
        try {
            return JSON.parse(JSON.stringify(this.scanResult || {}))
        } catch (_) {
            return this.scanResult || {}
        }
    }

    _recalculateStats(findings = [], packages = []) {
        const stats = {
            findingsCount: 0,
            packagesCount: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0
        }
        if (!Array.isArray(findings)) return stats
        findings.forEach(finding => {
            if (!finding) return
            stats.findingsCount += 1
            const sev = String(finding.severity || '').toLowerCase()
            if (sev === 'critical') stats.critical += 1
            else if (sev === 'high') stats.high += 1
            else if (sev === 'medium') stats.medium += 1
            else if (sev === 'low') stats.low += 1
            else stats.info += 1
        })
        if (Array.isArray(packages)) {
            stats.packagesCount = packages.length
        }
        return stats
    }

    _buildPackagesFromFindings(findings = []) {
        if (!Array.isArray(findings)) return []
        const map = new Map()
        findings.forEach(finding => {
            const evidence = finding?.evidence?.sca || {}
            const component = evidence.component || {}
            const name = component.name || component.component || finding?.ruleName || null
            if (!name) return
            const version = component.version || null
            const file = evidence.sourceFile || finding?.location?.file || null
            const key = String(component.purl || component.basePurl || `${name}@${version || ""}`).toLowerCase()
            if (!map.has(key)) {
                map.set(key, {
                    name,
                    version,
                    file,
                    npmname: component.npmname || null,
                    purl: component.purl || null,
                    basePurl: component.basePurl || null,
                    detection: component.detection || null,
                    source: component.source || null,
                    ecosystem: component.ecosystem || null,
                    locations: Array.isArray(component.locations) ? component.locations.slice() : (file ? [file] : [])
                })
            } else {
                const existing = map.get(key)
                const mergedLocations = Array.from(new Set([
                    ...(Array.isArray(existing.locations) ? existing.locations : []),
                    ...(Array.isArray(component.locations) ? component.locations : []),
                    file
                ].filter(Boolean)))
                existing.locations = mergedLocations
                if (!existing.file && mergedLocations.length) {
                    existing.file = mergedLocations[0]
                }
            }
        })
        return Array.from(map.values())
    }

    async reset() {
        await this._releaseAllBrowserCapture('reset')
        await ptk_storage.setItem(this.storageKey, {})
        this.resetScanResult()
    }

    addMessageListeners() {
        this.onMessage = this.onMessage.bind(this)
        browser.runtime.onMessage.addListener(this.onMessage)
    }

    addListeners() {
        this.onRemoved = this.onRemoved.bind(this)
        browser.tabs.onRemoved.addListener(this.onRemoved)

        this.onUpdated = this.onUpdated.bind(this)
        browser.tabs.onUpdated.addListener(this.onUpdated)

        this.onCompleted = this.onCompleted.bind(this)
        browser.webRequest.onCompleted.addListener(
            this.onCompleted,
            { urls: ["<all_urls>"], types: ptk_utils.requestFilters },
            ["responseHeaders"].concat(ptk_utils.extraInfoSpec)
        )
    }

    async onUpdated(tabId, info, tab) {
        if (!this.isTrackedScanTab(tabId)) return
        if (String(info?.status || '').toLowerCase() !== 'complete') return
        const url = String(tab?.url || info?.url || '').trim()
        if (!this.scopedTabCoordinator?.isUrlInScope?.('SCA', url)) return
        this.collectCurrentTabResources(tabId)
            .then((resources) => this.scanResourceList(resources, tabId))
            .catch(() => { })
    }

    removeListeners() {
        browser.tabs.onRemoved.removeListener(this.onRemoved)
        browser.tabs.onUpdated.removeListener(this.onUpdated)
        browser.webRequest.onCompleted.removeListener(this.onCompleted)
    }

    onRemoved(tabId, info) {
        if (this.activeTabId === tabId) {
            this.activeTabId = null
            this.isScanRunning = false
        }
    }

    onCompleted(response) {
        if (this.isTrackedScanTab(response.tabId) && ptk_utils.isURL(response?.url)
            && (!this.scopedTabCoordinator?.isUrlInScope || this.scopedTabCoordinator.isUrlInScope('SCA', response.url))) {
            if (!this.urls.includes(response.url)) {
                this.urls.push(response.url)
                const scan = this.scanResult
                this.scan(response.url, { metadataOnly: !!this.browserCaptureManager })
                    .then(result => { if (this.isScanRunning && this.scanResult === scan) this._ingestScanResults(result) })
                    .catch(() => { })
            }
        }
    }

    _ingestScanResults(result, acquisition = null) {
        const components = this._convertRuntimeResults(result?.vulns || [])
        if (!components.length) {
            return 0
        }
        let newFindings = buildFindingsFromComponents(components, {
            scanId: this.scanResult?.scanId || null,
            createdAt: new Date().toISOString()
        })
        if (!newFindings.length) {
            return 0
        }
        if (acquisition) {
            const previous = new Map((this.scanResult.findings || []).map(finding => [finding.id, finding.evidence?.sca]))
            newFindings = newFindings.map(finding => ({ ...finding, evidence: { ...finding.evidence,
                sca: { ...finding.evidence?.sca, acquisition,
                    acquisitions: [...new Set([...(previous.get(finding.id)?.acquisitions ||
                        [previous.get(finding.id)?.acquisition].filter(Boolean)), acquisition])] } } }))
        }
        if (!Array.isArray(this.scanResult.findings)) {
            this.scanResult.findings = []
        }
        const before = this.scanResult.findings.length
        this.scanResult.findings = mergeScaFindingLists(this.scanResult.findings, newFindings)
        this.updateScanResult()
        return Math.max(0, this.scanResult.findings.length - before)
    }

    updateScanResult() {
        this.scanResult.packages = this._buildPackagesFromFindings(this.scanResult.findings)
        this.scanResult.stats = this._recalculateStats(this.scanResult.findings, this.scanResult.packages)
        if (!Array.isArray(this.scanResult.groups)) {
            this.scanResult.groups = []
        }
        this._schedulePersistScanResult()
    }

    _schedulePersistScanResult() {
        if (this._persistTimer) return
        this._persistTimer = setTimeout(() => {
            this._persistTimer = null
            ptk_storage.setItem(this.storageKey, this.scanResult)
        }, this._persistDebounceMs)
    }

    _flushPersistScanResult() {
        if (this._persistTimer) {
            clearTimeout(this._persistTimer)
            this._persistTimer = null
        }
        ptk_storage.setItem(this.storageKey, this.scanResult)
    }

    getFileName(url) {
        var a = new URL(url)//document.createElement("a");
        //a.href = url;
        return (a.pathname.match(/\/([^\/?#]+)$/i) || [, ""])[1];
    }

    _bodyGap(url, reason, record = {}, kind = 'body') {
        const coverage = kind === 'source'
            ? (this.scanResult.scaSourceCoverage ||= { captured: 0, analyzed: 0, gaps: 0 })
            : (this.scanResult.scaBodyCoverage ||= { captured: 0, analyzed: 0, gaps: 0 })
        coverage.gaps++
        const warnings = this.scanResult.coverageWarnings ||= []
        if (warnings.length < 200) warnings.push({ url: url || null, reason, tabId: record.tabId ?? null,
            requestId: record.requestId || null, ...(Number.isInteger(record.response?.status) ? { status: record.response.status } : {}), documentId: record.documentId || record.loaderId || null,
            ...(kind === 'source' ? { acquisition: 'debugger_script_source' } : {}) })
        this._schedulePersistScanResult()
    }

    _chargeAcquisition(entry, content) {
        const bytes = content.length * 2
        const resourceLimit = entry.acquisition?.maxResourceBytes || 8 * 1024 * 1024
        const totalLimit = entry.acquisition?.maxTotalBytes || 32 * 1024 * 1024
        if (bytes > resourceLimit) throw Error('acquisition_resource_limit')
        if ((entry.acquiredBytes || 0) + bytes > totalLimit) throw Error('acquisition_total_limit')
        entry.acquiredBytes = (entry.acquiredBytes || 0) + bytes
    }

    _contentAlreadyAnalyzed(entry, documentKey, content, mark = false) {
        entry.analyzedContent ||= new Map()
        const hash = CryptoES.SHA256(content).toString(CryptoES.enc.Hex)
        const hashes = entry.analyzedContent.get(documentKey)
        if (hashes?.has(hash)) return true
        if (mark && entry.analyzedContent.size < 512) {
            if (!hashes) entry.analyzedContent.set(documentKey, new Set([hash]))
            else if (hashes.size < 64) hashes.add(hash)
        }
        return false
    }

    async _onSourceBatch(entry, lease, batch) {
        const gap = (...args) => { if (this.scanResult === entry.scan) this._bodyGap(...args) }
        try {
            entry.analyzedScripts ||= new Set()
            entry.analyzedBodies ||= new Set()
            if (this.captureLeases?.get(lease.tabId) !== entry || this.scanResult !== entry.scan || !this.isScanRunning || !batch.isActive()) return
            const { identity, records, incompleteCount = 0 } = batch.read()
            if (identity.epoch !== lease.epoch || identity.captureId !== lease.captureId
                || identity.ownerId !== entry.ownerId || identity.tabId !== lease.tabId) throw new Error('script_source_owner_changed')
            for (const record of records) {
                if (!record.executedSource) continue
                const key = scaCaptureKey(record)
                const documentKey = JSON.stringify([record.tabId, record.sessionId || '', record.frameId,
                    record.documentId || record.loaderId, record.sessionGeneration, record.navigationGeneration, record.url])
                if (!key || entry.analyzedScripts.has(key) || entry.analyzedBodies.has(documentKey)) continue
                entry.analyzedScripts.add(key)
                try {
                    const content = decodeScaExecutedSource(record, entry.acquisition?.maxResourceBytes)
                    this._chargeAcquisition(entry, content)
                    entry.sourceUrls?.add(record.url)
                    this.scanResult.scaSourceCoverage.captured++
                    await this.ensureRepoReady()
                    if (this.captureLeases?.get(lease.tabId) !== entry || this.scanResult !== entry.scan
                        || !this.isScanRunning || !batch.isActive()) throw new Error('script_source_revoked_before_analysis')
                    if (!this.retire || !this.repo || !Object.keys(this.repo).length) throw new Error('sca_repository_unavailable')
                    if (this._contentAlreadyAnalyzed(entry, documentKey, content)) continue
                    const detections = this.retire.scanFileContent(content, this.repo, this.hasher)
                    if (detections.length) this._ingestScanResults({ vulns: [[record.url, detections, key]] }, 'debugger_script_source')
                    this._contentAlreadyAnalyzed(entry, documentKey, content, true)
                    this.scanResult.scaSourceCoverage.analyzed++
                } catch (error) {
                    gap(record.url, error?.message || 'script_source_analysis_failed', record, 'source')
                }
            }
            if (incompleteCount) gap(identity.url, 'script_source_batch_incomplete', identity, 'source')
        } catch (error) {
            gap(null, error?.message || 'script_source_batch_unavailable', { tabId: lease.tabId }, 'source')
        } finally { batch.release(); this._schedulePersistScanResult() }
    }

    async _onCapturedResource(entry, lease, event) {
        const gap = (...args) => { if (this.scanResult === entry.scan) this._bodyGap(...args) }
        if (this.captureLeases?.get(lease.tabId) !== entry || this.scanResult !== entry.scan || !this.isScanRunning) return
        const record = event.record || {}
        if (event.type === 'gap') {
            const requestKey = scaRequestKey(record)
            if (requestKey) entry.requests.delete(requestKey)
            gap(null, record.reason || 'capture_unavailable', record,
                /^script_source_/.test(record.reason || '') ? 'source' : 'body')
            return
        }
        if (!isScaBodyCandidate(record)) return
        const key = scaCaptureKey(record)
        const requestKey = scaRequestKey(record)
        if (!key) {
            if (event.type === 'body' || event.type === 'request') gap(record.url, 'capture_identity_unavailable', record)
            return
        }
        if (event.type === 'request') {
            if (entry.requests.size >= 512) gap(record.url, 'sca_request_limit', record)
            else entry.requests.set(requestKey, { url: record.url, tabId: record.tabId, requestId: record.requestId, documentId: record.documentId, loaderId: record.loaderId })
            return
        }
        if (event.type === 'response' && !entry.requests.has(requestKey)) {
            if (entry.requests.size >= 512) gap(record.url, 'sca_request_limit', record)
            else entry.requests.set(requestKey, { url: record.url, tabId: record.tabId, requestId: record.requestId,
                documentId: record.documentId, loaderId: record.loaderId })
            return
        }
        if (event.type !== 'body') return
        entry.requests.delete(requestKey)
        // The lease/store grant, rather than a URL match, proves owner and exact
        // native request/document identity. A revoked or replaced grant is unusable.
        const owned = lease.getResource(key)
        if (owned !== record) { gap(record.url, 'capture_body_unavailable', record); return }
        try {
            const content = decodeScaBody(owned, entry.acquisition?.maxResourceBytes)
            this._chargeAcquisition(entry, content)
            const coverage = this.scanResult.scaBodyCoverage ||= { captured: 0, analyzed: 0, gaps: 0 }
            coverage.captured++
            await this.ensureRepoReady()
            if (this.scanResult !== entry.scan) return
            if (this.captureLeases?.get(lease.tabId) !== entry || !this.isScanRunning || !lease.getResource(key)) {
                gap(record.url, 'capture_revoked_before_analysis', record)
                return
            }
            if (!this.retire || !this.repo || !Object.keys(this.repo).length) throw new Error('sca_repository_unavailable')
            const documentKey = JSON.stringify([record.tabId, record.sessionId || '', record.frameId,
                record.documentId || record.loaderId, record.sessionGeneration, record.navigationGeneration, record.url])
            if (this._contentAlreadyAnalyzed(entry, documentKey, content)) {
                entry.analyzedBodies.add(documentKey)
                return
            }
            const detections = this.retire.scanFileContent(content, this.repo, this.hasher)
            if (detections.length) this._ingestScanResults({ vulns: [[record.url, detections, key]] }, 'captured_http_body')
            this._contentAlreadyAnalyzed(entry, documentKey, content, true)
            coverage.analyzed++
            (entry.analyzedBodies ||= new Set()).add(documentKey)
        } catch (error) {
            gap(record.url, error?.message || 'response_body_analysis_failed', record)
        } finally {
            lease.consume(key)
            this._schedulePersistScanResult()
        }
    }

    async scan(url, { metadataOnly = false } = {}) {
        await this.ensureRepoReady()
        const retire = this.retire
        if (!retire || !this.repo || !Object.keys(this.repo).length) {
            return Promise.resolve({ "vulns": [] })
        }
        let dt = new Array()
        let fetches = []

        let results = retire.scanUri(url, this.repo)
        if (results.length > 0) {
            let hash = url + results[0].component + results[0].version
            if (dt.findIndex(u => u[2] == hash) == -1) {
                dt.push([url, results, hash])
            }
        }

        results = retire.scanFileName(this.getFileName(url), this.repo)
        if (results.length > 0) {
            let hash = url + results[0].component + results[0].version
            if (dt.findIndex(u => u[2] == hash) == -1) {
                dt.push([url, results, hash])
            }
        }

        if (!metadataOnly) fetches.push(
            (this.certXFetch ? this.certXFetch(url) : fetch(url))
                .then(response => response.text())
                .then(content => {
                    var results = retire.scanFileContent(content, this.repo, this.hasher);
                    if (results.length > 0) {
                        let hash = url + results[0].component + results[0].version
                        if (dt.findIndex(u => u[2] == hash) == -1) {
                            dt.push([url, results, hash])
                        }
                    }
                })
                .catch(error => { if (this.certXFetch) { this.scanResult.coverageWarnings ||= []; this.scanResult.coverageWarnings.push({url,reason:error?.message || String(error)}); } })
        )

        if (fetches.length) {
            await Promise.all(fetches).then()
        }
        return Promise.resolve({ "vulns": dt })
    }

    _convertRuntimeResults(entries = []) {
        const components = []
        entries.forEach(tuple => {
            if (!Array.isArray(tuple) || tuple.length < 2) return
            const sourceFile = tuple[0] || null
            const detections = tuple[1]
            if (!Array.isArray(detections)) return
            detections.forEach(item => {
                if (!item || typeof item !== "object") return
                const normalized = normalizeComponentEntry({
                    file: sourceFile,
                    component: item.component,
                    version: item.version,
                    detection: item.detection,
                    npmname: item.npmname,
                    basePurl: item.basePurl,
                    findings: item.vulnerabilities || []
                })
                if (normalized && Array.isArray(normalized.findings) && normalized.findings.length) {
                    components.push(normalized)
                }
            })
        })
        return components
    }


    onMessage(message, sender, sendResponse) {
        if (message.channel == "ptk_popup2background_sca") {
            if (!ptk_utils.isTrustedExtensionPageSender(sender)) {
                return Promise.resolve({ result: false, error: 'untrusted_extension_sender' })
            }
            if (this["msg_" + message.type]) {
                return this["msg_" + message.type](message)
            }
            return Promise.resolve({ result: false })
        }
    }



    async msg_init(message) {
        await this.init()
        if (!this.isScanRunning && this.scanResult?.finishedAt) applyScanAnalysis(this.scanResult, { force: true })
        const scanResult = this._cloneScanResultForUi({ ensureAnalysis: false })
        const hasRenderableData = Array.isArray(scanResult?.findings) && scanResult.findings.length > 0
        return Promise.resolve({
            scanResult,
            isScanRunning: this.isScanRunning,
            viewState: this.isScanRunning ? 'running' : (hasRenderableData ? 'idle_with_data' : 'idle_empty'),
            activeTab: worker.ptk_app.proxy.activeTab
        })
    }


    msg_reset(message) {
        this.reset()
        return Promise.resolve({
            scanResult: this._cloneScanResultForUi({ ensureAnalysis: false }),
            activeTab: worker.ptk_app.proxy.activeTab
        })
    }

    async msg_loadfile(message) {
        this.reset()
        const parsed = await parseUploadedScanFile(message?.file)
        if (!parsed?.ok || !parsed?.json) {
            return Promise.reject(new Error("Wrong format or empty scan result"))
        }
        return this.msg_save({ json: JSON.stringify(parsed.json) })
    }

    async msg_save(message) {
        let res = JSON.parse(message.json)
        if (!res) {
            return Promise.reject(new Error("Wrong format or empty scan result"))
        }
        const normalized = this._normalizeEnvelope(res)
        if (!Array.isArray(normalized.findings) || normalized.findings.length === 0) {
            return Promise.reject(new Error("Wrong format or empty scan result"))
        }
        this.scanResult = normalized
        if (this.scanResult && this.scanResult.finishedAt) {
            try {
                applyScanAnalysis(this.scanResult, { force: false })
            } catch (_) { }
        }
        this._flushPersistScanResult()
        return Promise.resolve({
            scanResult: this._cloneScanResultForUi({ ensureAnalysis: true }),
            isScanRunning: this.isScanRunning,
            activeTab: worker.ptk_app.proxy.activeTab
        })
    }

    async msg_run_bg_scan(message) {
        await this.runBackgroundScan(message.tabId, message.host)
        return Promise.resolve({ isScanRunning: this.isScanRunning, scanResult: this._cloneScanResultForUi({ ensureAnalysis: false }) })
    }

    async msg_stop_bg_scan(message) {
        await this.stopBackgroundScan()
        return Promise.resolve({
            scanResult: this._cloneScanResultForUi({ ensureAnalysis: true }),
            isScanRunning: this.isScanRunning
        })
    }

    async msg_get_projects(message) {
        await initializePortalRuntimeConfig()
        const profile = worker.ptk_app.settings.profile || {}
        const apiKey = profile?.api_key
        if (!apiKey) {
            return { success: false, json: { message: "No API key found" } }
        }
        const url = this.buildPortalUrl("/projects")
        if (!url) {
            return { success: false, json: { message: "Portal endpoint is not configured." } }
        }
        const response = await fetch(url, {
            headers: {
                'Authorization': 'Bearer ' + apiKey,
                'Accept': 'application/json'
            },
            credentials: 'omit',
            redirect: 'error',
            cache: 'no-cache'
        })
            .then(async (httpResponse) => {
                const json = await httpResponse.json().catch(() => null)
                if (httpResponse.ok) {
                    return { success: true, json }
                }
                return { success: false, json: json || { message: 'Unable to load projects' } }
            })
            .catch(e => ({ success: false, json: { message: 'Error while loading projects: ' + e.message } }))
        return response
    }

    async msg_save_scan(message) {
        await initializePortalRuntimeConfig()
        const profile = worker.ptk_app.settings.profile || {}
        const apiKey = profile?.api_key
        if (!apiKey) {
            return { success: false, json: { message: "No API key found" } }
        }
        if (!Array.isArray(this.scanResult?.findings) || !this.scanResult.findings.length) {
            const stored = await ptk_storage.getItem(this.storageKey) || {}
            if (stored && Object.keys(stored).length > 0) {
                this.scanResult = this._normalizeEnvelope(stored)
            }
        }
        if (!Array.isArray(this.scanResult?.findings) || !this.scanResult.findings.length) {
            return { success: false, json: { message: "Scan result is empty" } }
        }
        const url = this.buildPortalUrl("/scans")
        if (!url) {
            return { success: false, json: { message: "Portal endpoint is not configured." } }
        }
        const payload = buildExportScanResult(this.scanResult?.scanId, {
            target: "portal",
            scanResult: this.scanResult
        })
        if (!payload) {
            return { success: false, json: { message: "Scan result is empty" } }
        }
        if (message?.projectId) {
            payload.projectId = message.projectId
        }
        let compressed
        try {
            compressed = await compressScanPayload(payload)
        } catch (err) {
            return {
                success: false,
                json: { message: "Unable to compress scan payload: " + (err?.message || "compression_failed") }
            }
        }
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Authorization': 'Bearer ' + apiKey,
                'Accept': 'application/json',
                'Content-Type': compressed.contentType,
                'X-PTK-Compression': compressed.compression
            },
            credentials: 'omit',
            redirect: 'error',
            cache: 'no-cache',
            body: compressed.body
        })
            .then(async (httpResponse) => {
                if (httpResponse.status === 201) {
                    return { success: true }
                }
                const json = await httpResponse.json().catch(() => ({ message: httpResponse.statusText }))
                return { success: false, json }
            })
            .catch(e => ({ success: false, json: { message: 'Error while saving report: ' + e.message } }))
        return response
    }

    async msg_export_scan_result(message) {
        if (!this.scanResult) return null
        try {
            const payload = buildExportScanResult(this.scanResult?.scanId, {
                target: message?.target || "download",
                includeSecrets: message?.includeSecrets === true,
                scanResult: this.scanResult
            })
            if (!payload) return null
            const compressed = await compressScanPayload(payload)
            const descriptor = this.exportChunkStore.createEntry({
                bytes: compressed.body,
                fileName: message?.fileName || "PTK_SCA_scan.json",
                contentType: compressed.contentType,
                compression: compressed.compression,
                owner: message?.owner || null
            })
            if (!descriptor) {
                return { success: false, error: "empty_export_payload" }
            }
            return {
                success: true,
                exportMode: "chunked",
                ...descriptor
            }
        } catch (err) {
            console.error("[PTK SCA] Failed to export scan result", err)
            throw err
        }
    }

    async msg_export_scan_chunk(message) {
        const chunk = this.exportChunkStore.getChunk(message?.exportId, message?.index, message?.owner || null)
        if (!chunk) {
            return { success: false, error: "export_not_found_or_expired" }
        }
        return {
            success: true,
            exportMode: "chunked",
            exportId: chunk.exportId,
            index: chunk.index,
            chunkCount: chunk.chunkCount,
            chunk: chunk.chunk
        }
    }

    async msg_release_export_scan(message) {
        const released = this.exportChunkStore.release(message?.exportId, message?.owner || null)
        return { success: released }
    }

    async msg_download_scans(message) {
        await initializePortalRuntimeConfig()
        const profile = worker.ptk_app.settings.profile || {}
        const apiKey = profile?.api_key
        if (!apiKey) {
            return { success: false, json: { message: "No API key found" } }
        }
        const baseUrl = this.buildPortalUrl("/scans")
        if (!baseUrl) {
            return { success: false, json: { message: "Portal endpoint is not configured." } }
        }
        let requestUrl = baseUrl
        try {
            const url = new URL(baseUrl)
            if (message?.projectId) {
                url.searchParams.set('projectId', message.projectId)
            }
            const engine = message?.engine || 'sca'
            if (engine) {
                url.searchParams.set('engine', engine)
            }
            requestUrl = url.toString()
        } catch (err) {
            return { success: false, json: { message: "Invalid scans endpoint." } }
        }
        const response = await fetch(requestUrl, {
            headers: {
                'Authorization': 'Bearer ' + apiKey,
                'Accept': 'application/json'
            },
            credentials: 'omit',
            redirect: 'error',
            cache: 'no-cache'
        })
            .then(async (httpResponse) => {
                const json = await httpResponse.json().catch(() => null)
                if (httpResponse.ok) {
                    return { success: true, json }
                }
                return { success: false, json: json || { message: 'Unable to load scans' } }
            })
            .catch(e => ({ success: false, json: { message: 'Error while loading scans: ' + e.message } }))
        return response
    }

    async msg_download_scan_by_id(message) {
        await initializePortalRuntimeConfig()
        const profile = worker.ptk_app.settings.profile || {}
        const apiKey = profile?.api_key
        if (!apiKey) {
            return { success: false, json: { message: "No API key found" } }
        }
        if (!message?.scanId) {
            return { success: false, json: { message: "Scan identifier is required." } }
        }
        const baseUrl = this.buildPortalUrl("/scans")
        if (!baseUrl) {
            return { success: false, json: { message: "Portal endpoint is not configured." } }
        }
        const normalizedBase = baseUrl.replace(/\/+$/, "")
        const downloadUrl = `${normalizedBase}/${encodeURIComponent(message.scanId)}/download`
        const response = await fetch(downloadUrl, {
            headers: {
                'Authorization': 'Bearer ' + apiKey,
                'Accept': 'application/gzip, application/x-gzip'
            },
            credentials: 'omit',
            redirect: 'error',
            cache: 'no-cache'
        })
            .then(async (httpResponse) => {
                if (!httpResponse.ok) {
                    const json = await httpResponse.json().catch(() => null)
                    return { success: false, json: json || { message: 'Unable to download scan' } }
                }
                const parsed = await parseDownloadedScanPayload(httpResponse)
                if (!parsed?.ok || !parsed?.json) {
                    return { success: false, json: { message: "Downloaded scan payload is invalid JSON." } }
                }
                if (parsed.json) {
                    const normalized = this._normalizeEnvelope(parsed.json)
                    this.scanResult = normalized
                    if (this.scanResult && this.scanResult.finishedAt) {
                        try {
                            applyScanAnalysis(this.scanResult, { force: false })
                        } catch (_) { }
                    }
                    this._flushPersistScanResult()
                    return this._cloneScanResultForUi({ ensureAnalysis: true })
                }
                return parsed.json
            })
            .catch(e => ({ success: false, json: { message: 'Error while downloading scan: ' + e.message } }))
        return response
    }

    buildPortalUrl(endpoint) {
        return buildStoredCredentialPortalUrl(endpoint)
    }

    async ensureRepoReady() {
        try {
            await (this.repoReady || this.initRepo())
        } catch (_) {
            // already logged in initRepo
        }
    }

    async collectCurrentTabResources(tabId) {
        if (typeof tabId !== 'number') return []
        try {
            const response = await browser.tabs.sendMessage(tabId, {
                channel: "ptk_background2content_sca",
                type: "collect_resources"
            })
            return Array.isArray(response?.resources) ? response.resources : []
        } catch (_) {
            return []
        }
    }

    async scanResourceList(resources = [], tabId = this.activeTabId, { preexisting = false } = {}) {
        const scan = this.scanResult
        const unique = Array.from(new Set(
            (Array.isArray(resources) ? resources : [])
                .map((item) => String(item || '').trim())
                .filter((item) => /^https?:\/\//i.test(item)
                    && (!this.scopedTabCoordinator?.isUrlInScope || this.scopedTabCoordinator.isUrlInScope('SCA', item)))
        ))
        if (preexisting && this.isScanRunning && this.scanResult === scan) {
            const entry = this.captureLeases?.get(tabId)
            if (entry?.scan === scan) for (const url of unique) {
                let scriptPath = false
                try { scriptPath = /\.(?:m?js)$/i.test(new URL(url).pathname) } catch (_) { }
                if (scriptPath && !entry.sourceUrls.has(url)) this._bodyGap(url,
                    'preexisting_script_source_not_observed', { tabId }, 'source')
            }
        }
        for (const url of unique) {
            if (!this.isScanRunning || this.scanResult !== scan) break
            if (this.urls.includes(url)) continue
            this.urls.push(url)
            try {
                const result = await this.scan(url, { metadataOnly: !!this.browserCaptureManager })
                if (this.isScanRunning && this.scanResult === scan) this._ingestScanResults(result)
            } catch (_) { }
        }
    }

    async runBackgroundScan(tabId, host, settings = {}) {
        if (this.isScanRunning) {
            return false
        }
        await this.reset()
        await this.ensureRepoReady()
        this.isScanRunning = true
        this.scanningRequest = false
        this.activeTabId = tabId
        this.scanResult.scanId = ptk_utils.UUID()
        this.scanResult.host = host
        this.scanResult.tabId = tabId
        this.scanResult.startedAt = new Date().toISOString()
        this.scanResult.finishedAt = null
        try {
            this._captureTargetUrl = (await browser.tabs.get(tabId))?.url
            await this._acquireBrowserCapture(tabId, { ...settings, targetUrl: this._captureTargetUrl })
        } catch (error) {
            this.isScanRunning = false
            this.activeTabId = null
            throw error
        }
        try {
            this.addListeners()
            await this.scopedTabCoordinator?.registerSession?.('SCA', {
                primaryTabId: tabId,
                scopeMode: 'origin',
                onEnroll: async (meta) => {
                    await this._acquireBrowserCapture(meta.tabId, { ...settings, targetUrl: this._captureTargetUrl })
                    return this.collectCurrentTabResources(meta.tabId).then(resources => this.scanResourceList(resources, meta.tabId, { preexisting: true }))
                },
                onRelease: meta => this._releaseBrowserCapture(meta.tabId, 'tab_released')
            })
            this.collectCurrentTabResources(tabId)
                .then((resources) => this.scanResourceList(resources, tabId, { preexisting: true }))
                .catch(() => { })
        } catch (error) {
            await this.stopBackgroundScan({ skipPostStopAnalysis: true }).catch(() => {})
            throw error
        }
    }

    async stopBackgroundScan(options = {}) {
        let captureError = null
        try { await this._releaseAllBrowserCapture() } catch (error) { captureError = error }
        this.scopedTabCoordinator?.unregisterSession?.('SCA')
        this.isScanRunning = false
        this.activeTabId = null
        if (this.scanResult) {
            this.scanResult.finishedAt = new Date().toISOString()
        }
        await this._flushPersistScanResult()
        this.removeListeners()
        if (captureError) throw captureError
    }

}

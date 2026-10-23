/* PTK v10 report builders, extracted into a UI-independent owned module. Original author: Denis Podgurskii. */
import { ptk_utils, ptk_jwtHelper } from "../../../background/utils.js"

import { default as dompurify } from "../../../packages/dompurify/purify.es.mjs"

import { redactText, redactHeaders, redactStorage, redactEvidence } from "./report/redaction.js"

import { pdfTheme, setH1, setH2, setBody, setCode, setSmall } from "./report/pdfTheme.js"

import { createPdfLayout, clampCellText, formatUrlForTable } from "./report/pdfLayout.js"

import { drawBadge, drawFlagIcon, drawReplayIcon, drawCheckIcon, drawRiskBarList, drawKeyValueBlock, normalizeEvidenceSummary, drawCodeBlock, drawHostBanner, drawSummaryCard, drawMutedText } from "./report/pdfComponents.js"

import { escapeMarkdownCell, escapeMarkdownText, stripHtmlTags } from "./report/textEncoding.js"
import { drawRunCoverage, runCoverageMarkdown } from "./report/runCoverage.js"

var tokens = new Array()

let index_controller = null

const SAST_ALLOWED_TAGS = ['p', 'ul', 'li', 'code', 'strong', 'em', 'a', 'br', 'pre'];

const SAST_ALLOWED_ATTRS = ['href', 'target', 'rel'];

const EVIDENCE_SNIPPET_MAX = 800

const EXPORT_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

const UI_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

const STORAGE_TOKEN_KEY_REGEX = /(token|access[_-]?token|refresh[_-]?token|id[_-]?token|jwt|session)/i

const SEVERITY_FILTER_CONFIG = {
    dast: { container: "#rattacker_content", item: ".attack_info" },
    iast: { container: "#iast_report_items", item: ".iast_attack_card" },
    sast: { container: "#sast_report_items", item: ".sast-report-card" },
    sca: { container: "#sca_report_items", item: ".sca-report-card" }
}

const exportModel = {
    meta: {
        reportType: null,
        host: null,
        generatedAt: null,
        startTime: null,
        endTime: null,
        scanDuration: null,
        scanStatus: "Finished"
    },
    dashboard: {
        technologies: [],
        owaspHeaders: [],
        cves: [],
        headers: [],
        cookies: [],
        storage: [],
        storageDetails: {
            localStorage: [],
            sessionStorage: []
        },
        tokens: []
    },
    findings: [],
    sections: {
        dast: [],
        iast: [],
        sast: [],
        sca: []
    },
    discoveries: { sast: [], dast: [] },
    summary: {
        byEngine: {},
        bySeverity: {}
    },
    scanStats: {
        urlsSpidered: 0,
        uniqueInjectionPoints: 0,
        totalHttpRequests: 0,
        avgResponseTime: null,
        httpRequestErrors: 0,
        testsPerformed: [],
        testsTotal: 0,
        testsCompleted: 0
    },
    spiderResults: [],
    expectedSections: [],
    sectionsReady: {},
    expectedDashboardParts: {
        technologies: true,
        owasp: true,
        cves: true,
        headers: true,
        cookies: true,
        storage: true
    },
    dashboardPartsReady: {}
}

function normalizeExportSeverity(severity) {
    const normalized = String(severity || "").toLowerCase()
    if (EXPORT_SEVERITY_ORDER.includes(normalized)) return normalized
    return "info"
}

function truncateSnippet(value, max = EVIDENCE_SNIPPET_MAX) {
    if (!value) return ""
    const text = String(value)
    if (!Number.isFinite(max) || max <= 0) return text
    if (text.length <= max) return text
    return `${text.slice(0, Math.max(0, max - 3))}...`
}

function truncateEvidenceBlock(value, { maxChars = 3000, maxLines = 30 } = {}) {
    if (!value) return { text: "", truncated: false }
    const text = String(value)
    const lines = text.split(/\r?\n/)
    let truncated = false
    let trimmed = text
    if (lines.length > maxLines) {
        trimmed = lines.slice(0, maxLines).join("\n")
        truncated = true
    }
    if (trimmed.length > maxChars) {
        trimmed = trimmed.slice(0, Math.max(0, maxChars - 24))
        truncated = true
    }
    if (truncated) {
        trimmed = `${trimmed}\n...[truncated]...`
    }
    return { text: trimmed, truncated }
}

function normalizeTraceForExport(trace) {
    if (!trace) return ""
    if (Array.isArray(trace)) return trace
    if (typeof trace === "object") {
        try {
            return JSON.stringify(trace, null, 2)
        } catch (_) {
            return String(trace)
        }
    }
    return String(trace)
}

function formatLocationRange(location) {
    if (!location || typeof location !== "object") return ""
    const start = location.start || location.sourceLoc?.start || location.sinkLoc?.start || null
    const end = location.end || location.sourceLoc?.end || location.sinkLoc?.end || null
    const startLine = start?.line ?? location.line ?? location.row ?? null
    const startCol = start?.column ?? location.column ?? null
    const endLine = end?.line ?? null
    const endCol = end?.column ?? null
    if (startLine == null && startCol == null) return ""
    const startText = `L${startLine ?? ""}${startCol != null ? `:${startCol}` : ""}`
    if (endLine == null && endCol == null) return startText
    const endText = `L${endLine ?? ""}${endCol != null ? `:${endCol}` : ""}`
    return `${startText}–${endText}`
}

function normalizeEndpointDetails(endpoint) {
    if (!endpoint) return null
    if (typeof endpoint === "string") return { name: endpoint }
    if (typeof endpoint !== "object") return null
    return {
        name: endpoint.name || endpoint.label || endpoint.sourceName || endpoint.sinkName || endpoint.id || "",
        file: endpoint.file || endpoint.sourceFile || endpoint.sinkFile || "",
        location: endpoint.loc || endpoint.sourceLoc || endpoint.sinkLoc || endpoint.location || null
    }
}

function normalizeIastFlowForExport(flow) {
    if (!flow) return ""
    if (Array.isArray(flow)) {
        return flow.map(entry => {
            if (entry === null || entry === undefined) return ""
            if (typeof entry === "string") return entry
            try {
                return JSON.stringify(entry, null, 2)
            } catch (_) {
                return String(entry)
            }
        }).filter(Boolean).join("\n")
    }
    if (typeof flow === "object") {
        try {
            return JSON.stringify(flow, null, 2)
        } catch (_) {
            return String(flow)
        }
    }
    return String(flow)
}

function resolveIastProof(evidence = {}, fallback = {}) {
    const direct = evidence?.matched || evidence?.proof || evidence?.message
    const contextValue = evidence?.context?.value ?? evidence?.context?.valuePreview ?? evidence?.context?.innerHTML ?? evidence?.context?.text
    const fallbackValue = fallback?.matched || fallback?.proof || fallback?.message
    const resolved = direct || contextValue || fallbackValue
    return resolved ? String(resolved) : ""
}

function formatConfidenceLabel(value) {
    if (!Number.isFinite(value)) return ""
    if (value >= 80) return "High"
    if (value >= 50) return "Medium"
    return "Low"
}

function formatTimestamp(value) {
    if (!value) return ""
    const date = new Date(value)
    if (Number.isNaN(date.getTime())) {
        return String(value)
    }
    const pad = (num) => String(num).padStart(2, "0")
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`
}

function formatLocationSummary(location = {}) {
    if (!location || typeof location !== "object") return ""
    const parts = []
    if (location.url) parts.push(String(location.url))
    if (location.file) parts.push(String(location.file))
    const line = location.line != null ? `L${location.line}` : ""
    const column = location.column != null ? `C${location.column}` : ""
    if (line || column) {
        parts.push([line, column].filter(Boolean).join(":"))
    }
    if (location.method) parts.push(String(location.method))
    if (location.param) parts.push(`param:${location.param}`)
    return parts.filter(Boolean).join(" ")
}

function formatFindingId(prefix, index) {
    const num = String(index + 1).padStart(4, "0")
    return `${prefix}-${num}`
}

function buildSummaryTableRows(model, { interactive = true } = {}) {
    const summaryByEngine = model.summary?.byEngine || {}
    const summaryBySeverity = model.summary?.bySeverity || {}
    const engineSeverityCounts = model.findings.reduce((acc, finding) => {
        const engine = finding.engine || "UNKNOWN"
        const severity = normalizeSeverityKey(finding.severity)
        if (!acc[engine]) {
            acc[engine] = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
        }
        acc[engine][severity] += 1
        return acc
    }, {})
    const engines = Object.keys(summaryByEngine).length
        ? Object.keys(summaryByEngine)
        : Object.keys(engineSeverityCounts)
    const rows = engines.map(engine => {
        const sev = engineSeverityCounts[engine] || { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
        const total = summaryByEngine[engine] ?? Object.values(sev).reduce((sum, val) => sum + val, 0)
        const engineKey = String(engine || "").toLowerCase()
        const hasFilter = !!SEVERITY_FILTER_CONFIG[engineKey]
        const selected = new Set(EXPORT_SEVERITY_ORDER)
        const renderSeverityCell = (severity) => {
            const count = sev[severity] || 0
            if (!interactive || !hasFilter) return String(count)
            const checked = selected.has(severity)
            return `<div class="summary-sev-cell">` +
                `<span class="summary-sev-count">${escapeText(String(count), "")}</span>` +
                `<div class="ui mini checkbox ptk-summary-checkbox">` +
                `<input type="checkbox" class="severity-filter summary-severity-filter" data-engine="${engineKey}" data-severity="${severity}"${checked ? " checked" : ""}>` +
                `<label></label>` +
                `</div>` +
                `</div>`
        }
        return {
            isTotal: false,
            cells: [
                interactive ? escapeText(String(engine || "UNKNOWN"), "") : String(engine || "UNKNOWN"),
                renderSeverityCell("critical"),
                renderSeverityCell("high"),
                renderSeverityCell("medium"),
                renderSeverityCell("low"),
                renderSeverityCell("info"),
                String(total)
            ]
        }
    })
    const totals = {
        critical: summaryBySeverity.critical || 0,
        high: summaryBySeverity.high || 0,
        medium: summaryBySeverity.medium || 0,
        low: summaryBySeverity.low || 0,
        info: summaryBySeverity.info || 0
    }
    const totalAll = Object.values(totals).reduce((sum, val) => sum + val, 0)
    rows.push({
        isTotal: true,
        cells: [
            "Total",
            String(totals.critical),
            String(totals.high),
            String(totals.medium),
            String(totals.low),
            String(totals.info),
            String(totalAll)
        ]
    })
    return rows
}

function normalizeOwaspEntries(value) {
    const raw = Array.isArray(value) ? value : (value ? [value] : [])
    return raw.map(entry => {
        if (!entry) return null
        if (typeof entry === "string") {
            const cleaned = entry.replace(/\s+/g, " ").trim()
            const normalized = cleaned.replace(/^(A\d{2}:\d{4})\s*-\s*/i, "$1 - ").replace(/^(A\d{2}:\d{4})(?=[A-Za-z])/i, "$1 - ")
            return normalized
        }
        if (typeof entry === "object") {
            const id = entry.id || entry.code || entry.key || ""
            const name = entry.name || entry.title || ""
            const year = entry.year || entry.version || ""
            if (id && year && name) return `${id}:${year} - ${name}`
            if (id && name) return `${id} - ${name}`
            if (name) return name
        }
        return String(entry)
    }).filter(Boolean)
}

function resolveOwaspList(finding) {
    const sources = [
        finding?.owasp,
        finding?.metadata?.owasp,
        finding?.module_metadata?.owasp,
        finding?.owaspLegacy
    ]
    const merged = sources.flatMap(entry => {
        if (!entry) return []
        return Array.isArray(entry) ? entry : [entry]
    })
    const normalized = normalizeOwaspEntries(merged)
    return Array.from(new Set(normalized))
}

function normalizeCweEntries(value) {
    if (!value) return []
    if (Array.isArray(value)) return value.map(String)
    if (typeof value === "string") {
        return value.split(",").map(item => item.trim()).filter(Boolean)
    }
    return [String(value)]
}

function getByPath(obj, path) {
    if (!obj || !path) return undefined
    return path.split(".").reduce((acc, key) => (acc && acc[key] !== undefined ? acc[key] : undefined), obj)
}

function firstDefined(sources, paths) {
    for (const source of sources) {
        for (const path of paths) {
            const value = getByPath(source, path)
            if (value !== undefined && value !== null && value !== "") return value
        }
    }
    return undefined
}

function inferEnvironmentFromHost(host) {
    if (!host) return "N/A"
    const value = String(host).toLowerCase()
    if (value.includes("localhost") || value.includes("127.0.0.1")) return "Local"
    if (value.includes("staging") || value.includes("stage")) return "Staging"
    if (value.includes("dev")) return "Dev"
    return "Production"
}

function formatDateValue(value) {
    if (!value) return "N/A"
    const date = new Date(value)
    if (Number.isNaN(date.getTime())) return String(value)
    return date.toISOString().replace("T", " ").slice(0, 16)
}

function formatDuration(start, end) {
    if (!start || !end) return "N/A"
    const startDate = new Date(start)
    const endDate = new Date(end)
    if (Number.isNaN(startDate.getTime()) || Number.isNaN(endDate.getTime())) return "N/A"
    const ms = Math.max(0, endDate.getTime() - startDate.getTime())
    const mins = Math.floor(ms / 60000)
    const hours = Math.floor(mins / 60)
    const remMins = mins % 60
    if (hours > 0) return `${hours}h ${remMins}m`
    return `${remMins}m`
}

function resolveReportContext(sourceModel = {}) {
    const sources = [
        sourceModel.meta || {},
        sourceModel || {},
        exportModel.meta || {},
        exportModel || {},
        index_controller?.tab || {},
        index_controller?.tab?.scanResult || {},
        index_controller?.tab?.scanContext || {},
        index_controller?.tab?.scan || {}
    ]

    const target = firstDefined(sources, ["target.origin", "target.url", "meta.target", "scan.target", "host", "origin"]) || sourceModel.meta?.host || "N/A"
    const startTime = firstDefined(sources, ["meta.startedAt", "scan.startedAt", "startedAt", "timestamps.start", "startTime"])
    const endTime = firstDefined(sources, ["meta.finishedAt", "scan.endedAt", "endedAt", "timestamps.end", "endTime"])
    const ptkVersion = firstDefined(sources, ["meta.ptkVersion", "ptk.version", "client.version", "version"]) || "N/A"
    const policyName = firstDefined(sources, ["policy.name", "scan.policyName", "meta.policy", "profile.name"]) || "N/A"
    const scopeSummary = firstDefined(sources, ["scope", "meta.scope", "scan.scope"]) || "N/A"
    const authUsed = firstDefined(sources, ["auth.used", "meta.authUsed", "scan.authenticated"])

    const authResolved = authUsed === true
        ? "Yes"
        : authUsed === false
            ? "No"
            : "Unknown"

    return {
        target: target || "N/A",
        environment: firstDefined(sources, ["environment", "meta.environment", "scan.environment"]) || inferEnvironmentFromHost(target),
        scanStart: startTime ? formatDateValue(startTime) : "N/A",
        scanEnd: endTime ? formatDateValue(endTime) : "N/A",
        duration: formatDuration(startTime, endTime),
        ptkVersion,
        policyName,
        scopeSummary: typeof scopeSummary === "string" ? scopeSummary : JSON.stringify(scopeSummary),
        authUsed: authResolved
    }
}

function inferOwnerHint(finding) {
    const engine = String(finding?.engine || "").toUpperCase()
    const title = String(finding?.title || "").toLowerCase()
    const asset = String(finding?.location?.url || finding?.location?.route || finding?.location?.file || "").toLowerCase()
    if (engine === "SCA") return "Dependency"
    if (engine === "SAST") {
        if (title.includes("dom") || title.includes("xss") || asset.endsWith(".js") || asset.endsWith(".ts") || asset.endsWith(".jsx") || asset.endsWith(".tsx")) {
            return "Frontend"
        }
        return "App"
    }
    if (engine === "DAST" || engine === "IAST") {
        if (asset.includes("/api")) return "API"
        return "App"
    }
    return "App"
}

function inferFix(finding) {
    const title = String(finding?.title || "").toLowerCase()
    if (finding?.engine === "SCA") return "Upgrade to a secure version."
    if (title.includes("xss")) return "Encode output and use safe DOM APIs."
    if (title.includes("sql")) return "Use parameterized queries/ORM."
    if (title.includes("ssrf")) return "Validate URLs and block internal ranges."
    if (title.includes("csrf")) return "Add CSRF tokens and SameSite cookies."
    if (title.includes("rce") || title.includes("remote code")) return "Avoid dynamic code execution; validate inputs."
    if (title.includes("xxe")) return "Disable external entities."
    if (title.includes("jwt") || title.includes("token")) return "Store tokens securely; validate signing."
    if (title.includes("cors")) return "Restrict allowed origins and methods."
    if (title.includes("header")) return "Set recommended security headers."
    return "Apply recommended validation and security controls."
}

function buildExecutiveConclusion(model, tiers) {
    const severity = model.summary?.bySeverity || {}
    if (tiers.confirmedHigh > 0 || severity.critical > 0 || severity.high > 0) {
        return "High-severity findings detected; review evidence and prioritize remediation."
    }
    if (tiers.likely > 0) {
        return "Likely issues detected; validate and prioritize remediation."
    }
    let line = "No high-severity findings reported; review coverage and remaining candidates."
    const sastCount = model.sections?.sast?.length || 0
    const total = model.findings.length || 1
    if (sastCount / total > 0.6) {
        line += " SAST findings skew low/medium and may include false positives."
    }
    return line
}

function buildTopRisksLabel(summary = {}) {
    return "Top 5 Highest Risks"
}

function buildReferenceSummary(finding) {
    const refs = finding?.references || []
    if (!refs.length) return "N/A"
    return refs
        .map(ref => ref?.url || ref)
        .filter(Boolean)
        .slice(0, 2)
        .join(", ")
}

function renderMappingSectionMarkdown(cweList, owaspList) {
    const cwe = normalizeCweEntries(cweList)
    const owasp = Array.from(new Set(normalizeOwaspEntries(owaspList)))
    const lines = []
    if (cwe.length) lines.push(`**CWE:** ${escapeMarkdownText(cwe.join(", "))}`)
    if (owasp.length) lines.push(`**OWASP:** ${escapeMarkdownText(owasp.join(", "))}`)
    return lines.join("\n")
}

function stripHtmlToText(value) {
    if (!value) return ""
    const safeHtml = sanitizeRichText(String(value))
    const div = document.createElement("div")
    div.innerHTML = safeHtml
    return (div.textContent || div.innerText || "").trim()
}

function groupFindingsForExec(findings = [], { keyFn, maxItems = 10 } = {}) {
    const map = new Map()
    findings.forEach(item => {
        const key = keyFn ? keyFn(item) : (item.title || item.findingId || "finding")
        if (!map.has(key)) {
            map.set(key, { item, count: 0 })
        }
        const entry = map.get(key)
        entry.count += 1
        if (severityRank(item?.severity) < severityRank(entry.item?.severity)) {
            entry.item = item
        }
        const conf = Number.isFinite(item?.confidence) ? item.confidence : null
        const entryConf = Number.isFinite(entry.item?.confidence) ? entry.item.confidence : null
        if (conf !== null && (entryConf === null || conf > entryConf)) {
            entry.item = item
        }
    })
    return Array.from(map.values())
        .sort((a, b) => severityRank(a.item?.severity) - severityRank(b.item?.severity))
        .slice(0, maxItems)
}

function normalizeScaKey(item) {
    const name = item?.componentName || ""
    const version = item?.componentVersion || ""
    if (name || version) {
        return `${name}@${version || "unknown"}`
    }
    const title = String(item?.title || "")
    const base = title.split(" - ")[0].trim()
    return base || title || "component"
}

function resolveFindingCategory(finding) {
    const parts = []
    const cwe = Array.isArray(finding?.cwe) ? finding.cwe : (finding?.cwe ? [finding.cwe] : [])
    if (cwe.length) parts.push(cwe.join(", "))
    const owasp = Array.isArray(finding?.owasp) ? finding.owasp : (finding?.owasp ? [finding.owasp] : [])
    if (owasp.length) {
        const label = owasp
            .map(entry => (typeof entry === "string" ? entry : entry?.id || entry?.name || ""))
            .filter(Boolean)
            .join(", ")
        if (label) parts.push(label)
    }
    return parts.join(" | ")
}

function formatAssetForOverview(location = {}) {
    const raw = location.url || location.route || location.file || ""
    const formatted = formatUrlForTable(raw, "overview")
    return clampCellText(formatted, { maxChars: 90, maxLines: 2 })
}

function formatAssetForDetail(location = {}) {
    const raw = location.url || location.route || location.file || ""
    const base = formatUrlForTable(raw, "overview")
    const line = location.line != null ? `L${location.line}` : ""
    const column = location.column != null ? `C${location.column}` : ""
    const suffix = line || column ? ` ${[line, column].filter(Boolean).join(":")}` : ""
    return `${base}${suffix}`.trim()
}

function isJwtToken(value) {
    if (!value) return false
    return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(String(value))
}

function decodeJwtPayload(token) {
    if (!isJwtToken(token)) return null
    try {
        const payload = token.split(".")[1]
        const base64 = payload.replace(/-/g, "+").replace(/_/g, "/")
        const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=")
        const json = atob(padded)
        return JSON.parse(json)
    } catch (_) {
        return null
    }
}

function buildTokenSummaryEntries(dashboard = {}) {
    const entries = []
    const addEntry = (source, key, value) => {
        if (!value) return
        const token = String(value)
        const isJwt = isJwtToken(token)
        const payload = isJwt ? decodeJwtPayload(token) : null
        let validity = "present"
        if (isJwt) {
            if (!payload) {
                validity = "malformed"
            } else if (payload.exp) {
                const exp = Number(payload.exp)
                if (Number.isFinite(exp)) {
                    validity = exp * 1000 < Date.now() ? "expired" : "exp present"
                }
            } else {
                validity = "exp missing"
            }
        }
        entries.push({
            source,
            key,
            tokenType: isJwt ? "JWT" : "opaque",
            validity,
            note: source.includes("localStorage")
                ? "token stored in localStorage is high risk for XSS"
                : ""
        })
    }

    const storageDetails = dashboard.storageDetails || {}
    const addFromStorage = (source, list = []) => {
        list.forEach(entry => {
            if (!entry || !entry.key) return
            if (STORAGE_TOKEN_KEY_REGEX.test(String(entry.key))) {
                addEntry(source, entry.key, entry.value)
            }
        })
    }
    addFromStorage("localStorage", storageDetails.localStorage || [])
    addFromStorage("sessionStorage", storageDetails.sessionStorage || [])

    const cookies = dashboard.cookies || []
    cookies.forEach(cookie => {
        if (STORAGE_TOKEN_KEY_REGEX.test(cookie?.name || "")) {
            addEntry("cookie", cookie.name, cookie.value)
        }
    })

    const headers = dashboard.headers || []
    headers.forEach(header => {
        if (STORAGE_TOKEN_KEY_REGEX.test(header?.name || "")) {
            addEntry("header", header.name, header.value)
        }
    })

    return entries
}

function buildTokenPayloadForTechnical(tokenValue, opts = {}) {
    if (!tokenValue) return ""
    const payload = decodeJwtPayload(tokenValue)
    if (!payload || typeof payload !== "object") return ""
    const allowlist = new Set(["iss", "aud", "sub", "iat", "nbf", "exp", "jti", "scope", "roles", "role", "azp", "kid", "typ"])
    const blocked = /(email|password|secret|hash|totp|phone|address|name|username)/i
    const result = {}
    Object.keys(payload).forEach(key => {
        if (!allowlist.has(key)) return
        if (blocked.test(key)) return
        const value = payload[key]
        if (value === undefined || value === null) return
        const str = typeof value === "string" ? value : JSON.stringify(value)
        result[key] = str.length > 80 ? `${str.slice(0, 77)}...` : str
    })
    return Object.keys(result).length ? JSON.stringify(result, null, 2) : ""
}

function buildReferenceList(links) {
    if (!links) return []
    if (Array.isArray(links)) {
        return links.map(entry => {
            if (!entry) return null
            if (typeof entry === "string") return { title: null, url: entry }
            if (typeof entry === "object") return { title: entry.title || entry.name || null, url: entry.url || entry.href || null }
            return null
        }).filter(entry => entry?.url)
    }
    if (typeof links === "object") {
        return Object.entries(links)
            .map(([title, url]) => ({ title, url }))
            .filter(entry => entry.url)
    }
    return []
}

// Severity filtering is supplied in the report model, not read from a popup DOM.

function buildReportModel(sourceModel, options = {}) {
    const preset = options.preset || "executive"
    const includeSensitiveEvidence = !!options.includeSensitiveEvidence
    const opts = { includeSensitiveEvidence }
    const rawGeneratedAt = sourceModel.meta?.generatedAt || exportModel.meta.generatedAt || new Date().toISOString()
    const model = {
        meta: {
            host: sourceModel.meta?.host || exportModel.meta.host || "unknown",
            reportType: sourceModel.meta?.reportType || exportModel.meta.reportType || "report",
            generatedAt: formatTimestamp(rawGeneratedAt),
            generatedAtRaw: rawGeneratedAt,
            logoDataUrl: options.logoDataUrl || null,
            preset,
            redactionApplied: true,
            context: resolveReportContext(sourceModel)
        },
        summary: { byEngine: {}, bySeverity: {} },
        dashboard: {
            assessed: sourceModel.dashboard?.assessed === true,
            technologies: sourceModel.dashboard?.technologies || [],
            owaspHeaders: sourceModel.dashboard?.owaspHeaders || [],
            cves: sourceModel.dashboard?.cves || [],
            headers: sourceModel.dashboard?.headers || [],
            cookies: sourceModel.dashboard?.cookies || [],
            storage: sourceModel.dashboard?.storage || [],
            storageDetails: sourceModel.dashboard?.storageDetails || { localStorage: [], sessionStorage: [] },
            tokens: sourceModel.dashboard?.tokens || [],
            tokenSummary: [],
            tokenPayloadNote: ""
        },
        sections: { dast: [], iast: [], sast: [], sca: [] },
        discoveries: {
            dast: [],
            sast: Array.isArray(sourceModel.discoveries?.sast) ? sourceModel.discoveries.sast : []
        },
        findings: [],
        scanStats: sourceModel.scanStats || {
            urlsSpidered: 0,
            uniqueInjectionPoints: 0,
            totalHttpRequests: 0,
            avgResponseTime: null,
            httpRequestErrors: 0,
            testsPerformed: [],
            testsTotal: 0,
            testsCompleted: 0
        },
        spiderResults: sourceModel.spiderResults || []
    }

    model.dashboard.headers = redactHeaders(model.dashboard.headers, opts)
    model.dashboard.cookies = model.dashboard.cookies.map(item => ({
        ...item,
        value: redactText(item.value, opts)
    }))
    const redactStorageEntries = (entries = []) => {
        return entries.map(entry => {
            const key = entry?.key || ""
            if (STORAGE_TOKEN_KEY_REGEX.test(String(key)) && !includeSensitiveEvidence) {
                return { ...entry, value: "[REDACTED]" }
            }
            return { ...entry, value: redactText(entry?.value, opts) }
        })
    }
    model.dashboard.storageDetails = {
        localStorage: redactStorageEntries(model.dashboard.storageDetails.localStorage || []),
        sessionStorage: redactStorageEntries(model.dashboard.storageDetails.sessionStorage || [])
    }
    const rawTokens = model.dashboard.tokens || []
    model.dashboard.tokens = redactStorage(rawTokens, opts)
    model.dashboard.tokenSummary = buildTokenSummaryEntries(sourceModel.dashboard || {})
    if (preset === "executive") {
        model.dashboard.tokens = []
        model.dashboard.tokenPayloadNote = "Token payloads omitted in Executive exports."
    } else {
        model.dashboard.tokens = rawTokens.map(entry => {
            const tokenValue = entry?.token || ""
            const payload = buildTokenPayloadForTechnical(tokenValue, opts)
            const redactedToken = redactText(tokenValue, opts)
            return {
                ...entry,
                token: redactedToken,
                payload
            }
        }).filter(entry => entry.payload)
        model.dashboard.tokenPayloadNote = "Payload fields are allowlisted; sensitive fields are omitted."
    }

    const sectionMap = [
        { id: "dast", prefix: "DAST" },
        { id: "iast", prefix: "IAST" },
        { id: "sast", prefix: "SAST" },
        { id: "sca", prefix: "SCA" },
        { id: "dast", prefix: "DAST-RECON", discovery: true }
    ]

    const byEngine = {}
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }

    sectionMap.forEach(section => {
        const raw = (section.discovery ? sourceModel.discoveries?.dast : sourceModel.sections?.[section.id]) || []
        const sorted = raw.slice().sort((a, b) => severityRank(a?.severity) - severityRank(b?.severity))
        const mapped = sorted.map((finding, index) => {
            const confidence = Number.isFinite(finding?.confidence) ? finding.confidence : null
            const evidence = redactEvidence(finding?.evidence || {}, opts)
            const request = truncateEvidenceBlock(evidence?.requestSnippet || "")
            const response = truncateEvidenceBlock(evidence?.responseSnippet || "")
            const code = truncateEvidenceBlock(evidence?.codeSnippet || "")
            const notes = truncateEvidenceBlock(evidence?.notes || "")
            const evidenceTruncated = request.truncated || response.truncated || code.truncated || notes.truncated
            return {
                ...finding,
                findingId: formatFindingId(section.prefix, index),
                engine: section.prefix,
                category: resolveFindingCategory(finding),
                confidence,
                confidenceLabel: formatConfidenceLabel(confidence),
                evidence: {
                    ...evidence,
                    requestSnippet: redactText(request.text, opts),
                    responseSnippet: redactText(response.text, opts),
                    codeSnippet: redactText(code.text, opts),
                    notes: redactText(notes.text, opts),
                    evidenceTruncated
                }
            }
        })
        if (section.discovery) {
            model.discoveries.dast = mapped.map(item => ({
                ...item,
                summary: item.description,
                details: [
                    item.recommendation,
                    item.evidence.requestSnippet,
                    item.evidence.responseSnippet,
                    item.evidence.notes
                ].filter(Boolean)
            }))
            return
        }
        model.sections[section.id] = mapped
        model.findings = model.findings.concat(mapped)
        if (mapped.length) byEngine[section.prefix] = mapped.length
    })

    model.findings.forEach(finding => {
        const severity = normalizeSeverityKey(finding.severity)
        bySeverity[severity] = (bySeverity[severity] || 0) + 1
    })
    model.summary = { byEngine, bySeverity }
    return model
}

function buildExportFindingFromNormalized(finding, viewModel) {
    const engine = finding?.engine || "UNKNOWN"
    const location = finding?.location || {}
    const references = buildReferenceList(finding?.links)
    const exportFinding = {
        engine,
        severity: normalizeExportSeverity(finding?.severity),
        confidence: Number.isFinite(finding?.confidence) ? finding.confidence : null,
        title: finding?.ruleName || finding?.vulnId || finding?.category || "Finding",
        description: finding?.description || finding?.metadata?.description || finding?.module_metadata?.description || "",
        recommendation: finding?.recommendation || finding?.metadata?.recommendation || finding?.module_metadata?.recommendation || "",
        location: {
            url: location?.url || null,
            route: location?.route || null,
            file: location?.file || null,
            line: location?.line ?? null,
            column: location?.column ?? null,
            param: location?.param || null
        },
        evidence: {
            requestSnippet: "",
            responseSnippet: "",
            codeSnippet: "",
            notes: "",
            evidenceFullAvailable: false
        },
        references,
        cwe: Array.isArray(finding?.cwe) ? finding.cwe : (finding?.cwe ? [finding.cwe] : []),
        owasp: resolveOwaspList(finding)
    }

    if (engine === "DAST") {
        const { requestRecord, attackRecord } = resolveDastAttackContext(finding, viewModel)
        const requestRaw = attackRecord?.request?.raw
            || requestRecord?.original?.request?.raw
            || (attackRecord?.request ? buildRawRequest(attackRecord.request) : "")
            || (requestRecord?.original?.request ? buildRawRequest(requestRecord.original.request) : "")
        const responseRaw = attackRecord?.response?.raw
            || (attackRecord?.response ? buildRawResponse(attackRecord.response) : "")
            || (requestRecord?.original?.response ? buildRawResponse(requestRecord.original.response) : "")
        const proof = attackRecord?.proof || finding?.evidence?.dast?.proof || ""
        const meta = attackRecord?.metadata || finding?.metadata || {}
        exportFinding.evidence.requestSnippet = truncateSnippet(requestRaw)
        exportFinding.evidence.responseSnippet = truncateSnippet(responseRaw)
        exportFinding.evidence.notes = truncateSnippet(proof)
        exportFinding.evidence.evidenceFullAvailable = !!(requestRaw || responseRaw)
        if (!exportFinding.description) {
            exportFinding.description = meta.description || ""
        }
        if (!exportFinding.recommendation) {
            exportFinding.recommendation = meta.recommendation || ""
        }
        if (!exportFinding.references.length && meta.links) {
            exportFinding.references = buildReferenceList(meta.links)
        }
        if (meta.owasp) {
            const metaOwasp = normalizeOwaspEntries(meta.owasp)
            const hasVersioned = metaOwasp.some(entry => /\d{4}/.test(entry))
            if (metaOwasp.length && (hasVersioned || !exportFinding.owasp.length)) {
                exportFinding.owasp = metaOwasp
            }
        }
        if (!exportFinding.cwe.length && meta.cwe) {
            exportFinding.cwe = normalizeCweEntries(meta.cwe)
        }
    } else if (engine === "SAST") {
        const codeSnippet = finding?.evidence?.sast?.codeSnippet || ""
        exportFinding.evidence.codeSnippet = truncateSnippet(codeSnippet)
        exportFinding.evidence.notes = truncateSnippet(finding?.evidence?.sast?.nodeType || "")
        exportFinding.evidence.trace = normalizeTraceForExport(finding?.evidence?.sast?.trace || "")
        exportFinding.evidence.source = normalizeEndpointDetails(finding?.evidence?.sast?.source || null)
        exportFinding.evidence.sink = normalizeEndpointDetails(finding?.evidence?.sast?.sink || null)
        exportFinding.evidence.evidenceFullAvailable = !!(finding?.evidence?.sast?.trace || codeSnippet)
    } else if (engine === "IAST") {
        const iastEvidence = finding?.evidence?.iast || {}
        const context = iastEvidence?.context || {}
        const iastSnippet = context?.valuePreview || context?.location || ""
        exportFinding.evidence.codeSnippet = truncateSnippet(iastSnippet)
        const message = iastEvidence?.message || iastEvidence?.flowSummary || ""
        exportFinding.evidence.notes = truncateSnippet(message)
        exportFinding.evidence.proof = truncateSnippet(resolveIastProof(iastEvidence, context))
        exportFinding.evidence.flow = normalizeIastFlowForExport(iastEvidence?.flow || context?.flow || "")
        exportFinding.evidence.trace = normalizeTraceForExport(iastEvidence?.trace || "")
        exportFinding.evidence.source = iastEvidence?.taintSource || iastEvidence?.sourceId || ""
        exportFinding.evidence.sink = iastEvidence?.sinkId || ""
        exportFinding.evidence.url = iastEvidence?.routing?.runtimeUrl || iastEvidence?.routing?.url || finding?.location?.url || ""
        exportFinding.evidence.category = finding?.category || ""
        exportFinding.evidence.evidenceFullAvailable = !!(iastEvidence?.trace || iastSnippet)
    }

    return exportFinding
}

function buildExportFindingFromSca(entry) {
    const component = entry?.component || {}
    const finding = entry?.finding || {}
    const componentName = component.component || component.name || component.library || component.package || component.module || "Unknown component"
    const componentVersion = component.version || component.pkgVersion || component.release || component.componentVersion || component.libraryVersion || component.packageVersion || ""
    const description = finding.description || finding?.identifiers?.description || ""
    const recommendation = finding.recommendation || finding?.identifiers?.recommendation || ""
    const references = normalizeScaList(finding?.info || finding?.references || finding?.urls)
        .map(url => ({ title: null, url }))
        .filter(entry => entry.url)
    return {
        engine: "SCA",
        severity: normalizeExportSeverity(finding?.severity),
        confidence: 85,
        title: `${componentName} - ${finding?.identifiers?.summary || finding?.summary || "Vulnerability"}`,
        componentName,
        componentVersion,
        description,
        location: {
            file: component.file || component.path || component.location || null
        },
        evidence: {
            requestSnippet: "",
            responseSnippet: "",
            codeSnippet: truncateSnippet(description || recommendation),
            notes: truncateSnippet(recommendation),
            evidenceFullAvailable: !!(description || recommendation)
        },
        references,
        cwe: Array.isArray(finding?.cwe) ? finding.cwe : (finding?.cwe ? [finding.cwe] : []),
        owasp: []
    }
}

function toMarkdownTable(headers, rows) {
    const headerLine = `| ${headers.map(escapeMarkdownCell).join(" | ")} |`
    const sepLine = `| ${headers.map(() => "---").join(" | ")} |`
    const bodyLines = rows.map(row => `| ${row.map(escapeMarkdownCell).join(" | ")} |`)
    return [headerLine, sepLine, ...bodyLines].join("\n")
}

function buildMarkdownFromExportModel(model) {
    const lines = []
    const push = (line = "") => lines.push(line)
    const host = model.meta.host || "unknown"
    const reportType = model.meta.reportType || "report"
    const generatedAt = model.meta.generatedAt || new Date().toISOString()
    const isExecutive = model.meta.preset === "executive"

    push(`# cert-x Security Report`)
    push(``)
    push(`- Host: ${escapeMarkdownText(host)}`)
    push(`- Report type: ${escapeMarkdownText(reportType)}`)
    push(`- Generated: ${escapeMarkdownText(generatedAt)}`)
    push(``)
    const runCoverage = runCoverageMarkdown(model.certXRun)
    if (runCoverage) push(runCoverage)

    // Summary section (both presets)
    if (Object.keys(model.summary.byEngine || {}).length) {
        push(`## Summary`)
        push(``)
        push(`### Risk Ratings`)
        const severityRows = Object.entries(model.summary.bySeverity || {})
            .map(([severity, count]) => [severity, count])
        if (severityRows.length) {
            push(toMarkdownTable(["Severity", "Count"], severityRows))
            push(``)
        }
        push(`### Findings by Engine`)
        const engineRows = Object.entries(model.summary.byEngine).map(([engine, count]) => [engine, count])
        if (engineRows.length) {
            push(toMarkdownTable(["Engine", "Count"], engineRows))
            push(``)
        }

        // Exposure & Hygiene in Summary
        push(`### Exposure & Hygiene`)
        const headerHighlights = (model.dashboard.owaspHeaders || []).slice(0, 3)
        const headersText = headerHighlights.length
            ? headerHighlights.join("; ")
            : "No header issues detected or data unavailable."
        const storageDetails = model.dashboard.storageDetails || { localStorage: [], sessionStorage: [] }
        const tokenInStorage = [...(storageDetails.localStorage || []), ...(storageDetails.sessionStorage || [])]
            .some(entry => STORAGE_TOKEN_KEY_REGEX.test(String(entry.key)))
        const cookieFlagsMissing = (model.dashboard.cookies || []).some(item => item?.httpOnly === false)
        push(`- **Headers:** ${escapeMarkdownText(headersText)}`)
        push(`- **Token/storage:** ${escapeMarkdownText(model.dashboard.assessed !== true ? 'Not assessed in this report.' : `Tokens in storage: ${tokenInStorage ? "Yes" : "No"}; Cookie HttpOnly missing: ${cookieFlagsMissing ? "Yes" : "No"}`)}`)
        const scaTop = (model.sections?.sca || []).slice(0, 3).map(item => {
            const fix = item.recommendation ? truncateSnippet(item.recommendation, 80) : "Upgrade to a secure version."
            return `${item.title} (${item.severity}) - ${fix}`
        })
        const scaLine = scaTop.length ? scaTop.join("; ") : "No high-risk dependencies identified or data unavailable."
        push(`- **Dependencies:** ${escapeMarkdownText(scaLine)}`)
        push(``)

        // Remediation Plan in Summary
        push(`### Remediation Plan`)
        const sev = model.summary.bySeverity || {}
        push(toMarkdownTable(["Bucket", "Items"], [
            ["Fix now (0–7 days)", (sev.critical || 0) + (sev.high || 0)],
            ["Fix soon (7–30 days)", sev.medium || 0],
            ["Backlog", (sev.low || 0) + (sev.info || 0)]
        ]))
        push(``)
    }

    if (isExecutive) {
        // Executive format: Top 5 Highest Risks, Correlated, then engine sections
        const topLabel = buildTopRisksLabel(model.summary?.bySeverity || {})
        const severityCounts = model.summary?.bySeverity || {}
        const topPool = severityCounts.critical > 0
            ? model.findings.filter(item => normalizeSeverityKey(item?.severity) === "critical")
            : model.findings
        const topGrouped = groupFindingsForExec(topPool, {
            keyFn: item => item.title || item.findingId || "finding",
            maxItems: 5
        })

        if (topGrouped.length) {
            push(`## ${topLabel}`)
            push(``)
            // Render each finding as a card-like block (matching HTML layout)
            topGrouped.forEach(entry => {
                const item = entry.item
                const occ = entry.count > 1 ? ` (${entry.count} occurrences)` : ""
                const owner = inferOwnerHint(item)
                const mapping = renderMappingSectionMarkdown(item.cwe, resolveOwaspList(item))
                const refs = buildReferenceSummary(item)
                const asset = formatAssetForOverview(item.location)
                const severityKey = normalizeSeverityKey(item.severity)

                push(`### ${escapeMarkdownText(item.title)}${occ}`)
                push(`${escapeMarkdownText(item.engine || "DAST")} • ${escapeMarkdownText(asset)}`)
                push(``)
                push(`**${severityKey.toUpperCase()}** | Owner: ${escapeMarkdownText(owner)}`)
                push(``)
                const cweList = Array.isArray(item.cwe) ? item.cwe : (item.cwe ? [item.cwe] : [])
                const owaspList = resolveOwaspList(item)
                if (cweList.length) {
                    push(`**CWE:**`)
                    push(escapeMarkdownText(cweList.join(", ")))
                    push(``)
                }
                if (owaspList.length) {
                    push(`**OWASP:**`)
                    push(escapeMarkdownText(owaspList.join(", ")))
                    push(``)
                }
                if (item.references?.length) {
                    push(`**References:**`)
                    item.references.slice(0, 5).forEach(ref => {
                        const refUrl = ref?.url || ref
                        if (refUrl) push(escapeMarkdownText(refUrl))
                    })
                    push(``)
                }
                push(``)
                push(`---`)
                push(``)
            })
        }

        // Engine Top Findings (executive format) - card-like blocks matching HTML
        const engineSections = [
            { id: "dast", label: "DAST" },
            { id: "iast", label: "IAST" },
            { id: "sast", label: "SAST" },
            { id: "sca", label: "SCA" }
        ]
        engineSections.forEach(section => {
            const findings = model.sections?.[section.id] || []
            if (!findings.length) return
            const grouped = groupFindingsForExec(findings, {
                keyFn: section.id === "sca"
                    ? normalizeScaKey
                    : (item) => item.title || item.findingId || "finding"
            })
            push(`## ${section.label} Top Findings`)
            push(``)

            // Render each finding as a card-like block
            grouped.forEach(entry => {
                const item = entry.item
                const occ = entry.count > 1 ? ` - ${entry.count} occurrences` : ""
                const asset = formatAssetForOverview(item.location)
                const severityKey = normalizeSeverityKey(item.severity)
                const description = item.description ? stripHtmlToText(item.description) : ""
                const fix = item.recommendation ? stripHtmlToText(item.recommendation) : inferFix(item)

                push(`### ${escapeMarkdownText(item.title)}${occ}`)
                push(`${escapeMarkdownText(asset)}`)
                push(``)
                push(`**${severityKey.toUpperCase()}**`)
                push(``)

                // Description (for DAST/IAST/SAST, not SCA)
                if (description && section.id !== "sca") {
                    push(`**Description:**`)
                    push(escapeMarkdownText(description))
                    push(``)
                }

                // Fix/Recommendation
                if (fix) {
                    push(`**Recommendation:**`)
                    push(escapeMarkdownText(fix))
                    push(``)
                }

                // CWE (separate from OWASP)
                const cweList = Array.isArray(item.cwe) ? item.cwe : (item.cwe ? [item.cwe] : [])
                if (cweList.length) {
                    push(`**CWE:**`)
                    push(escapeMarkdownText(cweList.join(", ")))
                    push(``)
                }

                // OWASP (separate from CWE)
                const owaspList = resolveOwaspList(item)
                if (owaspList.length) {
                    push(`**OWASP:**`)
                    push(escapeMarkdownText(owaspList.join(", ")))
                    push(``)
                }

                // References (each on separate line)
                const refsList = (item.references || []).map(ref => ref?.url || ref).filter(Boolean)
                if (refsList.length) {
                    push(`**References:**`)
                    refsList.forEach(refUrl => {
                        push(escapeMarkdownText(refUrl))
                    })
                    push(``)
                }
                push(`---`)
                push(``)
            })
        })

        // Methodology & Scope (footer)
        push(``)
        push(`Report generated using cert-x scanning engines. Executive preset includes top findings only and excludes sensitive evidence by default. Results depend on scan coverage and target responsiveness.`)
        const scopeText = model.meta.context?.scopeSummary && model.meta.context?.scopeSummary !== "N/A"
            ? model.meta.context.scopeSummary
            : "N/A"
        push(`**Scope:** ${escapeMarkdownText(scopeText)}`)
        push(`**Limitations:** Results depend on available routes and auth context; some flows may not be covered.`)
        push(``)

    } else {
        // Technical format aligned with HTML sections
        push(`## General Information`)
        push(``)
        if (model.dashboard.technologies.length) {
            push(`### Technology Stack`)
            const rows = model.dashboard.technologies.map(item => [item.name, item.version, item.category])
            push(toMarkdownTable(["Name", "Version", "Category"], rows))
            push(``)
        }

        if (model.dashboard.owaspHeaders.length) {
            push(`### OWASP Secure Headers`)
            const rows = model.dashboard.owaspHeaders.map(item => [item])
            push(toMarkdownTable(["Header"], rows))
            push(``)
        }

        if (model.dashboard.cves.length) {
            push(`### CVE Lookup`)
            const rows = model.dashboard.cves.map(item => [item.id, item.severity, item.evidence, item.verify])
            push(toMarkdownTable(["CVE", "Severity", "Evidence", "Verify"], rows))
            push(``)
        }

        if (model.dashboard.headers.length) {
            push(`### Request Headers`)
            const rows = model.dashboard.headers.map(item => [item.name, item.value])
            push(toMarkdownTable(["Header", "Value"], rows))
            push(``)
        }

        if (model.dashboard.cookies.length) {
            push(`### Cookies`)
            const rows = model.dashboard.cookies.map(item => [item.domain, item.name, item.value, String(item.httpOnly)])
            push(toMarkdownTable(["Domain", "Name", "Value", "HttpOnly"], rows))
            push(``)
        }

        const storageDetails = model.dashboard.storageDetails || { localStorage: [], sessionStorage: [] }
        if (storageDetails.localStorage.length) {
            push(`### Local Storage`)
            const rows = storageDetails.localStorage.map(item => [item.key, truncateSnippet(item.value, 400)])
            push(toMarkdownTable(["Key", "Value"], rows))
            push(``)
        }
        if (storageDetails.sessionStorage.length) {
            push(`### Session Storage`)
            const rows = storageDetails.sessionStorage.map(item => [item.key, truncateSnippet(item.value, 400)])
            push(toMarkdownTable(["Key", "Value"], rows))
            push(``)
        }
        if (model.dashboard.storage.length && !storageDetails.localStorage.length && !storageDetails.sessionStorage.length) {
            push(`### Storage`)
            const rows = model.dashboard.storage.map(item => [item.type, item.entriesCount])
            push(toMarkdownTable(["Storage", "Entries"], rows))
            push(``)
        }


        const sections = [
            { id: "dast", label: "DAST" },
            { id: "iast", label: "IAST" },
            { id: "sast", label: "SAST" },
            { id: "sca", label: "SCA" }
        ]
        sections.forEach(section => {
            const findings = model.sections?.[section.id] || []
            if (!findings.length) return
            push(`## ${section.label}`)
            push(``)

            // Render each finding as a card-like block (similar to executive report)
            findings.forEach(item => {
                const severityKey = normalizeSeverityKey(item.severity)
                const confidence = item.confidence != null ? ` | Confidence: ${Math.round(item.confidence)}` : ""
                const location = formatLocationSummary(item.location)
                const description = item.description ? stripHtmlToText(item.description) : ""
                const fix = item.recommendation ? stripHtmlToText(item.recommendation) : ""
                const evidence = item.evidence || {}

                push(`### ${escapeMarkdownText(item.findingId || section.label)} - ${escapeMarkdownText(item.title)}`)
                if (location) {
                    push(`${escapeMarkdownText(location)}`)
                }
                push(``)
                push(`**${severityKey.toUpperCase()}**${confidence}`)
                push(``)

                const renderOtherInfo = () => {
                    if (description && section.id !== "sca") {
                        push(`**Description:**`)
                        push(escapeMarkdownText(truncateSnippet(description, 1200)))
                        push(``)
                    }
                    if (fix) {
                        push(`**Recommendation:**`)
                        push(escapeMarkdownText(truncateSnippet(fix, 800)))
                        push(``)
                    }
                    if (item.cwe?.length) {
                        push(`**CWE:**`)
                        push(escapeMarkdownText(item.cwe.join(", ")))
                        push(``)
                    }
                    if (item.owasp?.length) {
                        const owaspLabel = item.owasp.map(entry => (typeof entry === "string" ? entry : entry?.name || entry?.id || "")).filter(Boolean).join(", ")
                        if (owaspLabel) {
                            push(`**OWASP:**`)
                            push(escapeMarkdownText(owaspLabel))
                            push(``)
                        }
                    }
                    if (item.references?.length) {
                        push(`**References:**`)
                        item.references.slice(0, 5).forEach(ref => {
                            const refUrl = ref?.url || ref
                            if (refUrl) push(refUrl)
                        })
                        push(``)
                    }
                }

                // Evidence section based on engine type
            if (section.id === "dast") {
                // DAST: Request, Response, Proof
                if (evidence.requestSnippet) {
                    push(`**Request:**`)
                    push("```")
                    push(escapeMarkdownText(truncateSnippet(evidence.requestSnippet, 2000)))
                    push("```")
                    push(``)
                }
                if (evidence.responseSnippet) {
                    push(`**Response:**`)
                    push("```")
                    push(escapeMarkdownText(truncateSnippet(evidence.responseSnippet, 2000)))
                    push("```")
                    push(``)
                }
                if (evidence.notes) {
                    push(`**Proof:**`)
                    push(escapeMarkdownText(evidence.notes))
                    push(``)
                }
                    // DAST order matches HTML: evidence first, then other information
                    renderOtherInfo()
                } else if (section.id === "iast") {
                    // IAST order matches HTML: meta, context, flow, trace, other information
                    const iastMetaLines = []
                    if (evidence.source) iastMetaLines.push(`- Source: ${escapeMarkdownText(evidence.source)}`)
                    if (evidence.sink) iastMetaLines.push(`- Sink: ${escapeMarkdownText(evidence.sink)}`)
                    if (evidence.category) iastMetaLines.push(`- Category: ${escapeMarkdownText(evidence.category)}`)
                    if (evidence.url) iastMetaLines.push(`- URL: ${escapeMarkdownText(evidence.url)}`)
                    if (iastMetaLines.length) {
                        push(`**Meta:**`)
                        iastMetaLines.forEach(line => push(line))
                        push(``)
                    }

                    // IAST: Context/Value, Flow, Trace
                if (evidence.codeSnippet) {
                    push(`**Context / Value:**`)
                    push("```")
                    push(escapeMarkdownText(truncateSnippet(evidence.codeSnippet, 1500)))
                    push("```")
                    push(``)
                }
                if (evidence.flow) {
                    push(`**Flow:**`)
                    push("```")
                    push(escapeMarkdownText(truncateSnippet(evidence.flow, 2000)))
                    push("```")
                    push(``)
                } else if (evidence.notes) {
                    push(`**Flow:**`)
                    push(escapeMarkdownText(evidence.notes))
                        push(``)
                    }
                if (evidence.trace) {
                    push(`**Trace:**`)
                    push("```")
                    push(escapeMarkdownText(truncateSnippet(evidence.trace, 2000)))
                    push("```")
                    push(``)
                }
                    if (evidence.proof) {
                        push(`**Proof:**`)
                        push(escapeMarkdownText(evidence.proof))
                        push(``)
                    }
                    renderOtherInfo()
                } else if (section.id === "sast") {
                    // SAST order matches HTML: source/sink, trace, other information
                    const source = evidence.source || null
                    const sink = evidence.sink || null
                    if (source || sink) {
                        push(`**Source / Sink:**`)
                        if (source) {
                            const loc = formatLocationRange(source.location)
                            const parts = [
                                source.name ? `Name: ${escapeMarkdownText(source.name)}` : "",
                                source.file ? `File: ${escapeMarkdownText(source.file)}` : "",
                                loc ? `Location: ${escapeMarkdownText(loc)}` : ""
                            ].filter(Boolean).join("; ")
                            if (parts) push(`- Source: ${parts}`)
                        }
                        if (sink) {
                            const loc = formatLocationRange(sink.location)
                            const parts = [
                                sink.name ? `Name: ${escapeMarkdownText(sink.name)}` : "",
                                sink.file ? `File: ${escapeMarkdownText(sink.file)}` : "",
                                loc ? `Location: ${escapeMarkdownText(loc)}` : ""
                            ].filter(Boolean).join("; ")
                            if (parts) push(`- Sink: ${parts}`)
                        }
                        push(``)
                    }

                    if (evidence.trace) {
                        const traceEntries = formatTraceEntriesForExport(evidence.trace)
                        if (traceEntries.length) {
                            push(`**Taint Trace:**`)
                            traceEntries.forEach(entry => {
                                const stage = entry.stage ? entry.stage.toUpperCase() : "STEP"
                                const details = []
                                if (entry.label) details.push(`Label: ${escapeMarkdownText(entry.label)}`)
                                if (entry.file) details.push(`File: ${escapeMarkdownText(entry.file)}`)
                                if (entry.loc) details.push(`Location: ${escapeMarkdownText(entry.loc)}`)
                                const detailHtml = details.length ? `<br>${details.join("<br>")}` : ""
                                push(`1. <small><strong>${escapeMarkdownText(stage)}</strong>${detailHtml}</small>`)
                                push(``)
                            })
                        }
                    }
                    // SAST: Source Code, Node Type
                if (evidence.codeSnippet) {
                    push(`**Source Code:**`)
                    push("```")
                    push(escapeMarkdownText(truncateSnippet(evidence.codeSnippet, 1500)))
                    push("```")
                    push(``)
                }
                    if (evidence.notes) {
                        push(`**Node Type:** ${evidence.notes}`)
                        push(``)
                    }
                    renderOtherInfo()
                } else if (section.id === "sca") {
                    renderOtherInfo()
                    // SCA: Component info
                    if (item.componentName) {
                        push(`**Component:** ${item.componentName}${item.componentVersion ? ` @ ${item.componentVersion}` : ""}`)
                        push(``)
                    }
                }

                push(`---`)
                push(``)
            })
        })

        ;[['sast', 'SAST Discovery'], ['dast', 'DAST Reconnaissance']].forEach(([engine, heading]) => {
        const discoveryItems = Array.isArray(model.discoveries?.[engine]) ? model.discoveries[engine] : []
        if (discoveryItems.length) {
            push(`## ${heading}`)
            push(``)
            discoveryItems.forEach(item => {
                push(`### ${escapeMarkdownText(item.title || "Discovery")}`)
                if (item.file || item.location) {
                    const locationLabel = [
                        item.file ? `File: ${escapeMarkdownText(item.file)}` : "",
                        item.location ? `Location: ${escapeMarkdownText(engine === 'dast' ? item.location.url || '' : formatRange(item.location))}` : ""
                    ].filter(Boolean).join(" | ")
                    if (locationLabel) {
                        push(locationLabel)
                        push(``)
                    }
                }
                if (item.summary) {
                    push(escapeMarkdownText(item.summary))
                    push(``)
                }
                const detailItems = Array.isArray(item.details) ? item.details.filter(Boolean) : []
                if (detailItems.length) {
                    push(`**Details:**`)
                    detailItems.forEach(detail => {
                        push(`- ${escapeMarkdownText(detail)}`)
                    })
                    push(``)
                }
                push(`---`)
                push(``)
            })
        }
        })

        // Methodology & Scope for technical reports too (footer)
        push(``)
        push(`Report generated using cert-x scanning engines. Results depend on scan coverage and target responsiveness.`)
        const scopeText = model.meta.context?.scopeSummary && model.meta.context?.scopeSummary !== "N/A"
            ? model.meta.context.scopeSummary
            : "N/A"
        push(`**Scope:** ${escapeMarkdownText(scopeText)}`)
        push(`**Limitations:** Results depend on available routes and auth context; some flows may not be covered.`)
        push(``)
    }

    return lines.join("\n")
}

function getJsPdfCtor() {
    const root = window.jspdf
    const Ctor = root && root.jsPDF
    if (!Ctor) {
        throw new Error("jsPDF UMD not loaded: expected window.jspdf.jsPDF")
    }
    return Ctor
}

function buildPdfFromExportModel(model) {
    const JsPDF = getJsPdfCtor()
    const doc = new JsPDF({ unit: "pt", format: "a4" })
    const layout = createPdfLayout(doc, model.meta, pdfTheme)
    const margin = layout.margin
    let cursorY = layout.contentTop

    const ensureSpace = (height = 20) => {
        if (cursorY + height > layout.contentBottom) {
            doc.addPage()
            cursorY = layout.contentTop
        }
    }

    const addSectionTitle = (title) => {
        cursorY += pdfTheme.spacing.md
        ensureSpace(80)
        cursorY = layout.drawSectionTitle(title, cursorY)
        cursorY += pdfTheme.spacing.xs
    }

    const addSubsectionTitle = (title) => {
        ensureSpace(18)
        setBody(doc, pdfTheme)
        doc.setFont("helvetica", "bold")
        doc.text(title, margin, cursorY)
        cursorY += pdfTheme.spacing.sm
    }

    const addAutoTable = (options) => {
        const tableDefaults = pdfTheme.tables.technical
        doc.autoTable({
            ...tableDefaults,
            ...options,
            startY: cursorY,
            margin: { left: margin, right: margin },
            styles: { ...tableDefaults.styles, ...(options.styles || {}) },
            headStyles: { ...tableDefaults.headStyles, ...(options.headStyles || {}) },
            alternateRowStyles: { ...(tableDefaults.alternateRowStyles || {}), ...(options.alternateRowStyles || {}) }
        })
        cursorY = doc.lastAutoTable.finalY + pdfTheme.spacing.lg
    }

    const drawFindingHeader = (title, severity, { confirmed = true } = {}) => {
        ensureSpace(40)
        const safeTitle = clampCellText(title, { maxChars: 90, maxLines: 1 })
        const severityKey = normalizeSeverityKey(severity || "info")
        const headerHeight = 20
        // Draw flag icon colored by severity (like reference PDF)
        drawFlagIcon(doc, { x: margin, y: cursorY, severity: severityKey, size: 14 })
        // Draw title in teal/blue color like reference PDF
        setH2(doc, pdfTheme)
        doc.setTextColor(0, 128, 128) // Teal color for title
        doc.text(safeTitle, margin + 20, cursorY + 10)
        doc.setTextColor(0)
        // Draw CONFIRMED badge on right (like reference PDF)
        const badgeX = layout.pageWidth - margin - 80
        if (confirmed) {
            drawBadge(doc, "CONFIRMED", { x: badgeX, y: cursorY - 2, fill: [46, 125, 50] })
        } else {
            drawBadge(doc, "UNCONFIRMED", { x: badgeX - 10, y: cursorY - 2, fill: [158, 158, 158], textColor: [255, 255, 255] })
        }
        cursorY += headerHeight + pdfTheme.spacing.sm
    }

    cursorY = layout.drawHeaderBlock({
        title: "cert-x Security Report",
        subtitle: "Website Vulnerability Scanner Report",
        logoDataUrl: model.meta.logoDataUrl
    })
    cursorY = drawHostBanner(doc, {
        x: margin,
        y: cursorY,
        width: layout.pageWidth - margin * 2,
        text: model.meta.host || "unknown"
    })
    cursorY = drawRunCoverage(doc, layout, model.certXRun, cursorY)

    const tiers = { confirmed: 0, likely: 0, potential: model.findings.length, confirmedHigh: 0 }

    if (Object.keys(model.summary.byEngine || {}).length) {
        addSectionTitle("Summary")
        const riskEndY = drawRiskBarList(doc, {
            x: margin,
            y: cursorY,
            counts: model.summary.bySeverity || {},
            barMaxWidth: 180
        })
        cursorY = riskEndY + pdfTheme.spacing.sm
        const rows = buildSummaryTableRows(model, { interactive: false })
        if (rows.length) {
            addAutoTable({
                head: [["Engine", "Critical", "High", "Medium", "Low", "Info", "Total"]],
                body: rows.map(row => row.cells),
                columnStyles: { 0: { cellWidth: 70 } }
            })
        }

        const conclusion = buildExecutiveConclusion(model, tiers)
        const conclusionLines = doc.splitTextToSize(conclusion, layout.pageWidth - margin * 2)
        setBody(doc, pdfTheme)
        doc.text(conclusionLines, margin, cursorY)
        cursorY += conclusionLines.length * 12 + 6

        // Exposure & Hygiene
        ensureSpace(80)
        setBody(doc, pdfTheme)
        doc.setFont("helvetica", "bold")
        doc.text("Exposure & Hygiene:", margin, cursorY)
        cursorY += 14
        doc.setFont("helvetica", "normal")
        const headerHighlights = (model.dashboard.owaspHeaders || []).slice(0, 3)
        const headersText = headerHighlights.length
            ? headerHighlights.join("; ")
            : "No header issues detected or data unavailable."
        const storageDetails = model.dashboard.storageDetails || { localStorage: [], sessionStorage: [] }
        const tokenInStorage = [...(storageDetails.localStorage || []), ...(storageDetails.sessionStorage || [])]
            .some(entry => STORAGE_TOKEN_KEY_REGEX.test(String(entry.key)))
        const cookieFlagsMissing = (model.dashboard.cookies || []).some(item => item?.httpOnly === false)
        const tokenLine = model.dashboard.assessed !== true ? 'Not assessed in this report.' : `Tokens in storage: ${tokenInStorage ? "Yes" : "No"}; Cookie HttpOnly missing: ${cookieFlagsMissing ? "Yes" : "No"}`
        const scaTopSummary = (model.sections?.sca || []).slice(0, 3).map(item => {
            const fix = item.recommendation ? truncateSnippet(item.recommendation, 80) : "Upgrade to a secure version."
            return `${item.title} (${item.severity}) - ${fix}`
        })
        const scaLineSummary = scaTopSummary.length ? scaTopSummary.join("; ") : "No high-risk dependencies identified or data unavailable."
        const exposureLines = [
            `Headers: ${headersText}`,
            `Token/storage: ${tokenLine}`,
            `Dependencies: ${scaLineSummary}`
        ]
        exposureLines.forEach(line => {
            const lines = doc.splitTextToSize(line, layout.pageWidth - margin * 2)
            doc.text(lines, margin, cursorY)
            cursorY += lines.length * 12 + 2
        })
        cursorY += pdfTheme.spacing.xs

        // Remediation Plan
        ensureSpace(60)
        doc.setFont("helvetica", "bold")
        doc.text("Remediation Plan:", margin, cursorY)
        cursorY += 14
        doc.setFont("helvetica", "normal")
        const sevCounts = model.summary.bySeverity || {}
        addAutoTable({
            head: [["Bucket", "Items"]],
            body: [
                ["Fix now (0–7 days)", String((sevCounts.critical || 0) + (sevCounts.high || 0))],
                ["Fix soon (7–30 days)", String(sevCounts.medium || 0)],
                ["Backlog", String((sevCounts.low || 0) + (sevCounts.info || 0))]
            ],
            columnStyles: { 0: { cellWidth: 180 } }
        })
    }

    if (["technologies","owaspHeaders","cves","headers","cookies","storage","tokens"].some(key => model.dashboard[key]?.length)) addSectionTitle("General Information")
    if (model.dashboard.technologies.length) {
        addSubsectionTitle("Technology Stack")
        const rows = model.dashboard.technologies.map(item => [item.name, item.version, item.category])
        addAutoTable({ head: [["Name", "Version", "Category"]], body: rows })
    }

    if (model.dashboard.owaspHeaders.length) {
        addSubsectionTitle("OWASP Secure Headers")
        const rows = model.dashboard.owaspHeaders.map(item => [item])
        addAutoTable({ head: [["Header"]], body: rows })
    }

    if (model.dashboard.cves.length) {
        addSubsectionTitle("CVE Lookup")
        const rows = model.dashboard.cves.map(item => [item.id, item.severity, item.evidence, item.verify])
        addAutoTable({ head: [["CVE", "Severity", "Evidence", "Verify"]], body: rows })
    }

    if (model.dashboard.headers.length) {
        addSubsectionTitle("Request Headers")
        const rows = model.dashboard.headers.map(item => [item.name, item.value])
        addAutoTable({ head: [["Header", "Value"]], body: rows })
    }

    const storageDetails = model.dashboard.storageDetails || { localStorage: [], sessionStorage: [] }
    const tokensTable = model.dashboard.tokens || []
    if (model.dashboard.cookies.length) {
        addSubsectionTitle("Cookies")
        const rows = model.dashboard.cookies.map(item => [item.domain, item.name, item.value, String(item.httpOnly)])
        addAutoTable({ head: [["Domain", "Name", "Value", "HttpOnly"]], body: rows })
    }
    if (storageDetails.localStorage.length) {
        addSubsectionTitle("Local Storage")
        const rows = storageDetails.localStorage.map(item => [item.key, truncateSnippet(item.value, 400)])
        addAutoTable({
            head: [["Key", "Value"]],
            body: rows,
            styles: { overflow: "linebreak", cellWidth: "wrap" },
            columnStyles: { 0: { cellWidth: 120 }, 1: { cellWidth: 360 } }
        })
    }
    if (storageDetails.sessionStorage.length) {
        addSubsectionTitle("Session Storage")
        const rows = storageDetails.sessionStorage.map(item => [item.key, truncateSnippet(item.value, 400)])
        addAutoTable({
            head: [["Key", "Value"]],
            body: rows,
            styles: { overflow: "linebreak", cellWidth: "wrap" },
            columnStyles: { 0: { cellWidth: 120 }, 1: { cellWidth: 360 } }
        })
    }
    if (!storageDetails.localStorage.length && !storageDetails.sessionStorage.length && model.dashboard.storage.length) {
        addSubsectionTitle("Storage")
        const rows = model.dashboard.storage.map(item => [item.type, String(item.entriesCount)])
        addAutoTable({ head: [["Storage", "Entries"]], body: rows })
    }
    if (tokensTable.length) {
        addSubsectionTitle("Tokens")
        const rows = tokensTable.map(item => [
            item.source,
            truncateSnippet(item.token, 200),
            truncateSnippet(item.payload, 400)
        ])
        addAutoTable({
            head: [["Source", "Token", "Payload"]],
            body: rows,
            styles: { overflow: "linebreak", cellWidth: "wrap" },
            columnStyles: { 0: { cellWidth: 80 }, 1: { cellWidth: 200 }, 2: { cellWidth: 200 } }
        })
        if (model.dashboard.tokenPayloadNote) {
            setBody(doc, pdfTheme)
            doc.text(model.dashboard.tokenPayloadNote, margin, cursorY)
            cursorY += pdfTheme.spacing.sm
        }
    }

    const sortBySeverity = (a, b) => severityRank(a?.severity) - severityRank(b?.severity)
    const sections = [
        { id: "dast", label: "DAST" },
        { id: "iast", label: "IAST" },
        { id: "sast", label: "SAST" },
        { id: "sca", label: "SCA" }
    ]

    // Helper to render a code block in PDF
    const drawCodeBlock = (label, content) => {
        if (!content) return
        const text = truncateSnippet(content, 2000)
        const codeLines = doc.splitTextToSize(text, layout.pageWidth - margin * 2)
        const lineHeight = 9

        let remaining = codeLines.slice()

        while (remaining.length) {
            ensureSpace(60)
            setBody(doc, pdfTheme)
            doc.setFont("helvetica", "bold")
            doc.setFontSize(9)
            doc.setTextColor(0, 0, 0)
            const title = `${label}:`
            doc.text(title, margin, cursorY)
            cursorY += 12

            doc.setFont("courier", "normal")
            doc.setFontSize(8)
            doc.setTextColor(60, 60, 60)

            const availableHeight = layout.contentBottom - cursorY
            const maxLines = Math.max(1, Math.floor(availableHeight / lineHeight) - 1)
            const slice = remaining.slice(0, maxLines)
            doc.text(slice, margin, cursorY)
            cursorY += slice.length * lineHeight + 6
            remaining = remaining.slice(maxLines)

            doc.setTextColor(0)
            if (remaining.length) {
                doc.addPage()
                cursorY = layout.contentTop
            }
        }
    }

    const drawOtherInformationBlock = (item, sectionId) => {
        const description = item.description ? stripHtmlToText(item.description) : ""
        const fix = item.recommendation ? stripHtmlToText(item.recommendation) : ""
        const owaspLabel = (item.owasp || [])
            .map(entry => (typeof entry === "string" ? entry : entry?.name || entry?.id || ""))
            .filter(Boolean)
            .join(", ")
        const refsList = (item.references || [])
            .map(ref => ref?.url || ref)
            .filter(Boolean)
            .slice(0, 5)

        const hasContent = (description && sectionId !== "sca")
            || fix
            || (item.cwe?.length)
            || owaspLabel
            || refsList.length
        if (!hasContent) return

        const renderLabelValue = (label, value) => {
            if (!value) return
            ensureSpace(30)
            setBody(doc, pdfTheme)
            doc.setFont("helvetica", "bold")
            doc.setFontSize(9)
            doc.text(`${label}:`, margin, cursorY)
            cursorY += 12
            doc.setFont("helvetica", "normal")
            doc.setTextColor(80, 80, 80)
            const lines = doc.splitTextToSize(String(value), layout.pageWidth - margin * 2)
            doc.text(lines, margin, cursorY)
            cursorY += lines.length * 10 + 6
            doc.setTextColor(0)
        }

        if (description && sectionId !== "sca") {
            renderLabelValue("Description", truncateSnippet(description, 1200))
        }
        if (fix) {
            renderLabelValue("Recommendation", truncateSnippet(fix, 800))
        }
        if (item.cwe?.length) {
            renderLabelValue("CWE", item.cwe.join(", "))
        }
        if (owaspLabel) {
            renderLabelValue("OWASP", owaspLabel)
        }
        if (refsList.length) {
            renderLabelValue("References", refsList.join("\n"))
        }
    }

    const drawIastMetaBlock = (evidence) => {
        const lines = []
        if (evidence?.source) lines.push(`- Source: ${evidence.source}`)
        if (evidence?.sink) lines.push(`- Sink: ${evidence.sink}`)
        if (evidence?.category) lines.push(`- Category: ${evidence.category}`)
        if (evidence?.url) lines.push(`- URL: ${evidence.url}`)
        if (!lines.length) return

        ensureSpace(40)
        setBody(doc, pdfTheme)
        doc.setFont("helvetica", "bold")
        doc.setFontSize(9)
        doc.text("Meta:", margin, cursorY)
        cursorY += 12
        doc.setFont("helvetica", "normal")
        doc.setTextColor(80, 80, 80)
        lines.forEach(line => {
            const wrapped = doc.splitTextToSize(line, layout.pageWidth - margin * 2)
            doc.text(wrapped, margin, cursorY)
            cursorY += wrapped.length * 10 + 2
        })
        doc.setTextColor(0)
        cursorY += 6
    }

    const drawSastSourceSinkBlock = (evidence) => {
        const source = evidence?.source || null
        const sink = evidence?.sink || null
        if (!source && !sink) return

        ensureSpace(40)
        setBody(doc, pdfTheme)
        doc.setFont("helvetica", "bold")
        doc.setFontSize(9)
        doc.text("Source / Sink:", margin, cursorY)
        cursorY += 12
        doc.setFont("helvetica", "normal")
        doc.setTextColor(80, 80, 80)
        const buildLine = (label, endpoint) => {
            if (!endpoint) return ""
            const locText = formatLocationRange(endpoint.location)
            const parts = [
                endpoint.name ? `Name: ${endpoint.name}` : "",
                endpoint.file ? `File: ${endpoint.file}` : "",
                locText ? `Location: ${locText}` : ""
            ].filter(Boolean).join("; ")
            return parts ? `${label}: ${parts}` : ""
        }
        const sourceLine = buildLine("Source", source)
        const sinkLine = buildLine("Sink", sink)
        if (sourceLine) {
            const wrapped = doc.splitTextToSize(sourceLine, layout.pageWidth - margin * 2)
            doc.text(wrapped, margin, cursorY)
            cursorY += wrapped.length * 10 + 2
        }
        if (sinkLine) {
            const wrapped = doc.splitTextToSize(sinkLine, layout.pageWidth - margin * 2)
            doc.text(wrapped, margin, cursorY)
            cursorY += wrapped.length * 10 + 2
        }
        doc.setTextColor(0)
        cursorY += 6
    }

    const drawTraceListBlock = (label, trace) => {
        const entries = formatTraceEntriesForExport(trace)
        if (!entries.length) return
        ensureSpace(40)
        setBody(doc, pdfTheme)
        doc.setFont("helvetica", "bold")
        doc.setFontSize(9)
        doc.text(`${label}:`, margin, cursorY)
        cursorY += 12
        doc.setFont("helvetica", "normal")
        doc.setTextColor(80, 80, 80)
        entries.forEach(entry => {
            const stage = entry.stage ? String(entry.stage).toUpperCase() : "STEP"
            const header = `• ${stage}`
            const headerLines = doc.splitTextToSize(header, layout.pageWidth - margin * 2)
            doc.text(headerLines, margin, cursorY)
            cursorY += headerLines.length * 10 + 2

            const detailLines = []
            if (entry.label) detailLines.push(`Label: ${entry.label}`)
            if (entry.file) detailLines.push(`File: ${entry.file}`)
            if (entry.loc) detailLines.push(`Location: ${entry.loc}`)
            detailLines.forEach(detail => {
                const wrapped = doc.splitTextToSize(detail, layout.pageWidth - margin * 2)
                doc.text(wrapped, margin + 12, cursorY)
                cursorY += wrapped.length * 10 + 2
            })
            cursorY += 2
        })
        doc.setTextColor(0)
        cursorY += 6
    }

    const drawExecMappingBlock = (item) => {
        const cweList = Array.isArray(item?.cwe) ? item.cwe : (item?.cwe ? [item.cwe] : [])
        const owaspList = resolveOwaspList(item)
        const refsList = (item?.references || []).map(ref => ref?.url || ref).filter(Boolean).slice(0, 5)
        if (!cweList.length && !owaspList.length && !refsList.length) return

        const renderLabelValue = (label, value) => {
            if (!value) return
            ensureSpace(30)
            setBody(doc, pdfTheme)
            doc.setFont("helvetica", "bold")
            doc.setFontSize(9)
            doc.text(`${label}:`, margin, cursorY)
            cursorY += 12
            doc.setFont("helvetica", "normal")
            doc.setTextColor(80, 80, 80)
            const lines = doc.splitTextToSize(String(value), layout.pageWidth - margin * 2)
            doc.text(lines, margin, cursorY)
            cursorY += lines.length * 10 + 6
            doc.setTextColor(0)
        }

        if (cweList.length) {
            renderLabelValue("CWE", cweList.join(", "))
        }
        if (owaspList.length) {
            renderLabelValue("OWASP", owaspList.join(", "))
        }
        if (refsList.length) {
            renderLabelValue("References", refsList.join("\n"))
        }
    }

    sections.forEach(section => {
        const findings = (model.sections?.[section.id] || []).slice().sort(sortBySeverity)
        if (!findings.length) return
        addSectionTitle(section.label)

        // Render each finding as a card-like block (similar to executive report)
        findings.forEach(item => {
            const severityKey = normalizeSeverityKey(item.severity)
            const locationText = formatAssetForDetail(item.location)

            ensureSpace(120)

            // Finding ID and Title (bold)
            setBody(doc, pdfTheme)
            doc.setFont("helvetica", "bold")
            doc.setFontSize(10)
            const titleText = clampCellText(`${item.findingId || section.label} - ${item.title}`, { maxChars: 100, maxLines: 1 })
            doc.text(titleText, margin, cursorY)
            cursorY += 14

            // Location (muted)
            if (locationText) {
                doc.setFont("helvetica", "normal")
                doc.setFontSize(9)
                doc.setTextColor(120, 120, 120)
                const locLines = doc.splitTextToSize(locationText, layout.pageWidth - margin * 2)
                doc.text(locLines.slice(0, 2), margin, cursorY)
                cursorY += locLines.slice(0, 2).length * 11
                doc.setTextColor(0)
            }

            // Severity badge + Confidence
            const sevColor = pdfTheme.severityColors[severityKey] || pdfTheme.severityColors.info
            const badgeY = cursorY
            const badgeWidth = drawBadge(doc, severityKey.toUpperCase(), { x: margin, y: badgeY, fill: sevColor })
            if (item.confidence != null) {
                doc.setFont("helvetica", "normal")
                doc.setFontSize(9)
                doc.text(`Confidence: ${Math.round(item.confidence)}`, margin + badgeWidth + 10, badgeY + 12)
            }
            cursorY += 28

            // Evidence section based on engine type
            const evidence = item.evidence || {}
            if (section.id === "dast") {
                // DAST: Request, Response, Proof
                if (evidence.requestSnippet) {
                    drawCodeBlock("Request", evidence.requestSnippet)
                }
                if (evidence.responseSnippet) {
                    drawCodeBlock("Response", evidence.responseSnippet)
                    cursorY += pdfTheme.spacing.sm
                }
                if (evidence.notes) {
                    drawCodeBlock("Proof", evidence.notes)
                    cursorY += pdfTheme.spacing.sm
                }
                // DAST order matches HTML: evidence first, then other information
                drawOtherInformationBlock(item, section.id)
            } else if (section.id === "iast") {
                // IAST order matches HTML: meta, context, flow, trace, other information
                drawIastMetaBlock(evidence)
                if (evidence.codeSnippet) {
                    drawCodeBlock("Context / Value", evidence.codeSnippet)
                }
                if (evidence.flow) {
                    drawCodeBlock("Flow", evidence.flow)
                } else if (evidence.notes) {
                    ensureSpace(30)
                    setBody(doc, pdfTheme)
                    doc.setFont("helvetica", "bold")
                    doc.setFontSize(9)
                    doc.text("Flow:", margin, cursorY)
                    cursorY += 12
                    doc.setFont("helvetica", "normal")
                    doc.setTextColor(80, 80, 80)
                    const notesLines = doc.splitTextToSize(evidence.notes, layout.pageWidth - margin * 2)
                    doc.text(notesLines.slice(0, 4), margin, cursorY)
                    cursorY += notesLines.slice(0, 4).length * 10 + 8
                    doc.setTextColor(0)
                }
                if (evidence.trace) {
                    drawCodeBlock("Trace", evidence.trace)
                }
                if (evidence.proof) {
                    drawCodeBlock("Proof", evidence.proof)
                }
                drawOtherInformationBlock(item, section.id)
            } else if (section.id === "sast") {
                // SAST order matches HTML: source/sink, trace, other information
                drawSastSourceSinkBlock(evidence)
                if (evidence.trace) {
                    drawTraceListBlock("Taint Trace", evidence.trace)
                }
                if (evidence.codeSnippet) {
                    drawCodeBlock("Source Code", evidence.codeSnippet)
                }
                if (evidence.notes) {
                    ensureSpace(30)
                    setBody(doc, pdfTheme)
                    doc.setFont("helvetica", "bold")
                    doc.setFontSize(9)
                    doc.text("Node Type:", margin, cursorY)
                    cursorY += 12
                    doc.setFont("helvetica", "normal")
                    doc.setTextColor(80, 80, 80)
                    doc.text(evidence.notes, margin, cursorY)
                    cursorY += 12
                    doc.setTextColor(0)
                }
                drawOtherInformationBlock(item, section.id)
            } else if (section.id === "sca") {
                drawOtherInformationBlock(item, section.id)
                // SCA: Component info
                if (item.componentName) {
                    ensureSpace(30)
                    setBody(doc, pdfTheme)
                    doc.setFont("helvetica", "bold")
                    doc.setFontSize(9)
                    doc.text("Component:", margin, cursorY)
                    cursorY += 12
                    doc.setFont("helvetica", "normal")
                    doc.setTextColor(80, 80, 80)
                    doc.text(`${item.componentName}${item.componentVersion ? ` @ ${item.componentVersion}` : ""}`, margin, cursorY)
                    cursorY += 12
                    doc.setTextColor(0)
                }
            }

            cursorY += pdfTheme.spacing.sm

            // Draw a light separator line
            doc.setDrawColor(230, 230, 230)
            doc.setLineWidth(0.5)
            doc.line(margin, cursorY, layout.pageWidth - margin, cursorY)
            cursorY += pdfTheme.spacing.md
        })
    })

    ;[['sast', 'SAST Discovery'], ['dast', 'DAST Reconnaissance']].forEach(([engine, heading]) => {
    const discoveryItems = Array.isArray(model.discoveries?.[engine]) ? model.discoveries[engine] : []
    if (discoveryItems.length) {
        addSectionTitle(heading)
        discoveryItems.forEach(item => {
            ensureSpace(100)
            setBody(doc, pdfTheme)
            doc.setFont("helvetica", "bold")
            doc.setFontSize(10)
            const titleText = clampCellText(item.title || "Discovery", { maxChars: 100, maxLines: 1 })
            doc.text(titleText, margin, cursorY)
            cursorY += 14

            const metaLine = [
                item.file ? `File: ${item.file}` : "",
                item.location ? `Location: ${engine === 'dast' ? item.location.url || '' : formatRange(item.location)}` : ""
            ].filter(Boolean).join(" | ")
            if (metaLine) {
                doc.setFont("helvetica", "normal")
                doc.setFontSize(9)
                doc.setTextColor(120, 120, 120)
                const metaLines = doc.splitTextToSize(metaLine, layout.pageWidth - margin * 2)
                doc.text(metaLines.slice(0, 2), margin, cursorY)
                cursorY += metaLines.slice(0, 2).length * 11
                doc.setTextColor(0)
            }

            if (item.summary) {
                ensureSpace(24)
                setBody(doc, pdfTheme)
                doc.setFont("helvetica", "normal")
                doc.setFontSize(9)
                const summaryLines = doc.splitTextToSize(item.summary, layout.pageWidth - margin * 2)
                doc.text(summaryLines, margin, cursorY)
                cursorY += summaryLines.length * 10 + 6
            }

            const detailItems = Array.isArray(item.details) ? item.details.filter(Boolean) : []
            if (detailItems.length) {
                setBody(doc, pdfTheme)
                doc.setFont("helvetica", "bold")
                doc.setFontSize(9)
                doc.text("Details:", margin, cursorY)
                cursorY += 12
                doc.setFont("helvetica", "normal")
                doc.setTextColor(80, 80, 80)
                detailItems.forEach(detail => {
                    const wrapped = doc.splitTextToSize(`- ${detail}`, layout.pageWidth - margin * 2)
                    doc.text(wrapped, margin, cursorY)
                    cursorY += wrapped.length * 10 + 2
                })
                doc.setTextColor(0)
                cursorY += 4
            }

            doc.setDrawColor(230, 230, 230)
            doc.setLineWidth(0.5)
            doc.line(margin, cursorY, layout.pageWidth - margin, cursorY)
            cursorY += pdfTheme.spacing.md
        })
    }
    })

    cursorY += pdfTheme.spacing.lg
    ensureSpace(80)
    const methodologyText = "Report generated using cert-x scanning engines. Results depend on scan coverage and target responsiveness."
    const scopeText = model.meta.context?.scopeSummary && model.meta.context?.scopeSummary !== "N/A"
        ? `Scope: ${model.meta.context.scopeSummary}`
        : "Scope: N/A"
    const limitationsText = "Limitations: Results depend on available routes and auth context; some flows may not be covered."
    const methodologyLines = doc.splitTextToSize(`${methodologyText}\n\n${scopeText}\n${limitationsText}`, layout.pageWidth - margin * 2)
    setBody(doc, pdfTheme)
    doc.text(methodologyLines, margin, cursorY)
    cursorY += methodologyLines.length * 12

    const totalPages = doc.internal.getNumberOfPages()
    for (let page = 1; page <= totalPages; page += 1) {
        doc.setPage(page)
        layout.drawHeader(page, totalPages)
        layout.drawFooter(page, totalPages)
    }

    return doc
}

function buildExecutivePdfFromReportModel(model) {
    const JsPDF = getJsPdfCtor()
    const doc = new JsPDF({ unit: "pt", format: "a4" })
    const layout = createPdfLayout(doc, model.meta, pdfTheme)
    const margin = layout.margin
    let cursorY = layout.contentTop

    const ensureSpace = (height = 20) => {
        if (cursorY + height > layout.contentBottom) {
            doc.addPage()
            cursorY = layout.contentTop
        }
    }

    const addSectionTitle = (title) => {
        cursorY += pdfTheme.spacing.md
        ensureSpace(24)
        cursorY = layout.drawSectionTitle(title, cursorY)
        cursorY += pdfTheme.spacing.xs
    }

    const addAutoTable = (options) => {
        const tableDefaults = pdfTheme.tables.executive
        doc.autoTable({
            ...tableDefaults,
            ...options,
            startY: cursorY,
            margin: { left: margin, right: margin },
            styles: { ...tableDefaults.styles, ...(options.styles || {}) },
            headStyles: { ...tableDefaults.headStyles, ...(options.headStyles || {}) },
            alternateRowStyles: { ...(tableDefaults.alternateRowStyles || {}), ...(options.alternateRowStyles || {}) }
        })
        cursorY = doc.lastAutoTable.finalY + pdfTheme.spacing.lg
    }

    const drawExecMappingBlock = (item) => {
        const cweList = Array.isArray(item?.cwe) ? item.cwe : (item?.cwe ? [item.cwe] : [])
        const owaspList = resolveOwaspList(item)
        const refsList = (item?.references || []).map(ref => ref?.url || ref).filter(Boolean).slice(0, 5)
        if (!cweList.length && !owaspList.length && !refsList.length) return

        const renderLabelValue = (label, value) => {
            if (!value) return
            ensureSpace(30)
            setBody(doc, pdfTheme)
            doc.setFont("helvetica", "bold")
            doc.setFontSize(9)
            doc.text(`${label}:`, margin, cursorY)
            cursorY += 12
            doc.setFont("helvetica", "normal")
            doc.setTextColor(80, 80, 80)
            const lines = doc.splitTextToSize(String(value), layout.pageWidth - margin * 2)
            doc.text(lines, margin, cursorY)
            cursorY += lines.length * 10 + 6
            doc.setTextColor(0)
        }

        if (cweList.length) {
            renderLabelValue("CWE", cweList.join(", "))
        }
        if (owaspList.length) {
            renderLabelValue("OWASP", owaspList.join(", "))
        }
        if (refsList.length) {
            renderLabelValue("References", refsList.join("\n"))
        }
    }

    cursorY = layout.drawHeaderBlock({
        title: "cert-x Security Report",
        subtitle: "Website Vulnerability Scanner Report",
        logoDataUrl: model.meta.logoDataUrl
    })
    cursorY = drawHostBanner(doc, {
        x: margin,
        y: cursorY,
        width: layout.pageWidth - margin * 2,
        text: model.meta.host || "unknown"
    })
    cursorY = drawRunCoverage(doc, layout, model.certXRun, cursorY)

    if (Object.keys(model.summary.byEngine || {}).length) {
        const tiers = { confirmed: 0, likely: 0, potential: model.findings.length, confirmedHigh: 0 }

        addSectionTitle("Summary")
        const riskEndY = drawRiskBarList(doc, {
            x: margin,
            y: cursorY,
            counts: model.summary.bySeverity || {},
            barMaxWidth: 180
        })
        cursorY = riskEndY + pdfTheme.spacing.sm
        const summaryRows = buildSummaryTableRows(model, { interactive: false })
        if (summaryRows.length) {
            addAutoTable({
                head: [["Engine", "Critical", "High", "Medium", "Low", "Info", "Total"]],
                body: summaryRows.map(row => row.cells),
                columnStyles: { 0: { cellWidth: 70 } }
            })
        }

        const conclusion = buildExecutiveConclusion(model, tiers)
        const conclusionLines = doc.splitTextToSize(conclusion, layout.pageWidth - margin * 2)
        setBody(doc, pdfTheme)
        doc.text(conclusionLines, margin, cursorY)
        cursorY += conclusionLines.length * 12 + 6

        // Exposure & Hygiene in Summary
        ensureSpace(80)
        setBody(doc, pdfTheme)
        doc.setFont("helvetica", "bold")
        doc.text("Exposure & Hygiene:", margin, cursorY)
        cursorY += 14
        doc.setFont("helvetica", "normal")
        const headerHighlights = (model.dashboard.owaspHeaders || []).slice(0, 3)
        const headersText = headerHighlights.length
            ? headerHighlights.join("; ")
            : "No header issues detected or data unavailable."
        const storageDetails = model.dashboard.storageDetails || { localStorage: [], sessionStorage: [] }
        const tokenInStorage = [...(storageDetails.localStorage || []), ...(storageDetails.sessionStorage || [])]
            .some(entry => STORAGE_TOKEN_KEY_REGEX.test(String(entry.key)))
        const cookieFlagsMissing = (model.dashboard.cookies || []).some(item => item?.httpOnly === false)
        const tokenLine = model.dashboard.assessed !== true ? 'Not assessed in this report.' : `Tokens in storage: ${tokenInStorage ? "Yes" : "No"}; Cookie HttpOnly missing: ${cookieFlagsMissing ? "Yes" : "No"}`
        const scaTopSummary = (model.sections?.sca || []).slice(0, 3).map(item => {
            const fix = item.recommendation ? truncateSnippet(item.recommendation, 80) : "Upgrade to a secure version."
            return `${item.title} (${item.severity}) - ${fix}`
        })
        const scaLineSummary = scaTopSummary.length ? scaTopSummary.join("; ") : "No high-risk dependencies identified or data unavailable."
        const exposureLines = [
            `Headers: ${headersText}`,
            `Token/storage: ${tokenLine}`,
            `Dependencies: ${scaLineSummary}`
        ]
        exposureLines.forEach(line => {
            const lines = doc.splitTextToSize(line, layout.pageWidth - margin * 2)
            doc.text(lines, margin, cursorY)
            cursorY += lines.length * 12 + 2
        })
        cursorY += pdfTheme.spacing.xs

        // Remediation Plan in Summary
        ensureSpace(60)
        doc.setFont("helvetica", "bold")
        doc.text("Remediation Plan:", margin, cursorY)
        cursorY += 14
        doc.setFont("helvetica", "normal")
        const sevCounts = model.summary.bySeverity || {}
        addAutoTable({
            head: [["Bucket", "Items"]],
            body: [
                ["Fix now (0–7 days)", String((sevCounts.critical || 0) + (sevCounts.high || 0))],
                ["Fix soon (7–30 days)", String(sevCounts.medium || 0)],
                ["Backlog", String((sevCounts.low || 0) + (sevCounts.info || 0))]
            ],
            columnStyles: { 0: { cellWidth: 180 } }
        })
    }

    const severityCounts = model.summary.bySeverity || {}
    const topLabel = buildTopRisksLabel(severityCounts)
    const topPool = severityCounts.critical > 0
        ? model.findings.filter(item => normalizeSeverityKey(item?.severity) === "critical")
        : model.findings
    const topGrouped = groupFindingsForExec(topPool, {
        keyFn: item => item.title || item.findingId || "finding",
        maxItems: 5
    })

    if (topGrouped.length) {
        addSectionTitle(topLabel)
        // Render each finding as a card-like block (matching HTML layout)
        topGrouped.forEach(entry => {
            const item = entry.item
            const occ = entry.count > 1 ? ` (${entry.count} occurrences)` : ""
            const owner = inferOwnerHint(item)
            const asset = formatAssetForOverview(item.location)
            const severityKey = normalizeSeverityKey(item.severity)

            ensureSpace(80)

            // Title (bold)
            setBody(doc, pdfTheme)
            doc.setFont("helvetica", "bold")
            doc.setFontSize(11)
            const titleText = clampCellText(`${item.title}${occ}`, { maxChars: 100, maxLines: 1 })
            doc.text(titleText, margin, cursorY)
            cursorY += 14

            // Engine • Asset (muted)
            doc.setFont("helvetica", "normal")
            doc.setFontSize(9)
            doc.setTextColor(120, 120, 120)
            doc.text(`${item.engine || "DAST"} • ${asset}`, margin, cursorY)
            doc.setTextColor(0)
            cursorY += 12

            // Severity badge + Owner
            const sevColor = pdfTheme.severityColors[severityKey] || pdfTheme.severityColors.info
            const badgeY = cursorY
            const badgeWidth = drawBadge(doc, severityKey.toUpperCase(), { x: margin, y: badgeY, fill: sevColor })
            doc.setFont("helvetica", "normal")
            doc.setFontSize(9)
            const ownerX = margin + badgeWidth + 10
            doc.text(`Owner: ${owner}`, ownerX, badgeY + 12)
            cursorY += 28

            // CWE/OWASP mapping
            drawExecMappingBlock(item)
            doc.setTextColor(0)
            cursorY += pdfTheme.spacing.sm

            // Draw a light separator line
            doc.setDrawColor(230, 230, 230)
            doc.setLineWidth(0.5)
            doc.line(margin, cursorY, layout.pageWidth - margin, cursorY)
            cursorY += pdfTheme.spacing.sm
        })
    }

    // Engine sections (DAST, IAST, SAST, SCA) - card-like blocks matching HTML
    const engineSections = [
        { id: "dast", label: "DAST" },
        { id: "iast", label: "IAST" },
        { id: "sast", label: "SAST" },
        { id: "sca", label: "SCA" }
    ]
    engineSections.forEach(section => {
        const findings = model.sections?.[section.id] || []
        if (!findings.length) return
        const grouped = groupFindingsForExec(findings, {
            keyFn: section.id === "sca"
                ? normalizeScaKey
                : (item) => item.title || item.findingId || "finding"
        })
        ensureSpace(190)
        addSectionTitle(`${section.label} Top Findings`)

        // Render each finding as a card-like block
        grouped.forEach(entry => {
            const item = entry.item
            const occ = entry.count > 1 ? ` - ${entry.count} occurrences` : ""
            const asset = formatAssetForOverview(item.location)
            const severityKey = normalizeSeverityKey(item.severity)
            const description = item.description ? stripHtmlToText(item.description) : ""
            const fix = item.recommendation ? stripHtmlToText(item.recommendation) : inferFix(item)

            ensureSpace(150)

            // Title (bold)
            setBody(doc, pdfTheme)
            doc.setFont("helvetica", "bold")
            doc.setFontSize(11)
            const titleText = clampCellText(`${item.title}${occ}`, { maxChars: 100, maxLines: 1 })
            doc.text(titleText, margin, cursorY)
            cursorY += 14

            // Asset (muted)
            doc.setFont("helvetica", "normal")
            doc.setFontSize(9)
            doc.setTextColor(120, 120, 120)
            doc.text(asset, margin, cursorY)
            doc.setTextColor(0)
            cursorY += 14

            // Severity badge
            const sevColor = pdfTheme.severityColors[severityKey] || pdfTheme.severityColors.info
            drawBadge(doc, severityKey.toUpperCase(), { x: margin, y: cursorY - 4, fill: sevColor })
            cursorY += 24

            // Description (for DAST/IAST/SAST, not SCA)
            if (description && section.id !== "sca") {
                setBody(doc, pdfTheme)
                doc.setFont("helvetica", "bold")
                doc.setTextColor(0, 0, 0)
                doc.text("Description:", margin, cursorY)
                cursorY += 14
                doc.setFont("helvetica", "normal")
                doc.setTextColor(80, 80, 80)
                const descLines = doc.splitTextToSize(description, layout.pageWidth - margin * 2)
                doc.text(descLines, margin, cursorY)
                cursorY += descLines.length * 11 + 10
            }

            // Fix/Recommendation
            if (fix) {
                setBody(doc, pdfTheme)
                doc.setFont("helvetica", "bold")
                doc.setTextColor(0, 0, 0)
                doc.text("Recommendation:", margin, cursorY)
                cursorY += 14
                doc.setFont("helvetica", "normal")
                doc.setTextColor(80, 80, 80)
                const recLines = doc.splitTextToSize(fix, layout.pageWidth - margin * 2)
                doc.text(recLines, margin, cursorY)
                cursorY += recLines.length * 11 + 10
            }

            // CWE (separate from OWASP)
            const cweList = Array.isArray(item.cwe) ? item.cwe : (item.cwe ? [item.cwe] : [])
            if (cweList.length) {
                ensureSpace(40)
                setBody(doc, pdfTheme)
                doc.setFont("helvetica", "bold")
                doc.setTextColor(0, 0, 0)
                doc.text("CWE:", margin, cursorY)
                cursorY += 14
                doc.setFont("helvetica", "normal")
                doc.setTextColor(80, 80, 80)
                const cweText = cweList.join(", ")
                const cweLines = doc.splitTextToSize(cweText, layout.pageWidth - margin * 2)
                doc.text(cweLines, margin, cursorY)
                cursorY += cweLines.length * 11 + 10
            }

            // OWASP (separate from CWE)
            const owaspList = resolveOwaspList(item)
            if (owaspList.length) {
                ensureSpace(40)
                setBody(doc, pdfTheme)
                doc.setFont("helvetica", "bold")
                doc.setTextColor(0, 0, 0)
                doc.text("OWASP:", margin, cursorY)
                cursorY += 14
                doc.setFont("helvetica", "normal")
                doc.setTextColor(80, 80, 80)
                const owaspText = owaspList.join(", ")
                const owaspLines = doc.splitTextToSize(owaspText, layout.pageWidth - margin * 2)
                doc.text(owaspLines, margin, cursorY)
                cursorY += owaspLines.length * 11 + 10
            }

            // References (each on separate line)
            const refsList = (item.references || []).map(ref => ref?.url || ref).filter(Boolean)
            if (refsList.length) {
                ensureSpace(50)
                setBody(doc, pdfTheme)
                doc.setFont("helvetica", "bold")
                doc.setTextColor(0, 0, 0)
                doc.text("References:", margin, cursorY)
                cursorY += 14
                doc.setFont("helvetica", "normal")
                doc.setTextColor(80, 80, 80)
                refsList.forEach(refUrl => {
                    ensureSpace(20)
                    const refLines = doc.splitTextToSize(refUrl, layout.pageWidth - margin * 2)
                    doc.text(refLines, margin, cursorY)
                    cursorY += refLines.length * 11 + 2
                })
                cursorY += 6
            }

            doc.setTextColor(0)
            cursorY += pdfTheme.spacing.md

            // Draw a light separator line
            doc.setDrawColor(220, 220, 220)
            doc.setLineWidth(0.5)
            doc.line(margin, cursorY, layout.pageWidth - margin, cursorY)
            cursorY += pdfTheme.spacing.md
        })
    })

    cursorY += pdfTheme.spacing.lg
    ensureSpace(80)
    const methodologyText = "Report generated using cert-x scanning engines. Executive preset includes top findings only and excludes sensitive evidence by default. Results depend on scan coverage and target responsiveness."
    const scopeText = model.meta.context?.scopeSummary && model.meta.context?.scopeSummary !== "N/A"
        ? `Scope: ${model.meta.context.scopeSummary}`
        : "Scope: N/A"
    const limitationsText = "Limitations: Results depend on available routes and auth context; some flows may not be covered."
    const methodologyLines = doc.splitTextToSize(`${methodologyText}\n\n${scopeText}\n${limitationsText}`, layout.pageWidth - margin * 2)
    setBody(doc, pdfTheme)
    doc.text(methodologyLines, margin, cursorY)
    cursorY += methodologyLines.length * 12

    const totalPages = doc.internal.getNumberOfPages()
    for (let page = 1; page <= totalPages; page += 1) {
        doc.setPage(page)
        layout.drawHeader(page, totalPages)
        layout.drawFooter(page, totalPages)
    }

    return doc
}

function sanitizeRichText(html) {
    if (!html) return ""
    return dompurify.sanitize(html, { ALLOWED_TAGS: SAST_ALLOWED_TAGS, ALLOWED_ATTR: SAST_ALLOWED_ATTRS })
}

function escapeText(value, fallback = "-") {
    if (value === undefined || value === null || value === "") return fallback
    return ptk_utils.escapeHtml(String(value))
}

function normalizeSeverityKey(value) {
    const normalized = String(value || "").toLowerCase()
    if (UI_SEVERITY_ORDER.includes(normalized)) return normalized
    return "info"
}

const SEVERITY_RANKING = ["critical", "high", "medium", "low", "info"]

function severityRank(severity) {
    const normalized = String(severity || "").toLowerCase()
    const index = SEVERITY_RANKING.indexOf(normalized)
    return index === -1 ? SEVERITY_RANKING.length : index
}

function formatPoint(point) {
    if (!point || typeof point.line !== "number") return ""
    const column = typeof point.column === "number" ? `:C${point.column}` : ""
    return `L${point.line}${column}`
}

function formatRange(loc) {
    if (!loc) return ""
    const start = formatPoint(loc.start || loc)
    const end = formatPoint(loc.end || loc)
    if (start && end && start !== end) return `${start} → ${end}`
    return start || end
}

function normalizeTraceLabel(label) {
    if (!label) return ""
    const compact = String(label).replace(/\s+/g, " ").trim()
    if (compact.length <= 140) return compact
    return `${compact.slice(0, 137)}...`
}

function formatTraceEntriesForExport(trace) {
    const steps = Array.isArray(trace) && trace.length ? trace : null
    if (!steps) {
        if (trace) {
            return [{ stage: "step", label: normalizeTraceLabel(trace), file: "", loc: "" }]
        }
        return []
    }
    return steps.map((step, idx) => {
        const stage = step?.kind || (idx === 0 ? "source" : (idx === steps.length - 1 ? "sink" : "step"))
        const label = normalizeTraceLabel(step?.label || "")
        const file = step?.file ? String(step.file) : ""
        const loc = formatRange(step?.loc)
        return { stage, label, file, loc }
    }).filter(entry => entry.stage || entry.label || entry.file || entry.loc)
}

function normalizeScaList(value) {
    if (Array.isArray(value)) return value.filter(entry => entry !== undefined && entry !== null)
    if (value === undefined || value === null || value === "") return []
    return [value]
}

function buildScaEntries(list) {
    if (!Array.isArray(list)) return []
    const entries = []
    list.forEach(component => {
        if (!component) return
        const findings = Array.isArray(component.findings)
            ? component.findings
            : (Array.isArray(component.vulnerabilities) ? component.vulnerabilities : [])
        if (findings.length) {
            findings.forEach(finding => entries.push({ component, finding }))
            return
        }
        if (component.severity || component.identifiers || component.info) {
            entries.push({ component, finding: component })
        }
    })
    return entries
}

function cloneScaIdentifiers(raw) {
    if (!raw || typeof raw !== "object") return {}
    try {
        return JSON.parse(JSON.stringify(raw))
    } catch (_) {
        const copy = {}
        Object.keys(raw).forEach(key => {
            copy[key] = raw[key]
        })
        return copy
    }
}

function transformScaFindingForReport(finding) {
    if (!finding || (finding.engine && finding.engine !== "SCA")) return null
    const evidence = finding.evidence?.sca || {}
    const componentInfo = evidence.component || {}
    const componentName = componentInfo.name || componentInfo.component || finding.ruleName || "Dependency"
    const version = componentInfo.version || "n/a"
    const file = evidence.sourceFile || finding.location?.file || null
    const identifiers = cloneScaIdentifiers(evidence.identifiers)
    const summary = evidence.summary || identifiers.summary || finding.description || finding.ruleName || null
    if (summary && (!identifiers.summary || typeof identifiers.summary !== "string")) {
        identifiers.summary = summary
    }
    const versionRange = evidence.versionRange || {}
    const convertedFinding = {
        severity: finding.severity || "medium",
        identifiers,
        info: Array.isArray(evidence.info) ? evidence.info.slice() : [],
        cwe: finding.cwe,
        atOrAbove: versionRange.atOrAbove || null,
        above: versionRange.above || null,
        atOrBelow: versionRange.atOrBelow || null,
        below: versionRange.below || null
    }
    return {
        component: {
            component: componentName,
            version,
            file
        },
        finding: convertedFinding
    }
}

function buildScaEntriesFromFindings(findings = []) {
    if (!Array.isArray(findings)) return []
    return findings.map(transformScaFindingForReport).filter(Boolean)
}

function buildRawResponse(response = {}) {
    const parts = []
    const headersBlock = Array.isArray(response.headers) && response.headers.length
        ? response.headers.map(h => `${h.name}: ${h.value}`).join('\n')
        : ''
    if (response.statusLine) parts.push(response.statusLine)
    if (headersBlock) parts.push(headersBlock)
    if (parts.length) parts.push('')
    parts.push(typeof response.body === 'string' ? response.body : '')
    return parts.join('\n')
}

function buildRawRequest(request = {}) {
    const parts = []
    const method = request.method || "GET"
    const url = request.url || request.ui_url || request.target || "/"
    parts.push(`${method} ${url} HTTP/1.1`)
    const headersBlock = Array.isArray(request.headers) && request.headers.length
        ? request.headers.map(h => `${h.name}: ${h.value}`).join('\n')
        : ''
    if (headersBlock) parts.push(headersBlock)
    const body = typeof request.body === 'string'
        ? request.body
        : (request.body && typeof request.body.preview === 'string' ? request.body.preview : '')
    if (headersBlock || body) parts.push('')
    if (body) parts.push(body)
    return parts.join('\n')
}

function resolveDastAttackContext(finding, viewModel) {
    const evidence = finding?.evidence?.dast || {}
    const requests = Array.isArray(viewModel?.requests) ? viewModel.requests : []
    const requestRecord = evidence.requestId != null
        ? requests.find((record) => String(record.id) === String(evidence.requestId))
        : null
    const attackRecord = requestRecord && evidence.attackId != null
        ? (requestRecord.attacks || []).find((attack) => String(attack.id) === String(evidence.attackId))
        : null
    return { requestRecord, attackRecord }
}
export { buildReportModel, buildMarkdownFromExportModel, buildPdfFromExportModel, buildExecutivePdfFromReportModel, buildExportFindingFromNormalized, buildExportFindingFromSca, buildScaEntries, buildScaEntriesFromFindings, exportModel };

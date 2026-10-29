import { captureIdentity } from '../capture/captureStore.js'

export const SCA_BODY_BYTES_LIMIT = 8 * 1024 * 1024

export function isScaBodyCandidate(record) {
    const type = String(record?.resourceType || '').toLowerCase()
    // Script covers browser-loaded classic, module and dynamically inserted assets.
    // Fetch/XHR needs a JavaScript response type or script extension at admission.
    if (type === 'script') return true
    if (type !== 'fetch' && type !== 'xhr' && type !== 'xmlhttprequest') return false
    const mime = String(record?.response?.mimeType || record?.mimeType || '').toLowerCase()
    if (/(?:javascript|ecmascript)/.test(mime)) return true
    try { return /\.(?:m?js)(?:$)/i.test(new URL(record.url).pathname) } catch (_) { return false }
}

export function scaCaptureKey(record) {
    if (!record || !Number.isInteger(record.tabId) || typeof record.epoch !== 'string'
        || typeof record.requestId !== 'string' || !record.requestId
        || record.frameId === undefined || !(record.documentId || record.loaderId)) return null
    return captureIdentity(record)
}

export function scaRequestKey(record) {
    const grant = scaCaptureKey(record)
    return grant && JSON.stringify([grant, record.frameId, record.documentId || '', record.loaderId || '',
        record.sessionGeneration ?? null, record.navigationGeneration ?? null])
}

export function decodeScaBody(record) {
    const status = Number(record?.response?.status)
    if (!Number.isInteger(status) || status < 200 || status >= 300) throw new Error('response_status_unavailable')
    const mime = String(record?.response?.mimeType || record?.mimeType || '').toLowerCase()
    if (mime && !/(?:javascript|ecmascript|text\/plain|application\/octet-stream)/.test(mime)) throw new Error('non_javascript_response')
    if (record?.complete !== true || record?.truncated === true || typeof record.body !== 'string') throw new Error('response_body_incomplete')
    if (record.base64Encoded) {
        if (record.body.length > Math.ceil(SCA_BODY_BYTES_LIMIT / 3) * 4 + 4) throw new Error('response_body_limit')
        let binary
        try { binary = atob(record.body) } catch (_) { throw new Error('response_body_decode_failed') }
        if (binary.length > SCA_BODY_BYTES_LIMIT) throw new Error('response_body_limit')
        try { return new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(binary, character => character.charCodeAt(0))) }
        catch (_) { throw new Error('response_body_decode_failed') }
    }
    if (new TextEncoder().encode(record.body).length > SCA_BODY_BYTES_LIMIT) throw new Error('response_body_limit')
    return record.body
}

export function decodeScaExecutedSource(record) {
    if (record?.executedSource !== true || record?.provenance !== 'debugger_script_source'
        || record?.complete !== true || record?.truncated === true || typeof record.body !== 'string')
        throw new Error('script_source_incomplete')
    if (new TextEncoder().encode(record.body).length > SCA_BODY_BYTES_LIMIT) throw new Error('script_source_limit')
    return record.body
}

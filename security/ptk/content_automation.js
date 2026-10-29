/* Author: Denis Podgurskii */

if (!window.__PTK_CONTENT_AUTOMATION_LOADED__) {
window.__PTK_CONTENT_AUTOMATION_LOADED__ = true;

const shared = window.PTK_CONTENT_SHARED || {};
const runtime = shared.runtime || ((typeof browser !== 'undefined' && browser?.runtime)
    ? browser.runtime
    : (typeof chrome !== 'undefined' && chrome?.runtime ? chrome.runtime : null));
const PTK_AGENT_AUTOMATION_SCRIPT_ID = 'ptk-agent-automation-layer';
const AUTOMATION_REQUEST_EVENT = 'ptk-automation-request';
const AUTOMATION_RESPONSE_EVENT = 'ptk-automation-response';
const ptkAutomationManifest = (() => {
    try {
        return runtime?.getManifest ? runtime.getManifest() : null;
    } catch (_) {
        return null;
    }
})();
const ptkAutomationVersion = ptkAutomationManifest?.version || 'unknown';
const isPtkAutomationAgentManifest = (() => {
    const background = ptkAutomationManifest?.background || {};
    return ptkAutomationManifest?.name === 'OWASP Penetration Testing Kit Automation'
        || background?.service_worker === 'app_automation.js'
        || background?.page === 'security/ptk/background_automation.html';
})();
let automationNonce = null;
let automationMessageHandlerInstalled = false;
let zapAutomationKeepaliveTimer = null;

function sendRuntimeMessage(payload) {
    if (typeof shared.sendRuntimeMessage === 'function') return shared.sendRuntimeMessage(payload);
    if (!runtime?.sendMessage) return Promise.resolve();
    try {
        return runtime.sendMessage(payload);
    } catch (_) {
        return Promise.resolve();
    }
}

function runtimeGetURL(path) {
    if (typeof shared.runtimeGetURL === 'function') return shared.runtimeGetURL(path);
    if (!runtime?.getURL) return null;
    try {
        return runtime.getURL(path);
    } catch (_) {
        return null;
    }
}

function getCurrentHref() {
    if (typeof shared.getCurrentHref === 'function') return shared.getCurrentHref();
    try {
        return window.location?.href || '';
    } catch (_) {
        return '';
    }
}

function isTopFrame() {
    if (typeof shared.isTopFrame === 'function') return shared.isTopFrame();
    try {
        return window.top === window;
    } catch (_) {
        return false;
    }
}

function normalizeAutomationBridgeResponse(type, response) {
    const isSuccessfulResponse = response && response.ok !== false && response.success !== false;
    if (type === 'export-scan-chunk' && isSuccessfulResponse) {
        if (response.chunk instanceof Uint8Array) {
            return response;
        }

        const serializedChunk = response.chunk;
        if (Array.isArray(serializedChunk)) {
            return {
                ...response,
                chunk: Uint8Array.from(serializedChunk)
            };
        }

        if (serializedChunk && typeof serializedChunk === 'object') {
            const byteKeys = Object.keys(serializedChunk)
                .filter((key) => /^\d+$/.test(key))
                .sort((left, right) => Number(left) - Number(right));

            if (byteKeys.length) {
                return {
                    ...response,
                    chunk: Uint8Array.from(byteKeys.map((key) => serializedChunk[key]))
                };
            }
        }
    }

    return response;
}

function installPtkAutomationBridge(version, nonce, automationEnabledState) { /* Management is privileged in cert-x; no page automation API. */ }

function injectPtkAgentAutomationLayer() { /* Management is privileged in cert-x; no page automation API. */ }

function notifyAutomationStatus(enabled, nonce) { /* Management is privileged in cert-x; no page automation API. */ }

function parseAutomationRequestEvent(event) {
    try { return JSON.parse(String(event?.detail || '')); } catch (_) { return null; }
}

function dispatchAutomationResponse(payload) {
    const detail = JSON.stringify(payload, (_, value) => value instanceof Uint8Array
        ? { __ptkType: 'Uint8Array', data: Array.from(value) }
        : value);
    document.dispatchEvent(new CustomEvent(AUTOMATION_RESPONSE_EVENT, { detail }));
}

function handleAutomationBridgeMessage(data) { /* Management is privileged in cert-x; no page automation API. */ }

function enableAutomationBridge() { /* Management is privileged in cert-x; no page automation API. */ }

shared.installIastBridge?.();
const automationTopFrame = isTopFrame();
if (automationTopFrame) {
    enableAutomationBridge();

    if (runtime?.onMessage) runtime.onMessage.addListener(function (message) {
        if (message && message.channel === 'ptk_popup2content' && message.type === 'ping') {
            return Promise.resolve({ ok: true, url: document.URL, runtime: 'automation' });
        }

        if (message?.channel === 'ptk_background2content_automation' && message?.payload) {
            try {
                dispatchAutomationResponse(message.payload);
            } catch (_) { }
            return Promise.resolve({ ok: true });
        }

        return undefined;
    });

    window.addEventListener('message', (event) => {
        const data = event.data || {};

        if (data?.ptk_ws) {
            sendRuntimeMessage({
                channel: 'ptk_contentws2rattacker',
                type: data.kind,
                payload: data.payload
            }).catch(() => { });
            return;
        }

        if (data?.ptk) {
            sendRuntimeMessage({
                channel: 'ptk_content2rattacker',
                type: 'xss_confirmed',
                data: {
                    attackValue: data,
                    origin: event.origin,
                    location: window.location?.toString?.() || ''
                }
            }).catch(() => { });
        }
    }, false);

    shared.installDastUserInteractionHook?.({ topFrameOnly: true });
}

shared.installEarlySastScriptCapture?.();
shared.installSastContentMessageListener?.();
shared.installSpaUrlNotifier?.('content_automation.js');

}

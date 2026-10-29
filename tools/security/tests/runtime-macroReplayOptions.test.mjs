// Imported PTK v10 behavior tests; only the retired popup markup assertion is omitted.
import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import test from 'node:test'
import vm from 'node:vm'

globalThis.self = globalThis.self || {}
globalThis.browser = globalThis.browser || { runtime: {} }

const { ptk_exporter } = await import('../../../security/ptk/background/exporter.js')

const recordedClick = {
    eventTypeName: 'Click',
    data: '',
    eventDuration: 100,
    windowIndex: 0,
    csspath: '#loginButton',
    fullcsspath: 'html > body > main > button:nth-of-type(1)',
    xpath: '//*[@id="loginButton"]',
    fullxpath: '/HTML/BODY/MAIN/BUTTON[1]'
}

function exporter(settings = {}) {
    return new ptk_exporter({
        items: [recordedClick],
        recordingRequests: []
    }, {
        format: 'xml',
        min_duration: 0,
        enable_extra_delay: false,
        event_type: 'javascript',
        element_path: 'css',
        ...settings
    })
}

test('new macro exports use DriverClick while legacy replay handlers remain available', async () => {
    for (const requestedType of ['driverclick', 'onclick', 'javascript']) {
        const instance = exporter({ event_type: requestedType })
        assert.equal(instance.settings.event_type, 'driverclick')
        assert.equal(instance.getXmlEventName('Click'), 'DriverClick')
        assert.equal(instance.getXmlEventName('SetValue'), 'DriverSetControlValue')
    }

    // Popup markup is replaced by cert-x; retain all exporter and replay behavior checks.
    const replayer = await fs.readFile('security/ptk/content/replayer.js', 'utf8')
    assert.match(replayer, /onclick\(item\)\s*\{\s*return this\.click\(item\)\s*\}/)
    assert.match(replayer, /driverclick\(item\)\s*\{\s*return this\.click\(item\)\s*\}/)
    assert.match(replayer, /driversetcontrolvalue\(item\)\s*\{\s*return this\.type\(item\)\s*\}/)
    assert.match(replayer, /async javascript\(item\)/)
    assert.match(replayer, /Object\.getOwnPropertyDescriptor\(prototype, 'value'\)\?\.set/)
    assert.match(replayer, /new InputEvent\('input'/)
    assert.match(replayer, /this\.setElementValue\(element, item\.Data\)/)
    assert.match(replayer, /DriverSetControlValue writes through the native value setter[\s\S]*?waitForElement\(item, this\.getStepTimeout\(item\), 250, \{ interactable: false \}\)/)
})

test('Element ID, CSS selector, and full path exports retain distinct locators', () => {
    assert.equal(
        exporter({ element_path: 'id' }).getElementPath(recordedClick),
        'xpath=//*[@id="loginButton"]'
    )
    assert.equal(
        exporter({ element_path: 'css' }).getElementPath(recordedClick),
        'css=#loginButton'
    )
    assert.equal(
        exporter({ element_path: 'fullpath' }).getElementPath(recordedClick),
        'xpath=/HTML/BODY/MAIN/BUTTON[1]'
    )
})

test('replay recovers a generated Angular Material input ID only when the fallback is unambiguous', async () => {
    const replayer = await fs.readFile('security/ptk/content/replayer.js', 'utf8')
    assert.match(replayer, /\^mat-input-\\d\+\$/)
    assert.match(replayer, /input\[id\^="mat-input-"\],textarea\[id\^="mat-input-"\],input\.mat-mdc-input-element/)
    assert.match(replayer, /if \(unique\.length === 1\) return unique\[0\]/)
})

test('external replay relaxes transient Angular overlay IDs and indexes and requires one interactable match', async () => {
    const replayer = await fs.readFile('security/ptk/content/replayer.js', 'utf8')
    assert.match(replayer, /const externalXpath = Number\(item\?\.PtkXPathIndexBase\) === 1/)
    assert.match(replayer, /if \(!xpath\.startsWith\('\/'\) && !xpath\.startsWith\('\('\)\) xpath = '\/' \+ xpath/)
    assert.match(replayer, /\^\\\/html\\\/body\\\/div\\\[\\d\+\\\]\\\/div\\\[\\d\+\\\]\\\//)
    assert.match(replayer, /mat-dialog-container\\\[@id=/)
    assert.match(replayer, /const dialogSegment = xpath\.match/)
    assert.match(replayer, /XPathResult\.ORDERED_NODE_SNAPSHOT_TYPE/)
    assert.match(replayer, /this\.resolveInteractableElement\(this\.normalizeElement\(result\.snapshotItem\(index\)\)\)/)
    assert.match(replayer, /return candidates\.length === 1 \? candidates\[0\] : null/)
})

test('initial replay navigation preserves an already-open target and its SPA root alias', async () => {
    const replayer = await fs.readFile('security/ptk/content/replayer.js', 'utf8')
    assert.match(replayer, /function initialReplayDestinationMatchesCurrent\(rawUrl\)/)
    assert.match(replayer, /const rootHashes = new Set\(\['', '#', '#\/', '#\/\?'\]\)/)
    assert.match(replayer, /const destinationMatches = initialReplayDestinationMatchesCurrent\(item\.Data\)/)
    assert.match(replayer, /else if \(!destinationMatches\)[\s\S]*?window\.location\.href = item\.Data/)
})

test('optional producer helpers use a bounded replay timeout', async () => {
    const [replayer, chromeAdapter, sideAdapter] = await Promise.all([
        fs.readFile('security/ptk/content/replayer.js', 'utf8'),
        fs.readFile('security/ptk/background/macro/chromeRecorderAdapter.js', 'utf8'),
        fs.readFile('security/ptk/background/macro/sideAdapter.js', 'utf8')
    ])
    assert.match(replayer, /if \(!this\.isRequiredStep\(item\)\) return 1500/)
    assert.match(chromeAdapter, /source\?\.ptkOptional === true \? 1500 : 30000/)
    assert.match(sideAdapter, /const optional = command\?\.ptkOptional === true \|\| name === 'mouseOver'/)
    assert.match(sideAdapter, /timeoutMs: optional \? 1500 : 30000/)
})

test('replay promotes a non-interactable recorded child to its interactable control ancestor', async () => {
    const replayer = await fs.readFile('security/ptk/content/replayer.js', 'utf8')
    assert.match(replayer, /const el = interactable \? this\.resolveInteractableElement\(located\) : located/)
    assert.match(replayer, /element\.closest\?\.\('button,a,input,textarea,select,\[role="button"\]'\)/)
    assert.match(replayer, /return control && this\.isInteractable\(control\) \? control : null/)
    assert.match(replayer, /exactIdPresent: Boolean\(exactId\)/)
    assert.match(replayer, /exactIdInteractable: Boolean\(this\.resolveInteractableElement\(exactId\)\)/)
})

test('DriverClick uses the debugger only when the recorded target owns its screen point', async () => {
    const replayer = await fs.readFile('security/ptk/content/replayer.js', 'utf8')
    assert.match(replayer, /const targetAtPoint = this\.isTargetAtClickPoint\(target\)/)
    assert.match(replayer, /if \(point && targetAtPoint\)/)
    assert.match(replayer, /click_dom_fallback_obscured/)
    assert.match(replayer, /root\.elementFromPoint\(x, y\)/)
    assert.match(replayer, /element\.contains\?\.\(hit\)/)
    assert.match(replayer, /const menuToggleWasClosed = target\.getAttribute\?\.\('aria-haspopup'\) === 'menu'/)
    assert.match(replayer, /target\.getAttribute\?\.\('aria-expanded'\) === 'false'/)
    assert.match(replayer, /target\.click\?\.\(\)/)
    assert.match(replayer, /const owningDialog = target\.closest\?\.\('mat-dialog-container,\[role="dialog"\],dialog'\)/)
    assert.match(replayer, /const isDialogClose = Boolean\(owningDialog\)/)
    assert.match(replayer, /if \(isDialogClose && owningDialog\?\.isConnected && target\.isConnected\)/)
    assert.match(replayer, /const isMenuTrigger = control\.getAttribute\?\.\('aria-haspopup'\) === 'menu'/)
    assert.match(replayer, /if \(isMenuTrigger && control\.getAttribute\?\.\('aria-expanded'\) === 'true'\)/)
})

test('a cancelled in-page replayer can be replaced without reloading the target', async () => {
    const [replayer, tracker, recorder] = await Promise.all([
        fs.readFile('security/ptk/content/replayer.js', 'utf8'),
        fs.readFile('security/ptk/content/tracker.js', 'utf8'),
        fs.readFile('security/ptk/background/recorder.js', 'utf8')
    ])
    assert.match(replayer, /window\.__ptkReplayerRuntime\?\.create/)
    assert.match(replayer, /current\.cancelled \|\| current\.step < 0/)
    assert.match(replayer, /window\.ptk_replayer = window\.__ptkReplayerRuntime\.create\(\)/)
    assert.equal((replayer.match(/window\.addEventListener\("message"/g) || []).length, 1)
    assert.equal((replayer.match(/browser\.runtime\.onMessage\.addListener/g) || []).length, 1)
    assert.match(tracker, /if \(recordingStopped \|\| replayStopped\)[\s\S]*?removeListener\(trackerStorageListener\)[\s\S]*?return/)
    assert.match(tracker, /type:\s*"stop_replay",\s*sessionId:\s*activeSession\.sessionId/)
    assert.match(recorder, /message\?\.sessionId && message\.sessionId !== this\.sessionId/)
    assert.match(recorder, /error:\s*'stale_replay_session'/)
})

test('popup drag binding tolerates asynchronous overlay creation and repeated injection', async () => {
    const source = await fs.readFile('security/ptk/content/popup.js', 'utf8')
    const nodes = new Map()
    const windowListeners = new Map()
    const windowObject = {
        addEventListener(type, listener) {
            if (!windowListeners.has(type)) windowListeners.set(type, new Set())
            windowListeners.get(type).add(listener)
        },
        removeEventListener(type, listener) {
            windowListeners.get(type)?.delete(listener)
        }
    }
    const context = {
        document: { getElementById: (id) => nodes.get(id) || null },
        window: windowObject
    }

    assert.doesNotThrow(() => vm.runInNewContext(source, context))
    assert.equal(typeof windowObject.__ptkBindRecordingPopupDrag, 'function')
    assert.equal(windowObject.__ptkBindRecordingPopupDrag(), false)

    const handleListeners = new Map()
    const control = {
        isConnected: true,
        offsetLeft: 10,
        offsetTop: 20,
        style: {}
    }
    const handle = {
        dataset: {},
        addEventListener(type, listener) {
            if (!handleListeners.has(type)) handleListeners.set(type, new Set())
            handleListeners.get(type).add(listener)
        }
    }
    nodes.set('ptk_recording_control', control)
    nodes.set('ptk_recording_control_icons', handle)

    assert.equal(windowObject.__ptkBindRecordingPopupDrag(), true)
    assert.equal(windowObject.__ptkBindRecordingPopupDrag(), true)
    assert.equal(handleListeners.get('mousedown')?.size, 1)
    const mouseDown = [...handleListeners.get('mousedown')][0]
    mouseDown({ clientX: 25, clientY: 45 })
    assert.equal(windowListeners.get('mousemove')?.size, 1)
    ;[...windowListeners.get('mousemove')][0]({ clientX: 50, clientY: 80 })
    assert.deepEqual(control.style, { position: 'fixed', top: '55px', left: '35px' })
    ;[...windowListeners.get('mouseup')][0]()
    assert.equal(windowListeners.get('mousemove')?.size, 0)
    assert.equal(windowListeners.get('mouseup')?.size, 0)

    const tracker = await fs.readFile('security/ptk/content/tracker.js', 'utf8')
    assert.match(tracker, /appendChild\(popupHtml\)[\s\S]*?__ptkBindRecordingPopupDrag\(\)/)
})

test('scan-owned replay keeps full runtime values out of persistent replay storage', async () => {
    const [replayer, recorder] = await Promise.all([
        fs.readFile('security/ptk/content/replayer.js', 'utf8'),
        fs.readFile('security/ptk/background/recorder.js', 'utf8')
    ])
    assert.match(recorder, /const persistedReplayItems = scanOwned[\s\S]*?items\.map\(replayItemSummary\)[\s\S]*?"ptk_replay_items": persistedReplayItems/)
    assert.doesNotMatch(
        recorder.match(/function replayItemSummary[\s\S]*?\n}/)?.[0] || '',
        /\bData\b|EncryptedData|targetOptions|\btarget\b/
    )
    assert.match(recorder, /async msg_get_replay_payload\(message, sender\)/)
    assert.match(recorder, /!this\.scanOwnedReplay \|\| !Array\.isArray\(this\.replay\?\.replayEvents\)/)
    assert.match(recorder, /!this\.isTracking\(tabId\)/)
    assert.match(recorder, /!this\.isReplayUrlInScope\(tab\.url\)/)
    assert.match(replayer, /type: 'get_replay_payload'/)
    assert.match(replayer, /result\.ptk_replay\?\.scanOwned === true[\s\S]*?replayItems = payload\.items/)
    assert.match(replayer, /result\.ptk_replay\?\.scanOwned === true[\s\S]*?\? this\.items/)
})

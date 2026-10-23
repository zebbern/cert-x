// Imported PTK v10 regression; paths adapted to the owned cert-x subsystem.
import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import test from 'node:test'
import { parse } from '../../../security/ptk/background/sast/acorn/acorn.mjs'

import {
    PTK_FLOW_SCHEMA,
    PtkFlowError,
    compileFlow,
    locatorFromString,
    normalizeFlow,
    safeParseMacroJson
} from '../../../security/ptk/background/macro/flow.js'
import {
    detectMacroFormat,
    groupMacroDiagnostics,
    listMacroFormats,
    macroDownloadName,
    parseMacroDocument,
    serializeMacroDocument
} from '../../../security/ptk/background/macro/formatRegistry.js'

const fixture = (name) => fs.readFile(new URL(`./fixtures/macro/${name}`, import.meta.url), 'utf8')

test('legacy Selenium and Katalon link targets normalize as link text', () => {
    assert.deepEqual(locatorFromString('link=OWASP Juice Shop'), {
        type: 'linkText',
        value: 'OWASP Juice Shop'
    })
})

function representativeFlow() {
    return normalizeFlow({
        schema: PTK_FLOW_SCHEMA,
        metadata: { name: 'Representative login' },
        startUrl: 'http://localhost:3001/#/login',
        variables: [{ name: 'PASSWORD', secret: true }],
        steps: [
            {
                id: 'step-0001', type: 'navigate', enabled: true, optional: false,
                durationMs: 100, timeoutMs: 30000, window: { index: 0, handle: 'main' },
                frameChain: [], locators: [], data: null, url: 'http://localhost:3001/#/login'
            },
            {
                id: 'step-0002', type: 'fill', enabled: true, optional: false,
                durationMs: 100, timeoutMs: 5000, window: { index: 0, handle: 'main' },
                frameChain: [], locators: [{ type: 'id', value: 'passwordControl' }],
                data: { kind: 'secret', name: 'PASSWORD' }
            },
            {
                id: 'step-0003', type: 'click', enabled: true, optional: false,
                durationMs: 100, timeoutMs: 5000, window: { index: 0, handle: 'main' },
                frameChain: [], locators: [{ type: 'css', value: 'button[type=submit]' }], data: null
            },
            {
                id: 'step-0004', type: 'delay', enabled: true, optional: false,
                durationMs: 250, timeoutMs: 0, window: { index: 0, handle: 'main' },
                frameChain: [], locators: [], data: null
            }
        ]
    })
}

function exportContractFlow() {
    const steps = []
    const add = (step) => steps.push({
        id: `step-${String(steps.length + 1).padStart(4, '0')}`,
        enabled: true,
        optional: false,
        durationMs: 0,
        timeoutMs: 5000,
        window: { index: 0, handle: 'main' },
        frameChain: [],
        locators: [],
        data: null,
        ...step
    })
    add({ type: 'comment', comment: 'Sanitized export contract fixture' })
    add({ type: 'navigate', url: 'https://example.invalid/' })
    for (let index = 0; index < 17; index += 1) {
        add({
            type: 'scroll',
            optional: true,
            scrollMode: 'intoView',
            locators: index < 9
                ? [{ type: 'xpath', value: `//main/div[${index + 1}]` }]
                : [{ type: 'css', value: `.scroll-helper-${index + 1}` }]
        })
    }
    for (let index = 0; index < 9; index += 1) {
        add({ type: 'click', locators: [{ type: 'xpath', value: `//button[${index + 1}]` }] })
    }
    add({ type: 'submit', locators: [{ type: 'css', value: 'form#login' }] })
    for (let index = 0; index < 3; index += 1) {
        add({ type: 'fill', locators: [{ type: 'css', value: `#field-${index + 1}` }], data: { kind: 'literal', value: `value-${index + 1}` } })
    }
    for (let index = 0; index < 2; index += 1) {
        add({ type: 'click', optional: true, locators: [{ type: 'css', value: `.prepare-${index + 1}` }] })
    }
    for (let index = 0; index < 2; index += 1) {
        add({ type: 'click', locators: [{ type: 'css', value: `.finish-${index + 1}` }] })
    }
    return normalizeFlow({
        schema: PTK_FLOW_SCHEMA,
        metadata: { name: 'Export contract', sourceFormat: 'zest' },
        startUrl: 'https://example.invalid/',
        variables: [],
        steps
    })
}

test('format registry exposes only real import and export capabilities', () => {
    const formats = listMacroFormats()
    assert.deepEqual(formats.map((entry) => entry.id), [
        'ptk-flow', 'xml', 'zest', 'side', 'chrome-recorder',
        'playwright', 'puppeteer', 'selenium-webdriver', 'cypress'
    ])
    for (const id of ['playwright', 'puppeteer', 'selenium-webdriver', 'cypress']) {
        const format = formats.find((entry) => entry.id === id)
        assert.equal(format.canImport, false)
        assert.equal(format.readOnly, true)
    }
})

test('export diagnostics group repeated optional loss and block only required loss', () => {
    const flow = exportContractFlow()
    assert.equal(flow.steps.length, 36)

    const side = serializeMacroDocument(flow, 'side')
    assert.deepEqual(side.summary, {
        sourceSteps: 36,
        preservedSteps: 19,
        requiredOmitted: 0,
        optionalOmitted: 17,
        disabledOmitted: 0,
        informationalOmitted: 0,
        errors: 0,
        warnings: 17,
        info: 0
    })
    assert.equal(side.diagnosticGroups.length, 1)
    assert.equal(side.diagnosticGroups[0].level, 'warning')
    assert.equal(side.diagnosticGroups[0].stepType, 'scroll')
    assert.equal(side.diagnosticGroups[0].count, 17)
    assert.equal(side.diagnosticGroups[0].visibleStepIds.length, 3)
    assert.equal(side.diagnosticGroups[0].hiddenStepIds.length, 14)

    const chrome = serializeMacroDocument(flow, 'chrome-recorder')
    assert.equal(chrome.summary.requiredOmitted, 1)
    assert.equal(chrome.summary.optionalOmitted, 17)
    assert.equal(chrome.summary.informationalOmitted, 1)
    assert.deepEqual(chrome.diagnosticGroups.map((group) => [group.level, group.stepType, group.count]), [
        ['error', 'submit', 1],
        ['warning', 'scroll', 17],
        ['info', 'comment', 1]
    ])

    const cypress = serializeMacroDocument(flow, 'cypress')
    assert.equal(cypress.summary.requiredOmitted, 9)
    assert.equal(cypress.summary.optionalOmitted, 9)
    assert.deepEqual(cypress.diagnosticGroups.map((group) => [group.level, group.code, group.stepType, group.count]), [
        ['error', 'cypress_locator_unsupported', 'click', 9],
        ['warning', 'cypress_locator_unsupported', 'scroll', 9]
    ])

    for (const format of ['ptk-flow', 'xml', 'zest', 'playwright', 'puppeteer', 'selenium-webdriver']) {
        const result = serializeMacroDocument(flow, format)
        assert.deepEqual(result.diagnostics, [], format)
        assert.equal(result.summary.preservedSteps, 36, format)
    }
})

test('diagnostic grouping is stable by severity, code, and step type', () => {
    const grouped = groupMacroDiagnostics([
        { level: 'warning', code: 'same', stepType: 'scroll', message: 'Skipped', stepId: 'step-4' },
        { level: 'error', code: 'same', stepType: 'click', message: 'Blocked', stepId: 'step-2' },
        { level: 'warning', code: 'same', stepType: 'scroll', message: 'Skipped', stepId: 'step-5' }
    ], { visibleStepLimit: 1 })
    assert.deepEqual(grouped.map((group) => [group.level, group.stepType, group.count]), [
        ['error', 'click', 1],
        ['warning', 'scroll', 2]
    ])
    assert.deepEqual(grouped[1].visibleStepIds, ['step-4'])
    assert.deepEqual(grouped[1].hiddenStepIds, ['step-5'])
})

test('safe JSON and PTK Flow validation reject pollution, schemes, duplicates, and limits', () => {
    assert.throws(() => safeParseMacroJson('{"__proto__":{"polluted":true}}'), (error) => error.code === 'pollution_key')
    const flow = representativeFlow()
    assert.throws(() => normalizeFlow({ ...flow, startUrl: 'file:///tmp/demo' }), (error) => error.code === 'unsupported_url_scheme')
    assert.throws(() => normalizeFlow({ ...flow, steps: [flow.steps[0], { ...flow.steps[0] }] }), (error) => error.code === 'duplicate_step_id')
    assert.throws(() => normalizeFlow({ ...flow, variables: [...flow.variables, flow.variables[0]] }), (error) => error.code === 'duplicate_variable_name')
    assert.throws(() => normalizeFlow({ ...flow, variables: [] }), (error) => error.code === 'undeclared_variable')
    assert.throws(() => normalizeFlow({ ...flow, variables: [{ name: 'PASSWORD', secret: false }] }), (error) => error.code === 'variable_kind_mismatch')
    assert.throws(() => safeParseMacroJson(JSON.stringify({ value: 'x'.repeat(1024 * 1024 + 1) })), (error) => error.code === 'string_too_large')
})

test('XML parser rejects entity declarations and safely round trips CDATA terminators', () => {
    const malicious = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><MacroEventList></MacroEventList>'
    assert.throws(() => parseMacroDocument(malicious, { format: 'xml' }), (error) => error.code === 'unsafe_xml')

    const candidate = representativeFlow()
    candidate.steps[1].data = { kind: 'literal', value: 'safe]]>value' }
    candidate.steps[1].locators = [{ type: 'id', value: 'notesControl' }]
    candidate.variables = []
    const exported = serializeMacroDocument(candidate, 'xml')
    assert.match(exported.text, /\]\]\]\]>\<!\[CDATA\[>/)
    const reparsed = parseMacroDocument(exported.text, { format: 'xml' })
    assert.equal(reparsed.flow.steps[1].data.value, 'safe]]>value')
})

test('unsupported enabled commands block import instead of becoming comments or disappearing', () => {
    const side = JSON.stringify({
        id: 'unsupported', version: '3.17.0', name: 'Unsupported', url: 'https://example.invalid',
        tests: [{ id: 'test', name: 'Test', commands: [{ id: 'run', command: 'runScript', target: 'alert(1)', targets: [], value: '' }] }],
        suites: [], urls: ['https://example.invalid'], plugins: []
    })
    const sideResult = parseMacroDocument(side, { format: 'side' })
    assert.equal(sideResult.acceptable, false)
    assert.equal(sideResult.flow.steps.some((step) => step.type === 'comment'), false)
    assert.equal(sideResult.diagnostics.some((entry) => entry.code === 'unsupported_side_command' && entry.level === 'error'), true)

    const chrome = JSON.stringify({ title: 'Unsupported close', steps: [{ type: 'close', target: 'main' }] })
    const chromeResult = parseMacroDocument(chrome, { format: 'chrome-recorder' })
    assert.equal(chromeResult.acceptable, false)
    assert.equal(chromeResult.flow.steps.length, 0)
    assert.equal(chromeResult.diagnostics.some((entry) => entry.code === 'chrome_close_unsupported'), true)

    const zest = JSON.stringify({
        zestVersion: '0.3', title: 'Two windows', description: '', elementType: 'ZestScript',
        statements: [
            { elementType: 'ZestClientLaunch', url: 'https://example.invalid/a', windowHandle: 'one', enabled: true },
            { elementType: 'ZestClientElementClick', type: 'cssSelector', element: '#go', windowHandle: 'two', enabled: true }
        ]
    })
    const zestResult = parseMacroDocument(zest, { format: 'zest' })
    assert.equal(zestResult.acceptable, false)
    assert.equal(zestResult.diagnostics.some((entry) => entry.code === 'zest_multiple_windows_unsupported'), true)
})

test('Selenium IDE mouseOut helpers are omitted without blocking executable commands', () => {
    const side = JSON.stringify({
        id: 'pointer-helpers', version: '2.0', name: 'Pointer helpers', url: 'http://localhost:3001/',
        tests: [{
            id: 'test', name: 'Test', commands: [
                { id: 'open', command: 'open', target: '/', targets: [], value: '' },
                { id: 'over', command: 'mouseOver', target: 'id=navbarAccount', targets: [], value: '' },
                { id: 'out', command: 'mouseOut', target: 'id=navbarAccount', targets: [], value: '' },
                { id: 'click', command: 'click', target: 'id=navbarAccount', targets: [], value: '' }
            ]
        }],
        suites: [], urls: ['http://localhost:3001/'], plugins: []
    })
    const imported = parseMacroDocument(side, { format: 'side' })
    assert.equal(imported.acceptable, true, JSON.stringify(imported.diagnostics))
    assert.deepEqual(imported.flow.steps.map((step) => step.type), ['navigate', 'hover', 'click'])
    assert.equal(imported.flow.steps[1].optional, true)
    assert.equal(imported.flow.steps[2].optional, false)
    assert.equal(imported.diagnostics.some((entry) => (
        entry.code === 'side_mouseout_collapsed' && entry.level === 'info' && entry.stepId === 'step-0003'
    )), true)
})

test('Selenium IDE focus-state clicks prefer the preceding structural pointer target', () => {
    const side = JSON.stringify({
        id: 'focus-click', version: '2.0', name: 'Focus click', url: 'http://localhost:3001/',
        tests: [{
            id: 'test', name: 'Test', commands: [
                { id: 'open', command: 'open', target: '/', targets: [], value: '' },
                {
                    id: 'over', command: 'mouseOver',
                    target: 'css=.mat-grid-tile:nth-child(1) button[aria-label="Add to Basket"]',
                    targets: [['css=.mat-grid-tile:nth-child(1) button[aria-label="Add to Basket"]', 'css:finder']],
                    value: ''
                },
                { id: 'out', command: 'mouseOut', target: 'css=.product', targets: [], value: '' },
                {
                    id: 'click', command: 'click', target: 'css=.cdk-focused > .mdc-button__label > span',
                    targets: [['css=.cdk-focused > .mdc-button__label > span', 'css:finder']], value: ''
                }
            ]
        }],
        suites: [], urls: ['http://localhost:3001/'], plugins: []
    })
    const imported = parseMacroDocument(side, { format: 'side' })
    assert.equal(imported.acceptable, true, JSON.stringify(imported.diagnostics))
    const click = imported.flow.steps.find((step) => step.type === 'click')
    assert.equal(click.locators[0].value, '.mat-grid-tile:nth-child(1) button[aria-label="Add to Basket"]')
    assert.equal(click.locators.some((locator) => locator.value.includes('.cdk-focused')), true)
})

test('XML compatibility imports legacy event names and round trips without secret disclosure', async () => {
    const input = await fixture('legacy-login.rec')
    assert.equal(detectMacroFormat(input, 'legacy-login.rec').id, 'xml')
    const imported = parseMacroDocument(input, { fileName: 'legacy-login.rec' })
    assert.equal(imported.acceptable, true)
    assert.deepEqual(imported.flow.steps.map((step) => step.type), ['navigate', 'click'])
    const exported = serializeMacroDocument(representativeFlow(), 'xml')
    assert.match(exported.text, /<EventType>DriverSetControlValue<\/EventType>/)
    assert.match(exported.text, /\$\{PTK_SECRET:PASSWORD\}/)
    assert.doesNotMatch(exported.text, /real-password/i)
    const reparsed = parseMacroDocument(exported.text, { format: 'xml' })
    assert.equal(reparsed.flow.steps[1].data.kind, 'secret')
})

test('Zest, Selenium IDE, and Chrome Recorder fixtures normalize into PTK Flow', async () => {
    const cases = [
        ['zest-client-login.zst', 'zest'],
        ['selenium-login.side', 'side'],
        ['chrome-recorder-login.json', 'chrome-recorder']
    ]
    for (const [name, expectedFormat] of cases) {
        const input = await fixture(name)
        const imported = parseMacroDocument(input, { fileName: name })
        assert.equal(imported.format, expectedFormat)
        assert.equal(imported.acceptable, true, `${expectedFormat}: ${JSON.stringify(imported.diagnostics)}`)
        assert.equal(imported.flow.schema, PTK_FLOW_SCHEMA)
        assert.equal(imported.flow.steps.some((step) => step.type === 'navigate'), true)
        assert.equal(imported.flow.steps.some((step) => step.type === 'click'), true)
        assert.equal(imported.flow.steps.some((step) => step.data?.kind === 'secret'), true)
        assert.equal(JSON.stringify(imported.flow).includes('real-password'), false)
    }
})

test('Chrome Recorder key events inherit the focused locator in the same target', () => {
    const input = JSON.stringify({
        title: 'Focused search',
        steps: [
            { type: 'navigate', url: 'http://localhost:3001/' },
            { type: 'click', target: 'main', selectors: [['#search']] },
            { type: 'change', target: 'main', selectors: [['#search']], value: 'test' },
            { type: 'keyDown', target: 'main', key: 'Enter' },
            { type: 'keyUp', target: 'main', key: 'Enter' }
        ]
    })
    const imported = parseMacroDocument(input, { format: 'chrome-recorder' })
    assert.equal(imported.acceptable, true, JSON.stringify(imported.diagnostics))
    const key = imported.flow.steps.find((step) => step.type === 'keyPress')
    assert.deepEqual(key.locators, [{ type: 'css', value: '#search' }])
    assert.equal(key.data.value, '${KEY_ENTER}')
    assert.equal(imported.diagnostics.some((entry) => entry.code === 'chrome_keyup_collapsed' && entry.level === 'info'), true)
})

test('Chrome Recorder key events without a focused locator are rejected explicitly', () => {
    const input = JSON.stringify({
        title: 'Unfocused key',
        steps: [
            { type: 'navigate', url: 'http://localhost:3001/' },
            { type: 'keyDown', target: 'main', key: 'Enter' }
        ]
    })
    const imported = parseMacroDocument(input, { format: 'chrome-recorder' })
    assert.equal(imported.acceptable, false)
    assert.equal(imported.diagnostics.some((entry) => entry.code === 'chrome_key_target_missing' && entry.level === 'error'), true)
})

test('Chrome Recorder chains are not flattened into independently matching wrapper locators', () => {
    const selectors = [
        ['aria/Click to search', 'aria/[role="textbox"]'],
        ['#search-input'],
        ['xpath//input[@id="search-input"]']
    ]
    const imported = parseMacroDocument(JSON.stringify({
        title: 'Chained search',
        steps: [
            { type: 'navigate', url: 'http://localhost:3001/' },
            { type: 'click', selectors },
            { type: 'change', selectors, value: 'test' },
            { type: 'keyDown', key: 'Enter' }
        ]
    }), { format: 'chrome-recorder' })
    assert.equal(imported.acceptable, true)
    const expected = [
        { type: 'css', value: '#search-input' },
        { type: 'xpath', value: '/input[@id="search-input"]' }
    ]
    for (const step of imported.flow.steps.slice(1)) assert.deepEqual(step.locators, expected)
    assert.equal(imported.diagnostics.filter(entry => entry.code === 'chrome_selector_chain_unsupported').length, 2)
    const events = compileFlow(imported.flow).events.slice(1)
    for (const event of events) {
        assert.equal(event.target, 'css=#search-input')
        assert.equal(JSON.stringify(event.targetOptions).includes('aria/Click to search'), false)
    }
})

test('Chrome Recorder chain-only targeted steps are rejected, not redirected to prior focus', () => {
    for (const type of ['click', 'doubleClick', 'hover', 'change', 'waitForElement', 'keyDown']) {
        const imported = parseMacroDocument(JSON.stringify({
            title: 'Unsupported chain',
            steps: [
                { type: 'navigate', url: 'http://localhost:3001/' },
                { type: 'click', selectors: [['#previous-input']] },
                { type, selectors: [['#wrapper', '#child']], value: 'test', key: 'Enter' }
            ]
        }), { format: 'chrome-recorder' })
        assert.equal(imported.acceptable, false, type)
        assert.equal(imported.diagnostics.some(entry => entry.code === 'chrome_selector_chain_unsupported' && entry.level === 'error'), true, type)
    }
})

test('Chrome Recorder preserves complete single-selector order and does not leak chain prefixes', () => {
    const imported = parseMacroDocument(JSON.stringify({
        title: 'Complete alternatives',
        steps: [
            { type: 'navigate', url: 'http://localhost:3001/' },
            { type: 'click', selectors: [['aria/Save'], ['#shadow-host', '#nested'], ['#save'], ['#save']] }
        ]
    }), { format: 'chrome-recorder' })
    assert.equal(imported.acceptable, true)
    assert.deepEqual(imported.flow.steps[1].locators, [
        { type: 'aria', value: 'Save' },
        { type: 'css', value: '#save' }
    ])
})

test('Chrome Recorder release search targets the input for click, fill and inherited Enter', async () => {
    const input = await fixture('juice-shop/recordings/chrome-recorder.json')
    const imported = parseMacroDocument(input, { format: 'chrome-recorder' })
    assert.equal(imported.acceptable, true)
    const fill = imported.flow.steps.findIndex(step => step.type === 'fill' && step.data?.value === 'test')
    assert.ok(fill > 0)
    for (const step of imported.flow.steps.slice(fill - 1, fill + 2)) {
        assert.equal(step.locators[0].type, 'css')
        assert.equal(step.locators[0].value, '#mat-input-1')
        assert.equal(step.locators.some(locator => locator.type === 'aria'), false)
    }
})

test('Katalon Recorder TestCase XML imports as bounded Selenium XML with literal values', async () => {
    const input = await fixture('katalon-juice-shop.xml')
    assert.equal(detectMacroFormat(input, 'juice-shop.xml').id, 'xml')
    const imported = parseMacroDocument(input, { fileName: 'juice-shop.xml' })
    assert.equal(imported.acceptable, true, JSON.stringify(imported.diagnostics))
    assert.equal(imported.flow.metadata.sourceFormat, 'selenium-xml')
    assert.deepEqual(imported.flow.steps.map((step) => step.type), ['navigate', 'fill', 'fill', 'click'])
    assert.equal(imported.flow.steps[2].data.kind, 'literal')
    assert.equal(imported.flow.steps[2].data.value, 'fixture-password-value')
    assert.deepEqual(Object.keys(imported.secretValues || {}), [])
    assert.equal(imported.diagnostics.some((entry) => entry.code === 'selenium_xml_detected'), true)
    const compiled = compileFlow(imported.flow, { elementPath: 'id' })
    assert.equal(compiled.events[2].Data, 'fixture-password-value')
    assert.equal(compiled.events[2].ElementPath, 'id=password')
})

test('Katalon Recorder XML blocks unsupported required Selenese commands', () => {
    const input = `<?xml version="1.0"?><TestCase>
        <selenese><command>open</command><target>https://example.invalid/</target><value></value></selenese>
        <selenese><command>runScript</command><target>alert(1)</target><value></value></selenese>
    </TestCase>`
    const imported = parseMacroDocument(input, { fileName: 'unsupported.xml' })
    assert.equal(imported.acceptable, false)
    assert.equal(imported.diagnostics.some((entry) => entry.code === 'unsupported_side_command' && entry.level === 'error'), true)
    assert.equal(imported.flow.steps.some((step) => step.type === 'comment'), false)
})

test('external Angular dialog XPath keeps the producer value and gains stable structural fallbacks', () => {
    const input = `<?xml version="1.0"?><TestCase>
        <selenese><command>open</command><target>http://localhost:3001/#/</target><value></value></selenese>
        <selenese><command>click</command><target>//mat-dialog-container[@id='mat-mdc-dialog-12']/div/app-welcome-banner/button</target><value></value></selenese>
    </TestCase>`
    const imported = parseMacroDocument(input, { fileName: 'dialog.xml' })
    const locators = imported.flow.steps[1].locators.map((locator) => locator.value)
    assert.deepEqual(locators, [
        "//mat-dialog-container[@id='mat-mdc-dialog-12']/div/app-welcome-banner/button",
        '//mat-dialog-container/div/app-welcome-banner/button'
    ])
})

test('external formats preserve explicit PTK optional-step metadata without weakening other actions', () => {
    const documents = [{
        format: 'zest',
        text: JSON.stringify({
            zestVersion: '0.3', title: 'Optional', elementType: 'ZestScript', statements: [
                { elementType: 'ZestClientLaunch', url: 'http://localhost:3001/', windowHandle: 'main' },
                { elementType: 'ZestClientElementClick', type: 'id', element: 'dismiss', windowHandle: 'main', ptkOptional: true },
                { elementType: 'ZestClientElementClick', type: 'id', element: 'required', windowHandle: 'main' }
            ]
        })
    }, {
        format: 'side',
        text: JSON.stringify({
            id: 'optional', version: '2.0', name: 'Optional', url: 'http://localhost:3001/',
            tests: [{ id: 'test', name: 'test', commands: [
                { id: 'open', command: 'open', target: '/', targets: [], value: '' },
                { id: 'dismiss', command: 'click', target: 'id=dismiss', targets: [], value: '', ptkOptional: true },
                { id: 'required', command: 'click', target: 'id=required', targets: [], value: '' }
            ] }], suites: [], urls: [], plugins: []
        })
    }, {
        format: 'chrome-recorder',
        text: JSON.stringify({ title: 'Optional', steps: [
            { type: 'navigate', url: 'http://localhost:3001/' },
            { type: 'click', target: 'main', selectors: [['#dismiss']], ptkOptional: true },
            { type: 'click', target: 'main', selectors: [['#required']] }
        ] })
    }, {
        format: 'xml',
        text: `<?xml version="1.0"?><TestCase>
            <selenese><command>open</command><target>http://localhost:3001/</target><value></value></selenese>
            <selenese><command>click</command><target>id=dismiss</target><value></value><ptkOptional>true</ptkOptional></selenese>
            <selenese><command>click</command><target>id=required</target><value></value></selenese>
        </TestCase>`
    }]
    for (const document of documents) {
        const parsed = parseMacroDocument(document.text, { format: document.format })
        assert.equal(parsed.acceptable, true, `${document.format}: ${JSON.stringify(parsed.diagnostics)}`)
        const clicks = parsed.flow.steps.filter((step) => step.type === 'click')
        assert.equal(clicks[0].optional, true, document.format)
        assert.equal(clicks[1].optional, false, document.format)
    }
})

test('Zest scroll assistance is optional and external XPath keeps one-based predicates', async () => {
    const input = await fixture('zest-client-login.zst')
    const imported = parseMacroDocument(input, { fileName: 'zest-client-login.zst' })
    const scroll = imported.flow.steps.find((step) => step.type === 'scroll')
    assert.ok(scroll)
    assert.equal(scroll.optional, true)
    assert.equal(scroll.scrollMode, 'intoView')

    const compiled = compileFlow(imported.flow, { secrets: { PASSWORD: 'runtime-only' } })
    const runtimeScroll = compiled.events.find((event) => event.EventType === 'Scroll')
    assert.ok(runtimeScroll)
    assert.equal(runtimeScroll.PtkXPathIndexBase, 1)

    const replayer = await fs.readFile(new URL('../../../security/ptk/content/replayer.js', import.meta.url), 'utf8')
    assert.match(replayer, /const externalXpath = Number\(item\?\.PtkXPathIndexBase\) === 1/)
    assert.match(replayer, /if \(!externalXpath\) \{/)
    assert.match(replayer, /getElementByLocator\(locator, item\)/)
})

test('PTK Flow distinguishes visibility, absolute, and relative scroll semantics', () => {
    const base = representativeFlow()
    const scrollSteps = [
        {
            id: 'scroll-into-view', type: 'scroll', enabled: true, optional: true,
            durationMs: 0, timeoutMs: 5000, window: { index: 0, handle: 'main' },
            frameChain: [], locators: [{ type: 'id', value: 'later-control' }], data: null
        },
        {
            id: 'legacy-located-scroll', type: 'scroll', enabled: true, optional: true,
            durationMs: 0, timeoutMs: 5000, window: { index: 0, handle: 'main' },
            frameChain: [], locators: [{ type: 'css', value: '#legacy-control' }], data: null,
            x: 0, y: 240
        },
        {
            id: 'scroll-absolute', type: 'scroll', enabled: true, optional: false,
            durationMs: 0, timeoutMs: 5000, window: { index: 0, handle: 'main' },
            frameChain: [], locators: [], data: null, x: 10, y: 200
        },
        {
            id: 'scroll-relative', type: 'scroll', scrollMode: 'by', enabled: true, optional: false,
            durationMs: 0, timeoutMs: 5000, window: { index: 0, handle: 'main' },
            frameChain: [], locators: [{ type: 'css', value: '#results' }], data: null, x: -4, y: 75
        }
    ]
    const flow = normalizeFlow({ ...base, variables: [], steps: [base.steps[0], ...scrollSteps] })
    assert.deepEqual(flow.steps.slice(1).map((step) => step.scrollMode), ['intoView', 'intoView', 'to', 'by'])

    const compiled = compileFlow(flow)
    assert.deepEqual(compiled.events.slice(1).map((event) => event.PtkScrollMode), ['intoView', 'intoView', 'to', 'by'])
    assert.equal(compiled.events[3].Data, '10,200')
    assert.equal(compiled.events[4].Data, '-4,75')
    assert.throws(() => normalizeFlow({
        ...base,
        variables: [],
        steps: [{ ...scrollSteps[3], id: 'invalid-relative', locators: [] }]
    }), (error) => error.code === 'missing_scroll_locator')
    assert.throws(() => normalizeFlow({
        ...base,
        variables: [],
        steps: [{ ...scrollSteps[3], id: 'invalid-mode', scrollMode: 'around' }]
    }), (error) => error.code === 'unsupported_scroll_mode')
})

test('both official Zest client scroll statements round trip without semantic loss', () => {
    const source = JSON.stringify({
        zestVersion: '0.3', title: 'Scroll contract', elementType: 'ZestScript',
        statements: [
            { elementType: 'ZestClientLaunch', url: 'https://example.invalid/', windowHandle: 'main', enabled: true },
            { elementType: 'ZestClientElementScrollTo', type: 'id', element: 'later-control', windowHandle: 'main', waitForMsec: 5000, enabled: true },
            { elementType: 'ZestClientElementScroll', type: 'cssSelector', element: '#results', x: -8, y: 140, windowHandle: 'main', waitForMsec: 7000, enabled: true }
        ]
    })
    const imported = parseMacroDocument(source, { format: 'zest' })
    assert.equal(imported.acceptable, true)
    assert.deepEqual(imported.flow.steps.slice(1).map((step) => [step.scrollMode, step.optional, step.x, step.y]), [
        ['intoView', true, undefined, undefined],
        ['by', false, -8, 140]
    ])

    const exported = serializeMacroDocument(imported.flow, 'zest')
    assert.deepEqual(exported.diagnostics, [])
    const statements = JSON.parse(exported.text).statements
    assert.deepEqual(statements.slice(1).map((statement) => [statement.elementType, statement.type, statement.element, statement.x, statement.y]), [
        ['ZestClientElementScrollTo', 'id', 'later-control', undefined, undefined],
        ['ZestClientElementScroll', 'cssSelector', '#results', -8, 140]
    ])
    const reparsed = parseMacroDocument(exported.text, { format: 'zest' })
    assert.deepEqual(reparsed.flow.steps.slice(1).map((step) => [step.scrollMode, step.x, step.y]), [
        ['intoView', undefined, undefined],
        ['by', -8, 140]
    ])
})

test('Zest and Chrome Recorder preserve recorded hover and delay steps', () => {
    const base = representativeFlow()
    const flow = normalizeFlow({
        ...base,
        variables: [],
        steps: [
            base.steps[0],
            {
                id: 'step-hover', type: 'hover', enabled: true, optional: false,
                durationMs: 0, timeoutMs: 5000, window: { index: 0, handle: 'main' },
                frameChain: [], locators: [{ type: 'id', value: 'account-menu' }], data: null
            },
            {
                id: 'step-delay', type: 'delay', enabled: true, optional: false,
                durationMs: 750, timeoutMs: 0, window: { index: 0, handle: 'main' },
                frameChain: [], locators: [], data: null
            },
            {
                id: 'step-click', type: 'click', enabled: true, optional: false,
                durationMs: 0, timeoutMs: 5000, window: { index: 0, handle: 'main' },
                frameChain: [], locators: [{ type: 'id', value: 'logout' }], data: null
            }
        ]
    })

    const zest = serializeMacroDocument(flow, 'zest', { element_path: 'id' })
    assert.deepEqual(zest.diagnostics, [])
    assert.deepEqual(JSON.parse(zest.text).statements.map((statement) => statement.elementType), [
        'ZestClientLaunch', 'ZestClientElementMouseOver', 'ZestActionSleep', 'ZestClientElementClick'
    ])
    const zestRoundTrip = parseMacroDocument(zest.text, { format: 'zest' })
    assert.deepEqual(zestRoundTrip.flow.steps.map((step) => step.type), ['navigate', 'hover', 'delay', 'click'])
    assert.equal(zestRoundTrip.flow.steps[2].durationMs, 750)

    const chrome = serializeMacroDocument(flow, 'chrome-recorder', { element_path: 'id' })
    assert.deepEqual(chrome.diagnostics, [])
    const chromeSteps = JSON.parse(chrome.text).steps
    assert.deepEqual(chromeSteps.map((step) => step.type), ['navigate', 'hover', 'waitForExpression', 'click'])
    assert.equal(chromeSteps[2].expression, 'new Promise(resolve => setTimeout(() => resolve(true), 750))')
    const chromeRoundTrip = parseMacroDocument(chrome.text, { format: 'chrome-recorder' })
    assert.equal(chromeRoundTrip.acceptable, true)
    assert.deepEqual(chromeRoundTrip.flow.steps.map((step) => step.type), ['navigate', 'hover', 'delay', 'click'])
    assert.equal(chromeRoundTrip.flow.steps[2].durationMs, 750)
})

test('Chrome Recorder rejects arbitrary wait expressions instead of importing executable code', () => {
    const result = parseMacroDocument(JSON.stringify({
        title: 'Unsafe expression',
        steps: [
            { type: 'navigate', url: 'https://example.invalid/' },
            { type: 'waitForExpression', expression: 'fetch("https://example.invalid/")' }
        ]
    }), { format: 'chrome-recorder' })
    assert.equal(result.acceptable, false)
    assert.equal(result.diagnostics.some((entry) => entry.code === 'chrome_expression_unsupported'), true)
})

test('Chrome Recorder and XML preserve absolute and relative scroll modes', () => {
    const chromeSource = JSON.stringify({
        title: 'Absolute scroll',
        steps: [
            { type: 'navigate', url: 'https://example.invalid/' },
            { type: 'scroll', target: 'main', x: 25, y: 600 }
        ]
    })
    const chrome = parseMacroDocument(chromeSource, { format: 'chrome-recorder' })
    assert.equal(chrome.flow.steps[1].scrollMode, 'to')
    assert.equal(chrome.flow.steps[1].y, 600)
    assert.deepEqual(JSON.parse(serializeMacroDocument(chrome.flow, 'chrome-recorder').text).steps[1], {
        type: 'scroll', target: 'main', selectors: [], timeout: 30000, x: 25, y: 600
    })

    const zestRelative = parseMacroDocument(JSON.stringify({
        zestVersion: '0.3', title: 'Relative', elementType: 'ZestScript',
        statements: [
            { elementType: 'ZestClientLaunch', url: 'https://example.invalid/', windowHandle: 'main' },
            { elementType: 'ZestClientElementScroll', type: 'id', element: 'container', x: 1, y: 90, windowHandle: 'main' }
        ]
    }), { format: 'zest' })
    const xml = serializeMacroDocument(zestRelative.flow, 'xml')
    assert.match(xml.text, /<PtkScrollMode>by<\/PtkScrollMode>/)
    const reparsed = parseMacroDocument(xml.text, { format: 'xml' })
    assert.equal(reparsed.flow.steps[1].scrollMode, 'by')
    assert.equal(reparsed.flow.steps[1].x, 1)
    assert.equal(reparsed.flow.steps[1].y, 90)
})

test('Zest focus clicks before SendKeys are optional while value entry remains required', () => {
    const source = JSON.stringify({
        zestVersion: '0.3', title: 'Search', elementType: 'ZestScript',
        statements: [
            { elementType: 'ZestClientLaunch', url: 'https://example.invalid/', windowHandle: 'one', enabled: true },
            { elementType: 'ZestClientElementClick', type: 'id', element: 'search', windowHandle: 'one', enabled: true },
            { elementType: 'ZestClientElementScrollTo', type: 'id', element: 'search', windowHandle: 'one', enabled: true },
            { elementType: 'ZestClientElementSendKeys', type: 'id', element: 'search', value: 'query', windowHandle: 'one', enabled: true }
        ]
    })
    const imported = parseMacroDocument(source, { format: 'zest' })
    assert.equal(imported.acceptable, true)
    assert.equal(imported.flow.steps[1].type, 'click')
    assert.equal(imported.flow.steps[1].optional, true)
    assert.equal(imported.flow.steps[1].source.preparatory, true)
    assert.equal(imported.flow.steps[3].type, 'fill')
    assert.equal(imported.flow.steps[3].optional, false)
    const compiled = compileFlow(imported.flow)
    assert.equal(compiled.events[1].PtkPreparatory, 1)
    assert.equal(compiled.events[3].PtkPreparatory, 0)
})

test('required replay actions fail without blocking alert dialogs and submit can press Enter', async () => {
    const replayer = await fs.readFile(new URL('../../../security/ptk/content/replayer.js', import.meta.url), 'utf8')
    assert.match(replayer, /return this\.handleMissingElement\(item, 'click'\)/)
    assert.match(replayer, /return this\.handleMissingElement\(item, 'set value on'\)/)
    assert.match(replayer, /this\.dispatchKey\(element, 'KEY_ENTER'\)/)
    assert.match(replayer, /type:\s*'replay_outcome'/)
    assert.match(replayer, /throw this\.replayFailure\('element_not_found'/)
    assert.match(replayer, /recordOptionalWarning\('element_not_found'/)
    assert.match(replayer, /if \(item\?\.PtkPreparatory === 1\) return/)
    assert.doesNotMatch(replayer, /\balert\s*\(/)
})

test('literal values survive every structured import without prompts or side-channel secrets', async () => {
    const literal = 'fixture-password-value'
    const documents = [
        ['zest-client-login.zst', 'zest'],
        ['selenium-login.side', 'side'],
        ['chrome-recorder-login.json', 'chrome-recorder']
    ]
    for (const [name, format] of documents) {
        const source = (await fixture(name)).replace('${PTK_SECRET:PASSWORD}', literal)
        const imported = parseMacroDocument(source, { fileName: name, format })
        assert.deepEqual(Object.keys(imported.secretValues || {}), [], format)
        assert.equal(imported.diagnostics.some((entry) => entry.code === 'secret_replaced'), false, format)
        assert.equal(imported.flow.steps.some((step) => step.data?.kind === 'literal' && step.data.value === literal), true, format)
        const compiled = compileFlow(imported.flow)
        assert.equal(compiled.events.some((event) => event.Data === literal), true, format)
    }

    const base = representativeFlow()
    const literalFlow = normalizeFlow({
        ...base,
        variables: [],
        steps: base.steps.map((step) => step.type === 'fill'
            ? { ...step, data: { kind: 'literal', value: literal } }
            : step)
    })
    for (const format of ['ptk-flow', 'xml']) {
        const serialized = serializeMacroDocument(literalFlow, format)
        const imported = parseMacroDocument(serialized.text, { format })
        assert.equal(imported.flow.steps.some((step) => step.data?.kind === 'literal' && step.data.value === literal), true, format)
        assert.equal(compileFlow(imported.flow).events.some((event) => event.Data === literal), true, format)
    }
})

test('Selenium IDE frame and window context survives supported round trip', async () => {
    const input = await fixture('selenium-frame-window.side')
    const imported = parseMacroDocument(input, { fileName: 'selenium-frame-window.side' })
    assert.equal(imported.acceptable, true)
    const framed = imported.flow.steps.find((step) => step.type === 'click')
    const switched = imported.flow.steps.find((step) => step.type === 'selectWindow')
    const child = imported.flow.steps.find((step) => step.type === 'assertElement')
    assert.equal(framed.frameChain.length, 1)
    assert.deepEqual(framed.frameChain[0].locators[0], { type: 'css', value: 'iframe#account-frame' })
    assert.equal(switched.target, 'handle=account-window')
    assert.equal(child.window.index, 1)
    assert.equal(child.window.handle, 'account-window')

    const exported = serializeMacroDocument(imported.flow, 'side')
    assert.equal(exported.diagnostics.some((entry) => entry.level === 'error'), false)
    assert.match(exported.text, /"command": "selectFrame"/)
    assert.match(exported.text, /"command": "selectWindow"/)
    const reparsed = parseMacroDocument(exported.text, { format: 'side' })
    assert.equal(reparsed.acceptable, true)
    assert.equal(reparsed.flow.steps.find((step) => step.type === 'click').frameChain.length, 1)
    assert.equal(reparsed.flow.steps.find((step) => step.type === 'assertElement').window.handle, 'account-window')
})

test('structured serializers remain parseable for the representative workflow', async () => {
    const flow = representativeFlow()
    for (const format of ['ptk-flow', 'xml', 'zest', 'side', 'chrome-recorder']) {
        const result = serializeMacroDocument(flow, format)
        assert.equal(typeof result.text, 'string')
        assert.ok(result.text.length > 20)
        const blocking = result.diagnostics.filter((entry) => entry.level === 'error')
        assert.deepEqual(blocking, [], `${format}: ${JSON.stringify(blocking)}`)
        const imported = parseMacroDocument(result.text, { format })
        assert.equal(imported.acceptable, true, `${format}: ${JSON.stringify(imported.diagnostics)}`)
        assert.equal(imported.flow.steps.some((step) => step.type === 'navigate'), true)
    }
})

test('framework generators emit syntactically valid source with secret references only', () => {
    const flow = representativeFlow()
    for (const format of ['playwright', 'puppeteer', 'selenium-webdriver', 'cypress']) {
        const result = serializeMacroDocument(flow, format)
        assert.equal(result.readOnly, true)
        assert.equal(result.diagnostics.some((entry) => entry.level === 'error'), false, `${format}: ${JSON.stringify(result.diagnostics)}`)
        assert.match(result.text, /PTK_SECRET_PASSWORD/)
        assert.doesNotMatch(result.text, /real-password/i)
        parse(result.text, { ecmaVersion: 'latest', sourceType: 'module' })
    }

    const cypress = serializeMacroDocument(flow, 'cypress')
    assert.match(cypress.text, /cy\.then\(\(\) => Cypress\.env\("PTK_SECRET_PASSWORD"\)\)\.then/)
    assert.doesNotMatch(cypress.text, /cy\.env\(/)
})

test('framework generators keep code-shaped macro values inside JavaScript string literals', () => {
    const marker = 'PTK_CODE_INJECTION_MARKER'
    const payload = `https://example.test/\"); globalThis.${marker} = true; //\\\n</script>`
    const base = representativeFlow()
    const flow = normalizeFlow({
        ...base,
        variables: [],
        steps: base.steps.map((step) => step.type === 'fill'
            ? { ...step, data: { kind: 'literal', value: payload } }
            : step)
    })

    for (const format of ['playwright', 'puppeteer', 'selenium-webdriver', 'cypress']) {
        const result = serializeMacroDocument(flow, format)
        assert.doesNotMatch(result.text, /<\/script>/i, `${format} emitted a literal closing script tag`)
        assert.match(result.text, /https:\/\/example\.test\//, `${format} made ordinary URLs unreadable`)
        const ast = parse(result.text, { ecmaVersion: 'latest', sourceType: 'module' })
        const literalValues = []
        const identifiers = []
        const pending = [ast]
        while (pending.length) {
            const node = pending.pop()
            if (!node || typeof node !== 'object') continue
            if (node.type === 'Literal') literalValues.push(node.value)
            if (node.type === 'Identifier') identifiers.push(node.name)
            pending.push(...Object.values(node).filter((value) => value && typeof value === 'object'))
        }
        assert.ok(literalValues.includes(payload), `${format} did not preserve the macro value as a string literal`)
        assert.equal(identifiers.includes(marker), false, `${format} emitted the macro value as executable code`)
    }
})

test('structured exports and framework generators honor the selected element path', () => {
    const base = representativeFlow()
    const flow = normalizeFlow({
        ...base,
        steps: base.steps.map((step) => step.type !== 'click' ? step : {
            ...step,
            locators: [
                { type: 'css', value: 'button.login' },
                { type: 'id', value: 'login-button' },
                { type: 'xpath', value: '/html/body/main/form/button' }
            ]
        })
    })

    const side = serializeMacroDocument(flow, 'side', { element_path: 'id' })
    assert.match(side.text, /"target": "id=login-button"/)
    const chrome = serializeMacroDocument(flow, 'chrome-recorder', { element_path: 'id' })
    assert.match(chrome.text, /"#login-button"/)
    const zest = serializeMacroDocument(flow, 'zest', { element_path: 'fullpath' })
    assert.match(zest.text, /\/html\/body\/main\/form\/button/)

    const playwright = serializeMacroDocument(flow, 'playwright', { element_path: 'id' })
    assert.match(playwright.text, /locator\("#login-button"\)/)
    const selenium = serializeMacroDocument(flow, 'selenium-webdriver', { element_path: 'fullpath' })
    assert.match(selenium.text, /By\.xpath\("\/html\/body\/main\/form\/button"\)/)
})

test('generated source preserves nested frame and special-key semantics where supported', () => {
    const base = representativeFlow()
    const flow = normalizeFlow({
        ...base,
        variables: [],
        steps: [base.steps[0], {
            id: 'nested-key',
            type: 'keyPress',
            enabled: true,
            optional: false,
            durationMs: 0,
            timeoutMs: 5000,
            window: { index: 0, handle: 'main' },
            frameChain: [
                { locators: [{ type: 'css', value: 'iframe#outer' }] },
                { locators: [{ type: 'css', value: 'iframe#inner' }] }
            ],
            locators: [{ type: 'css', value: '#search' }],
            data: { kind: 'literal', value: '${KEY_ENTER}' }
        }]
    })

    const playwright = serializeMacroDocument(flow, 'playwright')
    assert.equal(playwright.diagnostics.some((entry) => entry.level === 'error'), false)
    assert.match(playwright.text, /page\.frameLocator\("iframe#outer"\)\.frameLocator\("iframe#inner"\)\.locator\("#search"\)\.press\("Enter"\)/)

    const cypressFlow = normalizeFlow({ ...flow, steps: flow.steps.map((step) => ({ ...step, frameChain: [] })) })
    const cypress = serializeMacroDocument(cypressFlow, 'cypress')
    assert.match(cypress.text, /\.type\("\{enter\}"\)/)
    parse(cypress.text, { ecmaVersion: 'latest', sourceType: 'module' })
})

test('compiled PTK Flow is bounded legacy replay data and requires runtime secrets', () => {
    const flow = representativeFlow()
    assert.throws(() => compileFlow(flow), (error) => error instanceof PtkFlowError && error.code === 'missing_secret')
    const compiled = compileFlow(flow, { secrets: { PASSWORD: 'runtime-only' }, elementPath: 'id' })
    assert.equal(compiled.startUrl, 'http://localhost:3001/#/login')
    assert.deepEqual(compiled.events.map((event) => event.EventType), ['Navigate', 'DriverSetControlValue', 'DriverClick', 'Delay'])
    assert.equal(compiled.events[1].Data, 'runtime-only')
    assert.equal(compiled.events[1].ElementPath, 'id=passwordControl')
})

test('compiled runtime events preserve native action metadata without executable source', async () => {
    const base = representativeFlow()
    const actionSteps = [
        { type: 'doubleClick', locators: [{ type: 'css', value: '#double' }] },
        { type: 'select', locators: [{ type: 'css', value: '#role' }], data: { kind: 'literal', value: 'admin' } },
        { type: 'submit', locators: [{ type: 'css', value: '#login' }] },
        { type: 'scroll', locators: [], x: 12, y: 34 },
        { type: 'waitForElement', locators: [{ type: 'css', value: '#ready' }] },
        { type: 'assertText', locators: [{ type: 'css', value: '#result' }], expected: 'Welcome' },
        { type: 'assertUrl', locators: [], expected: 'http://localhost:3001/#/home' },
        { type: 'assertElement', locators: [{ type: 'css', value: '#account' }], expected: 'present' }
    ].map((step, index) => ({
        id: `native-${index + 1}`,
        enabled: true,
        optional: false,
        durationMs: 0,
        timeoutMs: 4321,
        window: { index: 0, handle: '' },
        frameChain: [],
        data: null,
        ...step
    }))
    const flow = normalizeFlow({ ...base, variables: [], steps: [base.steps[0], ...actionSteps] })
    const compiled = compileFlow(flow)
    assert.deepEqual(compiled.events.slice(1).map((event) => event.EventType), [
        'DoubleClick', 'Select', 'Submit', 'Scroll', 'WaitForElement', 'AssertText', 'AssertUrl', 'AssertElement'
    ])
    assert.equal(compiled.events[4].Data, '12,34')
    assert.equal(compiled.events[5].TimeoutMs, 4321)
    assert.equal(compiled.events[6].Expected, 'Welcome')
    assert.equal(JSON.stringify(compiled.events).includes('function'), false)

    const replayer = await fs.readFile(new URL('../../../security/ptk/content/replayer.js', import.meta.url), 'utf8')
    for (const handler of ['doubleclick', 'select', 'submit', 'scroll', 'waitforelement', 'asserttext', 'asserturl', 'assertelement']) {
        assert.match(replayer, new RegExp(`async ${handler}\\(item\\)`))
    }
    assert.match(replayer, /item\?\.TimeoutMs/)
})

test('native recorded window and element scrolls preserve absolute targets', async () => {
    const { flowFromRecording } = await import('../../../security/ptk/background/macro/flow.js')
    const result = flowFromRecording({
        items: [
            { eventTypeName: 'Navigate', data: 'https://example.invalid/', windowIndex: 0 },
            { eventTypeName: 'Scroll', data: '0,640', x: 0, y: 640, scrollMode: 'to', scrollTarget: 'window', windowIndex: 0 },
            {
                eventTypeName: 'Scroll', data: '15,320', x: 15, y: 320,
                scrollMode: 'to', scrollTarget: 'element', target: 'css=#results',
                targetOptions: ['css=#results'], windowIndex: 0
            }
        ]
    })
    const scrolls = result.flow.steps.filter((step) => step.type === 'scroll')
    assert.deepEqual(scrolls.map((step) => [step.scrollMode, step.locators.length, step.x, step.y]), [
        ['to', 0, 0, 640],
        ['to', 1, 15, 320]
    ])
    const runtime = compileFlow(result.flow).events.filter((event) => event.EventType === 'Scroll')
    assert.deepEqual(runtime.map((event) => [event.PtkScrollMode, event.ElementPath, event.Data]), [
        ['to', '', '0,640'],
        ['to', 'css=#results', '15,320']
    ])
})

test('recorded stable IDs survive legacy recording conversion and drive Cypress export', async () => {
    const { flowFromRecording, selectFlowLocator } = await import('../../../security/ptk/background/macro/flow.js')
    const result = flowFromRecording({
        items: [
            { eventTypeName: 'Navigate', data: 'https://example.invalid/', windowIndex: 0 },
            {
                eventTypeName: 'Click', props: { id: 'checkoutButton', name: '' },
                target: 'xpath=//button[@id="checkoutButton"]',
                xpath: '//button[@id="checkoutButton"]', windowIndex: 0
            }
        ]
    })
    const click = result.flow.steps[1]
    assert.deepEqual(click.locators[0], { type: 'id', value: 'checkoutButton' })
    assert.deepEqual(selectFlowLocator(click, 'id'), { type: 'id', value: 'checkoutButton' })
    const cypress = serializeMacroDocument(result.flow, 'cypress', { element_path: 'id' })
    assert.deepEqual(cypress.diagnostics, [])
    assert.match(cypress.text, /cy\.get\("#checkoutButton"\)\.click\(\)/)
})

test('Element ID preference uses a portable CSS fallback before XPath', () => {
    const base = representativeFlow()
    const flow = normalizeFlow({
        ...base,
        variables: [],
        steps: [base.steps[0], {
            id: 'portable-fallback', type: 'click', enabled: true, optional: false,
            durationMs: 0, timeoutMs: 5000, window: { index: 0, handle: 'main' }, frameChain: [],
            locators: [
                { type: 'xpath', value: '//main/button[2]' },
                { type: 'css', value: 'main .checkout-action' }
            ],
            data: null
        }]
    })
    const cypress = serializeMacroDocument(flow, 'cypress', { element_path: 'id' })
    assert.deepEqual(cypress.diagnostics, [])
    assert.match(cypress.text, /cy\.get\("main \.checkout-action"\)\.click\(\)/)
})

test('native recorder coalesces scroll events and mode-aware replay remains non-blocking', async () => {
    const recorder = await fs.readFile(new URL('../../../security/ptk/content/recorder.js', import.meta.url), 'utf8')
    assert.match(recorder, /Scroll:\s*13/)
    assert.match(recorder, /window\.addEventListener\("scroll", this\.onscroll, true\)/)
    assert.match(recorder, /this\._pendingScrolls\.set/)
    assert.match(recorder, /last\?\.eventType === EventTypes\.Scroll/)
    assert.doesNotMatch(recorder, /onscroll\(e\)[\s\S]{0,1200}preventDefault/)

    const replayer = await fs.readFile(new URL('../../../security/ptk/content/replayer.js', import.meta.url), 'utf8')
    assert.match(replayer, /\['intoView', 'to', 'by'\]\.includes\(rawMode\)/)
    assert.match(replayer, /element\.scrollBy\(x, y\)/)
    assert.match(replayer, /element\.scrollTo\(x, y\)/)
    assert.match(replayer, /window\.scrollTo\(x, y\)/)
    assert.match(replayer, /async ensureElementInView\(element\)/)
    assert.doesNotMatch(replayer, /async scroll\(item\)[\s\S]{0,2400}alert\(/)
})

test('framework generators preserve all supported scroll modes', () => {
    const base = representativeFlow()
    const steps = [
        base.steps[0],
        {
            id: 'view', type: 'scroll', scrollMode: 'intoView', enabled: true, optional: true,
            durationMs: 0, timeoutMs: 5000, window: { index: 0, handle: 'main' }, frameChain: [],
            locators: [{ type: 'css', value: '#later' }], data: null
        },
        {
            id: 'window-to', type: 'scroll', scrollMode: 'to', enabled: true, optional: false,
            durationMs: 0, timeoutMs: 5000, window: { index: 0, handle: 'main' }, frameChain: [],
            locators: [], data: null, x: 0, y: 500
        },
        {
            id: 'container-to', type: 'scroll', scrollMode: 'to', enabled: true, optional: false,
            durationMs: 0, timeoutMs: 5000, window: { index: 0, handle: 'main' }, frameChain: [],
            locators: [{ type: 'css', value: '#list' }], data: null, x: 0, y: 300
        },
        {
            id: 'container-by', type: 'scroll', scrollMode: 'by', enabled: true, optional: false,
            durationMs: 0, timeoutMs: 5000, window: { index: 0, handle: 'main' }, frameChain: [],
            locators: [{ type: 'css', value: '#list' }], data: null, x: 5, y: 75
        }
    ]
    const flow = normalizeFlow({ ...base, variables: [], steps })
    const playwright = serializeMacroDocument(flow, 'playwright')
    assert.deepEqual(playwright.diagnostics, [])
    assert.match(playwright.text, /scrollIntoViewIfNeeded/)
    assert.match(playwright.text, /element\.scrollTo\(x, y\)/)
    assert.match(playwright.text, /element\.scrollBy\(x, y\)/)
    assert.match(playwright.text, /window\.scrollTo\(x, y\)/)

    const puppeteer = serializeMacroDocument(flow, 'puppeteer')
    assert.deepEqual(puppeteer.diagnostics, [])
    assert.match(puppeteer.text, /element\.scrollBy\(x, y\)/)

    const selenium = serializeMacroDocument(flow, 'selenium-webdriver')
    assert.deepEqual(selenium.diagnostics, [])
    assert.match(selenium.text, /arguments\[0\]\.scrollBy\(arguments\[1\], arguments\[2\]\)/)

    const cypress = serializeMacroDocument(flow, 'cypress')
    assert.deepEqual(cypress.diagnostics, [])
    assert.match(cypress.text, /\.scrollIntoView\(\)/)
    assert.match(cypress.text, /\.scrollTo\(0, 300\)/)
    assert.match(cypress.text, /\$element\[0\]\.scrollBy\(5, 75\)/)
})

test('recorded child-window alternatives survive Flow and XML compatibility round trip', async () => {
    const { flowFromRecording } = await import('../../../security/ptk/background/macro/flow.js')
    const recording = {
        items: [
            { eventTypeName: 'Navigate', data: 'https://example.test/', windowIndex: 0 },
            {
                eventTypeName: 'SelectWindow',
                data: 'title=New Tab',
                target: 'title=New Tab',
                targetOptions: ['title=New Tab', 'index=2'],
                windowIndex: 0
            },
            { eventTypeName: 'SetValue', data: 'proof', target: 'id=child-input', windowIndex: 1 }
        ]
    }
    const converted = flowFromRecording(recording)
    const selectWindow = converted.flow.steps.find((step) => step.type === 'selectWindow')
    assert.equal(selectWindow.target, 'index=2')
    assert.deepEqual(selectWindow.targetOptions, ['index=2', 'title=New Tab'])

    const compiled = compileFlow(converted.flow)
    const runtimeWindow = compiled.events.find((event) => event.EventType === 'SelectWindow')
    assert.deepEqual(runtimeWindow.targetOptions, ['index=2', 'title=New Tab'])

    const xml = serializeMacroDocument(converted.flow, 'xml')
    assert.match(xml.text, /<TargetOptions><!\[CDATA\[\["index=2","title=New Tab"\]\]\]><\/TargetOptions>/)
    const reparsed = parseMacroDocument(xml.text, { format: 'xml' })
    const reparsedWindow = reparsed.flow.steps.find((step) => step.type === 'selectWindow')
    assert.equal(reparsedWindow.target, 'index=2')
    assert.deepEqual(reparsedWindow.targetOptions, ['index=2', 'title=New Tab'])
})

test('recorded element locator alternatives survive XML compatibility round trip', async () => {
    const { flowFromRecording } = await import('../../../security/ptk/background/macro/flow.js')
    const recording = {
        items: [
            { eventTypeName: 'Navigate', data: 'https://example.test/', windowIndex: 0 },
            {
                eventTypeName: 'SetValue',
                data: 'proof',
                target: 'css=#email',
                targetOptions: ['css=#email', 'id=email', 'xpath=//input[@id="email"]'],
                fullxpath: '/html/body/form/input[1]',
                windowIndex: 0
            }
        ]
    }
    const converted = flowFromRecording(recording)
    const xml = serializeMacroDocument(converted.flow, 'xml', { elementPath: 'fullpath' })
    assert.match(xml.text, /<TargetOptions>/)

    const reparsed = parseMacroDocument(xml.text, { format: 'xml' })
    const fill = reparsed.flow.steps.find((step) => step.type === 'fill')
    assert.ok(fill.locators.some((locator) => locator.type === 'css' && locator.value === '#email'))
    assert.ok(fill.locators.some((locator) => locator.type === 'id' && locator.value === 'email'))
    assert.ok(fill.locators.some((locator) => locator.type === 'xpath' && locator.value === '//input[@id="email"]'))
    assert.ok(fill.locators.some((locator) => locator.type === 'xpath' && locator.value === '/html/body/form/input[1]'))
})

test('download names are sanitized and format specific', () => {
    const flow = representativeFlow()
    assert.equal(macroDownloadName(flow, 'xml'), 'PTK_Representative_login.rec')
    assert.equal(macroDownloadName(flow, 'zest'), 'PTK_Representative_login.zst')
    assert.equal(macroDownloadName(flow, 'playwright'), 'PTK_Representative_login.playwright.mjs')
})

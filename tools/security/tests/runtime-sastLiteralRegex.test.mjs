// Imported PTK v10 regression; paths adapted to the owned cert-x subsystem.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'

const { compilePattern } = await import('../../../security/ptk/background/sast/modules/_internals.js')

const modules = JSON.parse(fs.readFileSync(
    new URL('../../../security/ptk/background/sast/modules/modules.json', import.meta.url),
    'utf8'
))
const angularModule = modules.modules.find((module) => module.id === 'angularjs-expression-injection')

function patternFor(ruleId) {
    const rule = angularModule.rules.find((candidate) => candidate.id === ruleId)
    assert.ok(rule, `missing AngularJS SAST rule ${ruleId}`)
    assert.equal(rule.metadata.execution.findingKind, 'hint')
    return rule.detector.matches[0]
}

function staticTemplate(value) {
    return {
        type: 'TemplateLiteral',
        expressions: [],
        quasis: [{ value: { cooked: value, raw: value } }]
    }
}

test('literalRegex matches string literals and static template literals only', () => {
    const match = compilePattern(patternFor('angularjs-interpolation-template-literal'))

    assert.equal(match({ type: 'Literal', value: '{{ user.name }}' }), true)
    assert.equal(match({ type: 'StringLiteral', value: '[[ account.email ]]' }), true)
    assert.equal(match(staticTemplate('{{ constructor.constructor("return 1")() }}')), true)

    assert.equal(match({
        type: 'TemplateLiteral',
        expressions: [{ type: 'Identifier', name: 'user' }],
        quasis: [
            { value: { cooked: '{{ ', raw: '{{ ' } },
            { value: { cooked: ' }}', raw: ' }}' } }
        ]
    }), false)
    assert.equal(match({ type: 'Identifier', name: 'template' }), false)
    assert.equal(match({ type: 'Literal', value: 12345 }), false)
    assert.equal(match({ type: 'Literal', value: true }), false)
    assert.equal(match({ type: 'Literal', value: 'ordinary text' }), false)
})

test('literalRegex honours flags without retaining global-regex state', () => {
    const match = compilePattern({ literalRegex: 'ng-click', flags: 'gi' })
    const node = { type: 'Literal', value: '<button NG-CLICK="save()">Save</button>' }

    assert.equal(match(node), true)
    assert.equal(match(node), true)
})

test('AngularJS ng-expression literal hint has positive and clean controls', () => {
    const match = compilePattern(patternFor('angularjs-ng-expression-attribute-literal'))

    assert.equal(match({ type: 'Literal', value: '<button ng-click="save()">Save</button>' }), true)
    assert.equal(match(staticTemplate('<section ng-if="isVisible">Visible</section>')), true)
    assert.equal(match({ type: 'Literal', value: '<button data-click="save">Save</button>' }), false)
    assert.equal(match({ type: 'Literal', value: 'ng-click is documentation text' }), false)
})

test('invalid literalRegex patterns fail closed', () => {
    const match = compilePattern({ literalRegex: '[' })
    assert.equal(match({ type: 'Literal', value: '[' }), false)
})

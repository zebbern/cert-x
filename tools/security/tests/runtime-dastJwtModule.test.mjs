// Imported PTK v10 regression; paths adapted to the owned cert-x subsystem.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'

import { jsonLogic } from '../../../security/ptk/background/lib/json-logic-js.js'

globalThis.self = globalThis
const { ptk_module } = await import('../../../security/ptk/background/dast/modules/module.js')
const { dastEngine } = await import('../../../security/ptk/background/dast/dastEngine.js')
const { DastTaskPlanner } = await import('../../../security/ptk/background/dast/services/dastTaskPlanner.js')
const { RequestBuilderModel } = await import('../../../security/ptk/background/requestBuilder/model.js')

const modules = JSON.parse(fs.readFileSync(new URL('../../../security/ptk/background/dast/modules/modules.json', import.meta.url), 'utf8'))
const jwtModuleConfig = modules.modules.find((module) => module.id === 'jwt_injection')
const jwt1Config = jwtModuleConfig.attacks.find((attack) => attack.id === 'jwt_1')
const jwt2Config = jwtModuleConfig.attacks.find((attack) => attack.id === 'jwt_2')
const jwt3Config = jwtModuleConfig.attacks.find((attack) => attack.id === 'jwt_3')
const jwt4Config = jwtModuleConfig.attacks.find((attack) => attack.id === 'jwt_4')
const jwtNoFormConfig = jwtModuleConfig.attacks.find((attack) => attack.id === 'jwt_probe_no_form')
const jwtNoJsonConfig = jwtModuleConfig.attacks.find((attack) => attack.id === 'jwt_probe_no_json')
const jwt3HeaderRegex = jwt3Config.action.headers[0].regex
const jwtCookieRegex = jwtModuleConfig.metadata.constants.regex
const noneJwt = 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VyIjoiMSJ9.'
const signedJwt = 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiMSJ9.signature'
const noneCookieJwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VyIjoiMSJ9.'
const signedCookieJwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiMSJ9.signature'

jsonLogic.add_operation('regex', (obj, pattern) => {
  const re = new RegExp(pattern, 'gmi')
  if (Array.isArray(obj)) {
    return Object.values(obj).some((value) => re.test(JSON.stringify(value)))
  }
  return re.test(String(obj || ''))
})

function buildPostSchema({ contentType, body }) {
  return {
    request: {
      method: 'POST',
      url: 'https://example.test/session',
      headers: [
        { name: 'Content-Type', value: contentType }
      ],
      body
    },
    response: {
      statusCode: 200,
      length: 42,
      body: '{"authenticated":true}'
    }
  }
}

test('jwt_2 targets a JWT in form POST bodies without mutating unrelated fields', () => {
  for (const contentType of [
    'application/x-www-form-urlencoded',
    'multipart/form-data; boundary=ptk-boundary'
  ]) {
    const module = new ptk_module(jwtModuleConfig)
    const schema = buildPostSchema({
      contentType,
      body: {
        mimeType: contentType,
        params: [
          { name: 'access_token', value: signedCookieJwt },
          { name: 'note', value: 'leave-me-unchanged' }
        ]
      }
    })

    const attacks = module.buildAttacks(schema, jwt2Config)

    assert.equal(attacks.length, 1, contentType)
    assert.equal(attacks[0].metadata.attacked.location, 'form')
    assert.equal(attacks[0].metadata.attacked.name, 'access_token')
    assert.match(attacks[0].metadata.attacked.after, /eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0\./)
    assert.equal(
      attacks[0].request.body.params.find((entry) => entry.name === 'note')?.value,
      'leave-me-unchanged'
    )
  }
})

test('jwt_4 targets a nested JWT in a JSON POST body and ignores non-JWT leaves', () => {
  const module = new ptk_module(jwtModuleConfig)
  const schema = buildPostSchema({
    contentType: 'application/json',
    body: {
      mimeType: 'application/json',
      text: JSON.stringify({
        auth: { access_token: signedCookieJwt },
        profile: { label: 'leave-me-unchanged' }
      })
    }
  })

  const attacks = module.buildAttacks(schema, jwt4Config)

  assert.equal(attacks.length, 1)
  assert.equal(attacks[0].metadata.attacked.location, 'json')
  assert.equal(attacks[0].metadata.attacked.name, 'auth.access_token')
  assert.match(attacks[0].metadata.attacked.after, /eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0\./)
  assert.equal(JSON.parse(attacks[0].request.body.text).profile.label, 'leave-me-unchanged')
})

test('jwt_2 and jwt_4 do not create POST-body attacks when no JWT is present', () => {
  const formModule = new ptk_module(jwtModuleConfig)
  const formSchema = buildPostSchema({
    contentType: 'application/x-www-form-urlencoded',
    body: {
      mimeType: 'application/x-www-form-urlencoded',
      params: [
        { name: 'username', value: 'ptk-user' },
        { name: 'note', value: 'ordinary value' }
      ]
    }
  })
  assert.deepEqual(formModule.buildAttacks(formSchema, jwt2Config), [])

  const jsonModule = new ptk_module(jwtModuleConfig)
  const jsonSchema = buildPostSchema({
    contentType: 'application/json',
    body: {
      mimeType: 'application/json',
      text: JSON.stringify({ username: 'ptk-user', nested: { note: 'ordinary value' } })
    }
  })
  assert.deepEqual(jsonModule.buildAttacks(jsonSchema, jwt4Config), [])
})

test('body-specific JWT probes remove only the matching form or JSON carrier', () => {
  const formModule = new ptk_module(jwtModuleConfig)
  const formSchema = buildPostSchema({
    contentType: 'application/x-www-form-urlencoded',
    body: {
      mimeType: 'application/x-www-form-urlencoded',
      params: [
        { name: 'access_token', value: signedCookieJwt },
        { name: 'note', value: 'preserve-me' }
      ]
    }
  })
  const formProbe = formModule.buildAttacks(formSchema, jwtNoFormConfig)
  assert.equal(formProbe.length, 1)
  assert.equal(formProbe[0].metadata.attacked.location, 'form')
  assert.equal(formProbe[0].request.body.params.find((entry) => entry.name === 'access_token')?.value, '')
  assert.equal(formProbe[0].request.body.params.find((entry) => entry.name === 'note')?.value, 'preserve-me')

  const jsonModule = new ptk_module(jwtModuleConfig)
  const jsonSchema = buildPostSchema({
    contentType: 'application/json',
    body: {
      mimeType: 'application/json',
      text: JSON.stringify({ auth: { access_token: signedCookieJwt }, note: 'preserve-me' })
    }
  })
  const jsonProbe = jsonModule.buildAttacks(jsonSchema, jwtNoJsonConfig)
  assert.equal(jsonProbe.length, 1)
  assert.equal(jsonProbe[0].metadata.attacked.location, 'json')
  assert.equal(JSON.parse(jsonProbe[0].request.body.text).auth.access_token, '')
  assert.equal(JSON.parse(jsonProbe[0].request.body.text).note, 'preserve-me')
})

test('jwt_2 requires a contrasting form-body probe and survives carrier validation', () => {
  const module = new ptk_module(jwtModuleConfig)
  const original = buildPostSchema({
    contentType: 'application/x-www-form-urlencoded',
    body: {
      mimeType: 'application/x-www-form-urlencoded',
      params: [{ name: 'access_token', value: signedCookieJwt }]
    }
  })
  const requestSchema = module.buildAttacks(original, jwt2Config)[0]
  const engine = Object.create(dastEngine.prototype)
  engine._appendTaskRuntimeEvent = () => {}
  const executed = {
    request: requestSchema.request,
    response: original.response,
    metadata: engine._attackMetadataView(module, jwt2Config, requestSchema.metadata)
  }

  module.executed = []
  assert.equal(Boolean(module.validateAttackConditions(executed, original)), false)

  module.executed = [{
    metadata: { id: 'jwt_probe_no_form' },
    response: { statusCode: 401, length: 12, body: 'Unauthorized' }
  }]
  assert.equal(module.validateAttackConditions(executed, original), true)
  assert.equal(jsonLogic.apply(jwt2Config.validation.rule, { attack: executed, original, module }), true)

  const filtered = engine._filterActiveValidationResult(
    { moduleId: 'jwt_injection', attack: { id: 'jwt_2' }, module },
    { success: true, proof: 'form body JWT none accepted' },
    executed,
    { original }
  )
  assert.equal(filtered?.success, true)
})

test('jwt_4 requires a contrasting JSON-body probe and rejects unrelated carrier proof', () => {
  const module = new ptk_module(jwtModuleConfig)
  const original = buildPostSchema({
    contentType: 'application/json',
    body: {
      mimeType: 'application/json',
      text: JSON.stringify({ auth: { access_token: signedCookieJwt } })
    }
  })
  const requestSchema = module.buildAttacks(original, jwt4Config)[0]
  const engine = Object.create(dastEngine.prototype)
  engine._appendTaskRuntimeEvent = () => {}
  const executed = {
    request: requestSchema.request,
    response: original.response,
    metadata: engine._attackMetadataView(module, jwt4Config, requestSchema.metadata)
  }

  module.executed = [{
    metadata: { id: 'jwt_probe_no_authz' },
    response: { statusCode: 401, length: 12, body: 'Unauthorized' }
  }]
  assert.equal(Boolean(module.validateAttackConditions(executed, original)), false)

  module.executed = [{
    metadata: { id: 'jwt_probe_no_json' },
    response: { statusCode: 401, length: 12, body: 'Unauthorized' }
  }]
  assert.equal(module.validateAttackConditions(executed, original), true)
  assert.equal(jsonLogic.apply(jwt4Config.validation.rule, { attack: executed, original, module }), true)

  assert.equal(engine._filterActiveValidationResult(
    { moduleId: 'jwt_injection', attack: { id: 'jwt_4' }, module },
    { success: true, proof: 'JSON body JWT none accepted' },
    executed,
    { original }
  )?.success, true)
})

async function buildBodyOnlyJwtPlan({ contentType, bodyText }) {
  const raw = `POST https://example.test/session HTTP/1.1\r\nHost: example.test\r\nContent-Type: ${contentType}\r\n\r\n${bodyText}`
  const parsed = RequestBuilderModel.parseRawRequest(raw)
  const original = {
    request: parsed.request,
    response: {
      statusCode: 200,
      length: 42,
      body: '{"authenticated":true}'
    }
  }
  const module = new ptk_module(jwtModuleConfig)
  const planner = new DastTaskPlanner({
    awaitModulesLoaded: async () => {},
    resolveOriginal: async () => original,
    getModules: () => [module],
    shouldPlanModule: () => true,
    shouldUseBulkAttack: () => true,
    createTask: (task) => task,
    fingerprintFromSchema: () => 'POST|example.test|/session',
    fingerprintFromPayload: () => 'POST|example.test|/session'
  })
  return planner.buildAttackPlan({ raw })
}

test('planner carries a body-only JWT from raw POST capture into the matching probe and attack', async () => {
  const formPlan = await buildBodyOnlyJwtPlan({
    contentType: 'application/x-www-form-urlencoded',
    bodyText: `access_token=${encodeURIComponent(signedCookieJwt)}`
  })
  const formIds = formPlan.tasks.map((task) => task.attack.id)
  assert.ok(formIds.includes('jwt_probe_no_form'))
  assert.ok(formIds.includes('jwt_2'))

  const jsonPlan = await buildBodyOnlyJwtPlan({
    contentType: 'application/json',
    bodyText: JSON.stringify({ auth: { access_token: signedCookieJwt } })
  })
  const jsonIds = jsonPlan.tasks.map((task) => task.attack.id)
  assert.ok(jsonIds.includes('jwt_probe_no_json'))
  assert.ok(jsonIds.includes('jwt_4'))
})

function buildJwt3Attack(overrides = {}) {
  return {
    id: 'jwt_3',
    request: {
      headers: [
        { name: 'Authorization', value: noneJwt }
      ]
    },
    response: {
      statusCode: 200,
      length: 120,
      body: '{"user":"admin","authenticated":true}'
    },
    metadata: {
      id: 'jwt_3',
      regex: jwt3HeaderRegex,
      condition: jwt3Config.condition,
      validation: jwt3Config.validation,
      constants: jwt3Config.metadata.constants,
      ...(overrides.metadata || {})
    },
    ...overrides
  }
}

function buildJwt1Attack(overrides = {}) {
  return {
    id: 'jwt_1',
    request: {
      cookies: [
        { name: 'token', value: noneCookieJwt }
      ],
      headers: [
        { name: 'Cookie', value: `token=${noneCookieJwt}` }
      ]
    },
    response: {
      statusCode: 200,
      length: 120,
      body: '{"user":"admin","authenticated":true}'
    },
    metadata: {
      id: 'jwt_1',
      regex: jwtCookieRegex,
      condition: jwt1Config.condition,
      validation: jwt1Config.validation,
      ...(overrides.metadata || {})
    },
    ...overrides
  }
}

function buildOriginal(overrides = {}) {
  return {
    request: {
      headers: [
        { name: 'Authorization', value: signedJwt }
      ]
    },
    response: {
      statusCode: 200,
      length: 118,
      body: '{"user":"admin","authenticated":true}'
    },
    ...overrides
  }
}

function buildCookieOriginal(overrides = {}) {
  return {
    request: {
      cookies: [
        { name: 'token', value: signedCookieJwt }
      ],
      headers: [
        { name: 'Cookie', value: `token=${signedCookieJwt}` }
      ]
    },
    response: {
      statusCode: 200,
      length: 118,
      body: '{"user":"admin","authenticated":true}'
    },
    ...overrides
  }
}

test('jwt_1 can run when the cookie-removal probe alone proves cookie auth is required', () => {
  const module = new ptk_module(jwtModuleConfig)
  module.executed = [
    {
      metadata: { id: 'jwt_probe_no_cookie' },
      response: {
        statusCode: 200,
        length: 11,
        body: '{"user":{}}'
      }
    }
  ]

  const attack = buildJwt1Attack()
  const original = buildCookieOriginal()

  assert.equal(module.validateAttackConditions(attack, original), true)
  assert.equal(jsonLogic.apply(jwt1Config.validation.rule, { attack, original, module }), true)
})

test('jwt_1 does not run before a cookie auth-control probe is available', () => {
  const module = new ptk_module(jwtModuleConfig)
  module.executed = []

  assert.equal(module.validateAttackConditions(buildJwt1Attack(), buildCookieOriginal()), false)
})

test('jwt_1 does not treat removing both Authorization and cookies as cookie-specific proof', () => {
  const module = new ptk_module(jwtModuleConfig)
  module.executed = [
    {
      metadata: { id: 'jwt_probe_no_both' },
      response: {
        statusCode: 401,
        length: 31,
        body: 'No auth carrier was accepted'
      }
    }
  ]

  const attack = buildJwt1Attack()
  const original = buildCookieOriginal()

  assert.equal(module.validateAttackConditions(attack, original), false)
  assert.equal(jsonLogic.apply(jwt1Config.validation.rule, { attack, original, module }), false)
})

test('jwt_3 requires an auth-required probe before it is executable', () => {
  const module = { ...jwtModuleConfig, executed: [] }

  assert.equal(jsonLogic.apply(jwt3Config.condition, {
    attack: buildJwt3Attack(),
    original: buildOriginal(),
    module
  }), false)
})

test('jwt_3 validates none-algorithm Authorization header when no-authz probe proves auth is required', () => {
  const module = {
    ...jwtModuleConfig,
    executed: [
    {
      metadata: { id: 'jwt_probe_no_authz' },
      response: {
        statusCode: 401,
        length: 31,
        body: 'No Authorization header was found'
      }
    }
    ]
  }

  const attack = buildJwt3Attack()
  const original = buildOriginal()

  assert.equal(jsonLogic.apply(jwt3Config.condition, { attack, original, module }), true)
  assert.equal(jsonLogic.apply(jwt3Config.validation.rule, { attack, original, module }), true)
})

test('DAST JWT filter suppresses status-only Authorization findings when the attack body is not baseline-equivalent', () => {
  const engine = Object.create(dastEngine.prototype)
  engine._appendTaskRuntimeEvent = () => {}
  const original = buildOriginal({
    response: {
      statusCode: 200,
      length: 117,
      body: '{"user":{"id":23,"email":"ptk@test.com"}}'
    }
  })
  const attack = buildJwt3Attack({
    response: {
      statusCode: 200,
      length: 11,
      body: '{"user":{}}'
    }
  })
  const task = {
    moduleId: 'jwt_injection',
    attack: { id: 'jwt_3' },
    module: {
      executed: [
        {
          metadata: { id: 'jwt_probe_no_authz' },
          response: {
            statusCode: 200,
            length: 117,
            body: '{"user":{"id":23,"email":"ptk@test.com"}}'
          }
        }
      ]
    }
  }

  assert.equal(engine._filterActiveValidationResult(
    task,
    { success: true, proof: 'Attack response status matches baseline.' },
    attack,
    { original }
  ), null)
})

test('DAST JWT filter suppresses cookie findings when removing JWT cookies does not change the baseline', () => {
  const engine = Object.create(dastEngine.prototype)
  engine._appendTaskRuntimeEvent = () => {}
  const original = buildCookieOriginal()
  const attack = buildJwt1Attack()
  const task = {
    moduleId: 'jwt_injection',
    attack: { id: 'jwt_1' },
    module: {
      executed: [
        {
          metadata: { id: 'jwt_probe_no_cookie' },
          response: {
            statusCode: null,
            length: 118,
            body: '{"user":"admin","authenticated":true}'
          }
        }
      ]
    }
  }

  assert.equal(engine._filterActiveValidationResult(
    task,
    { success: true, proof: 'Attack response matches baseline (status and body).' },
    attack,
    { original }
  ), null)
})

test('DAST JWT filter keeps cookie findings when the cookie carrier is proven', () => {
  const engine = Object.create(dastEngine.prototype)
  engine._appendTaskRuntimeEvent = () => {}
  const original = buildCookieOriginal()
  const attack = buildJwt1Attack()
  const task = {
    moduleId: 'jwt_injection',
    attack: { id: 'jwt_1' },
    module: {
      executed: [
        {
          metadata: { id: 'jwt_probe_no_cookie' },
          response: {
            statusCode: 200,
            length: 11,
            body: '{"user":{}}'
          }
        }
      ]
    }
  }

  assert.equal(engine._filterActiveValidationResult(
    task,
    { success: true, proof: 'Attack response matches baseline (status and body).' },
    attack,
    { original }
  )?.success, true)
})

test('DAST JWT filter keeps Authorization findings when the Authorization carrier is proven', () => {
  const engine = Object.create(dastEngine.prototype)
  engine._appendTaskRuntimeEvent = () => {}
  const original = buildOriginal()
  const attack = buildJwt3Attack()
  const task = {
    moduleId: 'jwt_injection',
    attack: { id: 'jwt_3' },
    module: {
      executed: [
        {
          metadata: { id: 'jwt_probe_no_authz' },
          response: {
            statusCode: 401,
            length: 31,
            body: 'No Authorization header was found'
          }
        }
      ]
    }
  }

  assert.equal(engine._filterActiveValidationResult(
    task,
    { success: true, proof: 'Attack response matches baseline (status and body).' },
    attack,
    { original }
  )?.success, true)
})

test('jwt_3 does not recover from no-both control because it is not Authorization-specific proof', () => {
  const module = {
    ...jwtModuleConfig,
    executed: [
      {
        metadata: { id: 'jwt_probe_no_both' },
        response: {
          statusCode: 401,
          length: 31,
          body: 'No auth carrier was accepted'
        }
      }
    ]
  }

  const attack = buildJwt3Attack()
  const original = buildOriginal({
    request: {
      headers: [
        { name: 'Authorization', value: signedJwt },
        { name: 'Cookie', value: `token=${signedCookieJwt}` }
      ],
      cookies: [
        { name: 'token', value: signedCookieJwt }
      ]
    }
  })

  assert.equal(jsonLogic.apply(jwt3Config.condition, { attack, original, module }), false)
  assert.equal(jsonLogic.apply(jwt3Config.validation.rule, { attack, original, module }), false)

  const engine = Object.create(dastEngine.prototype)
  engine._appendTaskRuntimeEvent = () => {}
  const recovered = engine._recoverJwtValidationFromProbeContrast({
    moduleId: 'jwt_injection',
    attack: { id: 'jwt_3' },
    module
  }, { success: false, proof: '' }, attack, { original })
  assert.equal(recovered, null)
})

test('DAST JWT recovery does not recover cookie findings from no-both probe contrast', () => {
  const engine = Object.create(dastEngine.prototype)
  engine._appendTaskRuntimeEvent = () => {}
  const validationResult = { success: false, proof: '' }
  const executed = buildJwt1Attack()
  const task = {
    moduleId: 'jwt_injection',
    attack: { id: 'jwt_1' },
    module: {
      executed: [
        {
          metadata: { id: 'jwt_probe_no_both' },
          response: {
            statusCode: 401,
            length: 31,
            body: 'No auth carrier was accepted'
          }
        }
      ]
    }
  }

  assert.equal(engine._recoverJwtValidationFromProbeContrast(
    task,
    validationResult,
    executed,
    { original: buildCookieOriginal() }
  ), null)
})

test('DAST JWT recovery keeps cookie findings when cookie-only removal is the contrasting probe', () => {
  const engine = Object.create(dastEngine.prototype)
  engine._appendTaskRuntimeEvent = () => {}
  const validationResult = { success: false, proof: '' }
  const executed = buildJwt1Attack()
  const task = {
    moduleId: 'jwt_injection',
    attack: { id: 'jwt_1' },
    module: {
      executed: [
        {
          metadata: { id: 'jwt_probe_no_cookie' },
          response: {
            statusCode: 401,
            length: 31,
            body: 'No cookie auth carrier was accepted'
          }
        }
      ]
    }
  }

  const recovered = engine._recoverJwtValidationFromProbeContrast(
    task,
    validationResult,
    executed,
    { original: buildCookieOriginal() }
  )
  assert.equal(recovered.success, true)
  assert.match(recovered.proof, /jwt_probe_no_cookie/)
})

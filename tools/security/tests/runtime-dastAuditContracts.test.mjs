// Imported PTK v10 regression; paths adapted to the owned cert-x subsystem.
import test from 'node:test'
import assert from 'node:assert/strict'

globalThis.self = globalThis
const { RemoteDastEngineFacade } = await import('../../../security/ptk/background/dast/runtime/remoteDastEngineFacade.js')
const { DastWorkerRuntime } = await import('../../../security/ptk/background/dast/runtime/dastWorkerRuntime.js')
const { createDastRuntimeMessage } = await import('../../../security/ptk/background/dast/runtime/protocol.js')
const { default: DastSessionCoordinator } = await import('../../../security/ptk/background/dast/services/dastSessionCoordinator.js')

function fixture(progress = { planned: 4, executed: 1, remaining: 3, isIdle: false }) {
  const runtime = new DastWorkerRuntime({
    generationFactory: () => 'generation',
    executorFactory: async () => ({ call: async method => method === 'getProgressSnapshot' ? progress : undefined })
  })
  const calls = []
  const facade = new RemoteDastEngineFacade({ client: { request: async (type, payload) => {
    calls.push({ type, payload })
    return runtime.handle(createDastRuntimeMessage(type, payload))
  } } })
  return { runtime, facade, calls, async start() {
    await runtime.start({ sessionId: 'session' })
    facade.sessionId = 'session'; facade.executorGeneration = 'generation'
  } }
}

test('expired remote wait retains canonical outstanding work instead of inventing idle', async () => {
  const f = fixture()
  await f.start()
  assert.deepEqual(await f.facade.waitForIdle(1), { planned: 4, executed: 1, remaining: 3, isIdle: false })
  assert.equal(f.facade.getProgressSnapshot().isIdle, false)
})

test('remote wait drains canonical idle event watermark before returning', async () => {
  const f = fixture({ planned: 4, executed: 4, remaining: 0, isIdle: true })
  await f.start()
  const event = f.runtime.publishEvent({ type: 'result_mutation', payload: { type: 'finding' } })
  const seen = []
  f.facade.setResultMutationListener(value => seen.push(value.type))
  const progress = await f.facade.waitForIdle(1)
  assert.equal(progress.isIdle, true)
  assert.deepEqual(seen, ['finding'])
  assert.equal(f.facade.publicationCursor, event.cursor)
})

for (const failure of ['apply', 'negative_ack', 'rejected_ack', 'lost_ack_response']) {
  test(`failed event receipt (${failure}) blocks later cumulative ACK and recovers by replay`, async () => {
    const f = fixture()
    await f.start()
    const first = f.runtime.publishEvent({ type: 'result_mutation', payload: { type: 'first' } })
    const second = f.runtime.publishEvent({ type: 'result_mutation', payload: { type: 'second' } })
    let failed = false
    const seen = []
    f.facade.setResultMutationListener(value => {
      if (failure === 'apply' && !failed) { failed = true; throw new Error('apply_failed') }
      seen.push(value.type)
    })
    const request = f.facade.client.request
    f.facade.client.request = async (type, payload) => {
      if (type === 'ack_events' && !failed && failure !== 'apply') {
        failed = true
        if (failure === 'lost_ack_response') { await request(type, payload); throw new Error('ack_response_lost') }
        if (failure === 'rejected_ack') throw new Error('ack_transport_failed')
        return { ok: false, error: 'ack_rejected' }
      }
      return request(type, payload)
    }
    const one = f.facade._queueEngineMessage(first.event, first.cursor)
    const two = f.facade._queueEngineMessage(second.event, second.cursor)
    await assert.rejects(one)
    await assert.rejects(two)
    const committed = failure === 'lost_ack_response' ? 1 : 0
    assert.equal(f.runtime.acknowledgedEventCursor, committed)
    assert.deepEqual(f.runtime.eventJournal.map(item => item.cursor), committed ? [2] : [1, 2])
    await f.facade.drainEvents({ throughCursor: 2 })
    assert.equal(f.runtime.acknowledgedEventCursor, 2)
    assert.equal(seen.at(-1), 'second')
    assert.deepEqual(seen, ['first', 'second'], 'successful application is not repeated merely to retry an ACK')
  })
}

test('a missing live event cannot be cumulatively acknowledged; replay fills the gap', async () => {
  const f = fixture()
  await f.start()
  f.runtime.publishEvent({ type: 'result_mutation', payload: { type: 'first' } })
  const second = f.runtime.publishEvent({ type: 'result_mutation', payload: { type: 'second' } })
  await assert.rejects(f.facade._queueEngineMessage(second.event, second.cursor), /cursor_gap/)
  assert.equal(f.runtime.acknowledgedEventCursor, 0)
  await f.facade.drainEvents({ throughCursor: 2 })
  assert.equal(f.runtime.acknowledgedEventCursor, 2)
})

// Worker restart: the executor keeps emitting live events to the new controller
// while adoption replays the ones the old controller never acknowledged. A live
// event that overtakes the replay must not fail adoption (observed in the
// lifecycle browser test as error "dast_runtime_event_cursor_gap", losing the
// interrupted scan's evidence).
for (const at of ['events_page', 'ack_events']) test(`a live event overtaking replay at ${at} does not fail the drain`, async () => {
  const f = fixture()
  await f.start()
  const events = [1, 2, 3].map(n => f.runtime.publishEvent({ type: 'result_mutation', payload: { type: 'event-' + n } }))
  const seen = []
  f.facade.setResultMutationListener(value => seen.push(value.type))
  const request = f.facade.client.request
  let injected = false
  f.facade.client.request = async (type, payload) => {
    const response = await request(type, payload)
    if (type === at && !injected) { injected = true; f.facade._queueEngineMessage(events[2].event, events[2].cursor).catch(() => {}) }
    return response
  }
  await f.facade.drainEvents()
  assert.equal(injected, true)
  assert.equal(f.runtime.acknowledgedEventCursor, 3)
  assert.deepEqual(seen, ['event-1', 'event-2', 'event-3'], 'every event applied once, in order')
})

// Steady live traffic during a long replay is progress, not a missing event: each
// overtake costs a re-page, and the drain must still finish.
test('a drain overtaken by live events many times still completes in order', async () => {
  const f = fixture()
  await f.start()
  const events = Array.from({ length: 30 }, (_, n) => f.runtime.publishEvent({ type: 'result_mutation', payload: { type: 'event-' + n } }))
  const seen = []
  f.facade.setResultMutationListener(value => seen.push(value.type))
  const request = f.facade.client.request
  let acks = 0
  f.facade.client.request = async (type, payload) => {
    const response = await request(type, payload)
    if (type === 'ack_events' && ++acks % 3 === 0) {
      const live = f.runtime.publishEvent({ type: 'result_mutation', payload: { type: 'live-' + acks } })
      f.facade._queueEngineMessage(live.event, live.cursor).catch(() => {})
    }
    return response
  }
  await f.facade.drainEvents()
  assert.equal(f.runtime.acknowledgedEventCursor, f.runtime.eventCursor)
  assert.equal(new Set(seen).size, seen.length, 'no event applied twice')
  assert.deepEqual(seen.slice(0, 30), events.map((_, n) => 'event-' + n))
})

test('a genuinely missing journal event still fails the drain instead of being skipped', async () => {
  const f = fixture()
  await f.start()
  for (let n = 0; n < 3; n++) f.runtime.publishEvent({ type: 'result_mutation', payload: { type: 'event-' + n } })
  f.runtime.eventJournal = f.runtime.eventJournal.filter(item => item.cursor !== 2)
  await assert.rejects(f.facade.drainEvents(), /cursor_gap/)
  assert.equal(f.runtime.acknowledgedEventCursor, 1, 'nothing past the hole is acknowledged')
})

test('missing canonical progress fails explicitly without fabricating idle', async () => {
  const f = fixture(null)
  await f.start()
  f.facade.progress = { remaining: 3, isIdle: false }
  await assert.rejects(f.facade.waitForIdle(1), /progress_unavailable/)
  assert.deepEqual(f.facade.getProgressSnapshot(), { remaining: 3, isIdle: false })
})

test('persistent publication failure rejects idle settlement and leaves receipt replayable', async () => {
  const f = fixture({ remaining: 0, isIdle: true })
  await f.start()
  f.runtime.publishEvent({ type: 'result_mutation', payload: {} })
  f.facade.setResultMutationListener(() => { throw new Error('publisher_failed') })
  await assert.rejects(f.facade.waitForIdle(1), /publisher_failed/)
  assert.equal(f.facade.getProgressSnapshot().isIdle, false)
  assert.equal(f.runtime.acknowledgedEventCursor, 0)
  assert.equal(f.runtime.eventJournal.length, 1)
  f.facade.setResultMutationListener(() => true)
  assert.equal((await f.facade.waitForIdle(1)).isIdle, true)
})

test('absent optional UI delivery is best effort and does not block canonical receipt', async () => {
  const f = fixture()
  await f.start()
  const event = f.runtime.publishEvent({ channel: 'ptk_background2popup_rattacker', type: 'dast_idle' })
  f.facade.setDisplayMessageListener(() => false)
  await f.facade._queueEngineMessage(event.event, event.cursor)
  assert.equal(f.runtime.acknowledgedEventCursor, 1)
})

test('coordinator never treats missing counters or unpublished idle results as drained', async () => {
  const f = fixture({ remaining: 0, isIdle: true })
  await f.start()
  f.facade.progress = { isIdle: false }
  const coordinator = new DastSessionCoordinator({ engine: f.facade })
  assert.equal(coordinator._isDrainSnapshotIdle(coordinator._collectDrainSnapshot()), false)
  f.runtime.publishEvent({ type: 'result_mutation', payload: {} })
  f.facade.setResultMutationListener(() => { throw new Error('publisher_failed') })
  const result = await coordinator._drainBeforeZapClose(100, { drainTimeoutMs: 50 })
  assert.equal(result.drained, false)
  assert.equal(result.error, 'publisher_failed')
  assert.equal(result.after.idle, false)
})

test('ZAP drain preserves expired remote wait counters and accepts genuine idle only', async () => {
  const progress = { planned: 4, executed: 1, remaining: 3, isIdle: false }
  const f = fixture(progress)
  await f.start()
  f.facade.progress = { ...progress }
  const coordinator = new DastSessionCoordinator({ engine: f.facade })
  const busy = await coordinator._drainBeforeZapClose(100, { drainTimeoutMs: 50 })
  assert.equal(busy.drained, false)
  assert.equal(busy.after.remaining, 3)
  Object.assign(progress, { executed: 4, remaining: 0, isIdle: true })
  const idle = await coordinator._drainBeforeZapClose(100, { drainTimeoutMs: 50 })
  assert.equal(idle.drained, true)
  assert.equal(idle.after.executed, 4)
})

test('bounded replay snapshot receipt recovers a committed ACK with a lost response', async () => {
  const f = fixture()
  await f.start()
  f.runtime.eventLimit = 100
  for (let i = 0; i < 101; i++) f.runtime.publishEvent({ type: 'result_mutation', payload: { type: 'event' } })
  let failed = false
  const request = f.facade.client.request
  f.facade.client.request = async (type, payload) => {
    const result = await request(type, payload)
    if (type === 'ack_events' && !failed) { failed = true; throw new Error('snapshot_ack_response_lost') }
    return result
  }
  const seen = []
  f.facade.setResultMutationListener(value => seen.push(value.type))
  await assert.rejects(f.facade.drainEvents(), /snapshot_ack_response_lost/)
  await f.facade.drainEvents({ throughCursor: 101 })
  // Snapshot publication is deliberately idempotent across replacement/replay.
  assert.deepEqual(seen, ['runtime_replay_snapshot', 'runtime_replay_snapshot', ...Array(100).fill('event')])
  assert.equal(f.runtime.acknowledgedEventCursor, 101)
})

for (const path of ['snapshot', 'idle_event']) {
  test(`failed ${path} publication cannot restore facade idle during canonical drainage`, async () => {
    const canonical = { planned: 3, executed: 3, remaining: 0, isIdle: true }
    const f = fixture(canonical)
    await f.start()
    f.facade.progress = { isIdle: false }
    if (path === 'snapshot') {
      f.runtime.eventLimit = 100
      f.runtime.session.executor.describe = async () => ({ progress: canonical })
      for (let i = 0; i < 101; i++) f.runtime.publishEvent({ type: 'result_mutation', payload: {} })
    } else {
      f.runtime.publishEvent({ type: 'dast_progress', info: { progress: canonical } })
      f.runtime.publishEvent({ type: 'result_mutation', payload: {} })
    }
    let observedIdle
    f.facade.setResultMutationListener(() => {
      observedIdle = f.facade.getProgressSnapshot().isIdle
      throw new Error('publication_failed')
    })
    await assert.rejects(f.facade.waitForIdle(1), /publication_failed/)
    assert.equal(observedIdle, false, 'publication cannot expose idle before its receipt')
    assert.equal(f.facade.getProgressSnapshot().isIdle, false)
    assert.equal(f.facade.getProgressSnapshot().executed, 3)
  })
}

for (const outcome of ['error', 'timeout']) {
  test(`coordinator cannot declare drained after wait ${outcome} even if counters become idle`, async () => {
    let idle = false
    const coordinator = new DastSessionCoordinator({ engine: {
      getProgressSnapshot: () => ({ isIdle: idle, remaining: 0 }),
      waitForIdle() {
        idle = true
        if (outcome === 'error') return Promise.reject(new Error('wait_failed'))
        return new Promise(() => {})
      }
    } })
    const result = await coordinator._drainBeforeZapClose(100, { drainTimeoutMs: 10 })
    assert.equal(result.after.idle, true)
    assert.equal(result.drained, false)
    if (outcome === 'error') assert.equal(result.error, 'wait_failed')
    else assert.equal(result.timedOut, true)
  })
}

test('failed live receipt after an idle progress event revokes cached idle', async () => {
  const f = fixture()
  await f.start()
  const idle = f.runtime.publishEvent({ type: 'dast_progress', info: { progress: { remaining: 0, isIdle: true } } })
  const failed = f.runtime.publishEvent({ type: 'result_mutation', payload: {} })
  await f.facade._queueEngineMessage(idle.event, idle.cursor)
  f.facade.setResultMutationListener(() => { throw new Error('live_publication_failed') })
  await assert.rejects(f.facade._queueEngineMessage(failed.event, failed.cursor), /live_publication_failed/)
  assert.equal(f.facade.getProgressSnapshot().isIdle, false)
})

test('failed adoption snapshot publication cannot leave adopted executor idle visible', async () => {
  const f = fixture()
  f.facade.setResultMutationListener(() => { throw new Error('adoption_publication_failed') })
  await assert.rejects(f.facade.adopt({
    ok: true, sessionId: 'session', executorGeneration: 'generation', status: 'running',
    executorState: { progress: { remaining: 0, isIdle: true } }
  }), /adoption_publication_failed/)
  assert.equal(f.facade.getProgressSnapshot().isIdle, false)
})

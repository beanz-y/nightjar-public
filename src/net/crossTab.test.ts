import { afterEach, describe, expect, it } from 'vitest'
import { CROSS_TAB_CHANNEL, type CrossTab, type CrossTabEvent, createCrossTab } from './crossTab'

// BroadcastChannel delivery is async (task-queued); a short tick lets it land.
const tick = () => new Promise((r) => setTimeout(r, 20))

describe('crossTab render sync', () => {
  const open: CrossTab[] = []
  const mk = (sink: CrossTabEvent[]): CrossTab => {
    const ct = createCrossTab((ev) => sink.push(ev))
    open.push(ct)
    return ct
  }
  afterEach(() => {
    while (open.length) open.pop()!.close()
  })

  it('delivers an append to a sibling but never echoes it back to the sender', async () => {
    const aGot: CrossTabEvent[] = []
    const bGot: CrossTabEvent[] = []
    const a = mk(aGot)
    mk(bGot)
    const msg = { id: 'abc', dir: 'in' as const, text: 'hi', ts: 5 }
    a.post({ kind: 'append', peer: 'peer1', msg })
    await tick()
    expect(bGot).toEqual([{ kind: 'append', peer: 'peer1', msg }])
    expect(aGot).toEqual([]) // a posted it; it must not receive its own event (no ping-pong)
  })

  it('round-trips delete and failed events in order', async () => {
    const bGot: CrossTabEvent[] = []
    const a = mk([])
    mk(bGot)
    a.post({ kind: 'delete', peer: 'p', id: 'x' })
    a.post({ kind: 'failed', id: 'y' })
    await tick()
    expect(bGot).toEqual([
      { kind: 'delete', peer: 'p', id: 'x' },
      { kind: 'failed', id: 'y' },
    ])
  })

  it('stops receiving after close (a locked/torn-down tab gets nothing)', async () => {
    const bGot: CrossTabEvent[] = []
    const a = mk([])
    const b = mk(bGot)
    b.close()
    a.post({ kind: 'failed', id: 'z' })
    await tick()
    expect(bGot).toEqual([])
  })

  it('ignores non-event payloads on the channel', async () => {
    const bGot: CrossTabEvent[] = []
    mk(bGot)
    const raw = new BroadcastChannel(CROSS_TAB_CHANNEL)
    raw.postMessage({ hello: 'world' })
    raw.postMessage('nope')
    raw.postMessage({ kind: 'bogus' })
    await tick()
    raw.close()
    expect(bGot).toEqual([])
  })
})

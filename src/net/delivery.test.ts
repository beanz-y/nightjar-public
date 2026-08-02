// The delivery indicator (sending / sent / delivered). What it must and must not
// claim:
//   - a status is stamped only on a POSITIVE signal, never inferred from the
//     absence of a failure marker (the over-claim this feature could easily have
//     shipped: "sent" printed for a message the relay permanently refused);
//   - it only ever moves forward, so an out-of-order report cannot walk a message
//     back from delivered to sent;
//   - it is sealed INSIDE the history row, so a device image learns nothing new
//     about which rows are outbound or how many reached the peer (DESIGN 8.5);
//   - it never resurrects a row that was deleted in the meantime.
//
// The transport is never connected, so nothing here talks to a relay: the tests
// drive the client's own status path directly.

import { beforeEach, describe, expect, it } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { generateIdentity } from '../crypto/identity'
import { hash256 } from '../crypto/primitives'
import { AppLockStore } from '../storage/appLockStore'
import { HistoryStore } from '../storage/historyStore'
import { MemoryKeyStore } from '../storage/keystore'
import { InMemoryLock } from '../storage/lock'
import { PrekeyStore } from '../storage/prekeyStore'
import { MemorySessionStore, singleSessionBook } from '../storage/sessionStore'
import type { RatchetSnapshot } from '../crypto/ratchet'
import { ContactStore } from '../trust/contactStore'
import { NightjarClient } from './client'

const NOW = 1_700_000_000_000
const stubKdf = (s: Uint8Array, salt: Uint8Array) => hash256(new Uint8Array([...s, ...salt]))
const snap = 'aa'.repeat(32) as unknown as RatchetSnapshot

/** Reach the client's private status path the way the transport and the reconnect
 *  catch-up do, without standing up a relay. */
interface Internals {
  markDelivery(peer: string, id: string, status: 'sent' | 'delivered'): Promise<void>
}

async function harness() {
  const identity = generateIdentity()
  const keys = new MemoryKeyStore()
  const lock = new InMemoryLock()
  const store = new MemorySessionStore()
  const prekeys = new PrekeyStore(keys, lock)
  const contacts = new ContactStore(keys, lock)
  const appLock = new AppLockStore(keys, lock, stubKdf)
  await appLock.enroll([{ kind: 'pass', secret: 'x' }])
  const history = new HistoryStore(appLock)
  const reports: Array<{ peer: string; id: string; status: string }> = []
  const client = new NightjarClient(
    identity,
    store,
    prekeys,
    contacts,
    lock,
    { onMessage: () => {}, onDelivery: (peer, id, status) => reports.push({ peer, id, status }) },
    history,
  )
  const seedRow = async (peer: string, id: string, failed?: boolean) => {
    const row = history.seal({ id, peerId: peer, dir: 'out', ts: NOW, text: 'hello' }, failed)
    await store.saveBookWithSeen(peer, singleSessionBook(snap, NOW), `seed-${id}`, row)
  }
  const statusOf = async (peer: string, id: string) => {
    const row = await store.historyGet(history.storageKey(peer, 'out', id))
    return row ? history.open(row).status : undefined
  }
  return { client: client as unknown as Internals, real: client, store, history, reports, seedRow, statusOf }
}

describe('delivery status', () => {
  let peer: string
  let id: string
  beforeEach(() => {
    peer = generateIdentity().userId
    id = bytesToHex(new Uint8Array(16).fill(7))
  })

  it('stamps sent, then delivered, and reports each once', async () => {
    const h = await harness()
    await h.seedRow(peer, id)
    expect(await h.statusOf(peer, id)).toBeUndefined() // nothing claimed yet

    await h.client.markDelivery(peer, id, 'sent')
    expect(await h.statusOf(peer, id)).toBe('sent')
    await h.client.markDelivery(peer, id, 'delivered')
    expect(await h.statusOf(peer, id)).toBe('delivered')
    expect(h.reports).toEqual([
      { peer, id, status: 'sent' },
      { peer, id, status: 'delivered' },
    ])

    // Repeats change nothing and report nothing (a redelivered report, a retransmit
    // re-resolving waitSent).
    await h.client.markDelivery(peer, id, 'delivered')
    expect(h.reports).toHaveLength(2)
  })

  it('never walks backwards from delivered to sent', async () => {
    // The live report and the reconnect catch-up race: a stale 'sent' arriving
    // after 'delivered' must not undo it.
    const h = await harness()
    await h.seedRow(peer, id)
    await h.client.markDelivery(peer, id, 'delivered')
    await h.client.markDelivery(peer, id, 'sent')
    expect(await h.statusOf(peer, id)).toBe('delivered')
    expect(h.reports).toHaveLength(1)
  })

  it('keeps the status INSIDE the sealed body, not beside it', async () => {
    // A plaintext status flag would tell a forensic image which rows are outbound
    // and how many reached the peer. DESIGN 8.5 promises it reveals neither.
    const h = await harness()
    await h.seedRow(peer, id)
    await h.client.markDelivery(peer, id, 'delivered')
    const row = (await h.store.historyGet(h.history.storageKey(peer, 'out', id)))!
    expect(Object.keys(row).sort()).toEqual(['ct', 'key', 'salt'])
    expect(JSON.stringify(row)).not.toContain('delivered')
  })

  it('does nothing for a message that was never persisted or was deleted', async () => {
    // An ephemeral message, a control envelope (a delete carries no history row),
    // and a message deleted between the send and the report all land here. The
    // update must not resurrect a row.
    const h = await harness()
    await h.client.markDelivery(peer, id, 'sent')
    expect(await h.store.historyLoadAll()).toEqual([])
    expect(h.reports).toEqual([])
  })

  it('surfaces the status through loadAllHistory, so a reload still shows it', async () => {
    // The status is useless if the hydration path drops it: the ticks would
    // vanish on every reload even though the row on disk knew better.
    const h = await harness()
    await h.seedRow(peer, id)
    await h.client.markDelivery(peer, id, 'delivered')
    const loaded = (await h.real.loadAllHistory())[peer] ?? []
    expect(loaded).toHaveLength(1)
    expect(loaded[0].status).toBe('delivered')
  })

  it('leaves a failed message alone rather than relabelling it', async () => {
    // A permanently-rejected message is "not sent". A late positive report about
    // the same id must not overwrite that with a delivery claim, and the failed
    // flag itself has to survive the re-seal.
    const h = await harness()
    await h.seedRow(peer, id, true)
    await h.client.markDelivery(peer, id, 'sent')
    const row = (await h.store.historyGet(h.history.storageKey(peer, 'out', id)))!
    expect(row.failed).toBe(true)
  })
})
